package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// 证书同步：把面板签发的证书自动覆盖到挂载目录中已有的证书文件。
// 典型场景：挂载目录里已有 sub.example.com_cert.pem / _key.pem，
// 面板证书为 *.example.com，续期后自动用新内容替换这两个文件。

const (
	syncExact     = "exact"     // 目标域名与证书主域名完全相同
	syncSubdomain = "subdomain" // 目标是证书域名的子域（含 SAN 通配符）
	syncWildcard  = "wildcard"  // 仅用证书的 *. 通配 SAN 匹配
	syncFilename  = "filename"  // 按文件名 glob 匹配
	syncSAN       = "san"       // 读目标现有证书，按 CN/SAN 交集匹配
)

var syncModes = []struct {
	Code string `json:"code"`
	Name string `json:"name"`
	Hint string `json:"hint"`
}{
	{syncExact, "精确域名", "文件名里的域名与证书域名完全一样。例：sub.example.com_cert.pem 对应证书 example.com 时，需证书本身包含 sub.example.com"},
	{syncSubdomain, "子域名（推荐）", "只按证书里实际签发的域名匹配：文件名域名等于证书的 CN 或某个 SAN，或被通配符 SAN 覆盖（*.example.com 只覆盖 sub.example.com 这一级）。证书没签的域名一律不认：证书只签 mypython.example.net 时，不会去匹配其它 *.example.net 文件。已有独立证书的子域文件只归那张证书，泛域证书不会抢写"},
	{syncWildcard, "仅通配符", "只按证书里 *. 开头的域名匹配（*.example.com 只覆盖 sub.example.com 这一级），精确域名不算。适合严格限制泛域名证书；文件名域名已有同名独立证书时不抢写"},
	{syncFilename, "文件名模式", "用 * 或 ? 匹配文件名，不解析域名。例：*_cert.pem 匹配所有以 _cert.pem 结尾的文件"},
	{syncSAN, "按现有证书内容（推荐）", "读取目录里已有证书，比对里面的域名。适合目标文件名与域名不一致的情况；文件名域名已有同名独立证书时不抢写"},
}

var syncModeCodes = func() map[string]bool {
	m := map[string]bool{}
	for _, x := range syncModes {
		m[x.Code] = true
	}
	return m
}()

// SyncRule 是一条同步规则。Pattern 仅 filename 模式使用；其他模式留空即可。
type SyncRule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Enabled     bool     `json:"enabled"`
	Mode        string   `json:"mode"`
	Pattern     string   `json:"pattern"`
	Source      string   `json:"source"` // 面板证书目录名；* 或空表示全部
	CertTmpl    string   `json:"cert_tmpl"`
	KeyTmpl     string   `json:"key_tmpl"`
	RemoteHosts []string `json:"remote_hosts"` // 此规则命中的文件要推送到的远程主机 ID；空表示不推送
	LastSync    string   `json:"last_sync"`
	LastInfo    string   `json:"last_info"`
}

// SyncEvent 是一次同步尝试的记录（成功/跳过/失败都会记）。
type SyncEvent struct {
	Time   string   `json:"time"`
	Scope  string   `json:"scope"` // local | remote，分别展示，避免混在一起
	Rule   string   `json:"rule"`
	Source string   `json:"source"`
	Target string   `json:"target"`
	Result string   `json:"result"` // ok | skip | fail
	Detail string   `json:"detail"`
	Count  int      `json:"count"` // 覆盖的文件数
	Files  []string `json:"files"` // 覆盖的文件名列表（带类型标注，用于展示）

	WrittenFiles []string `json:"-"` // 真实写入的文件名（仅内部用于远程同步，不落盘）
	HostID       string   `json:"-"` // 对应的远程主机 ID（仅内部用于记录推送摘要）
	RuleID       string   `json:"-"` // 对应的同步规则 ID（仅内部用于按规则自动推送）
	Dir          string   `json:"-"` // 命中的本地目录（仅内部用于按规则自动推送）
}

var syncPresets = []struct {
	Name     string `json:"name"`
	Mode     string `json:"mode"`
	Pattern  string `json:"pattern"`
	CertTmpl string `json:"cert_tmpl"`
	KeyTmpl  string `json:"key_tmpl"`
}{
	{"按目录里已有证书的内容匹配（最省心）", syncSAN, "", "{domain}_cert.pem", "{domain}_key.pem"},
	{"按子域名匹配（泛域名证书常用）", syncSubdomain, "", "{domain}_cert.pem", "{domain}_key.pem"},
	{"按精确域名匹配", syncExact, "", "{domain}_cert.pem", "{domain}_key.pem"},
	{"按文件名通配匹配", syncFilename, "*_cert.pem", "{domain}_cert.pem", "{domain}_key.pem"},
}

// SyncFile 是挂载目录中的一个证书文件，供 Web 展示。
type SyncFile struct {
	Dir     string `json:"dir"`
	Name    string `json:"name"`
	Domain  string `json:"domain"`
	Kind    string `json:"kind"` // key | chain | cert
	Size    int64  `json:"size"`
	HasCert bool   `json:"has_cert"` // 内容是否为可解析的 PEM 证书
	CN      string `json:"cn"`
}

// SyncPreviewItem 是规则预览命中的一个目标（按实际匹配到的文件）。
type SyncPreviewItem struct {
	Dir        string `json:"dir"`
	Source     string `json:"source"` // 面板证书目录名
	SourceName string `json:"source_name"`
	Domain     string `json:"domain"`
	File       string `json:"file"`    // 将被覆盖的文件名
	Kind       string `json:"kind"`    // key | chain | cert
	Content    string `json:"content"` // 将写入的内容：新私钥 / 新证书 / 新证书链
}

// SyncRunResult 是一次同步的汇总。Skipped 是因证书内容未变化而没有重写的文件数。
type SyncRunResult struct {
	Events  []SyncEvent `json:"events"`
	Skipped int         `json:"skipped"`
}

// syncRunCtx 在同一次 run 内共享去重状态。
type syncRunCtx struct {
	force   bool              // 手动勾选「强制同步」时忽略指纹记录
	seen    map[string]string // 目标文件 -> 上次写入的证书指纹
	updates map[string]string // 本次新写入的目标文件 -> 指纹
	skipped int               // 本次因内容未变化而跳过的文件数
}

// SyncEngine 负责执行同步。目录列表为空时禁用（不需要用户配置也能跑）。
type SyncEngine struct {
	store  *Store
	certs  *CertScanner
	notify *NotifyEngine
	dirs   []string
}

func NewSyncEngine(store *Store, certs *CertScanner, notify *NotifyEngine, dirs []string) *SyncEngine {
	return &SyncEngine{store: store, certs: certs, notify: notify, dirs: dirs}
}

func (e *SyncEngine) Enabled() bool { return len(e.dirs) > 0 }

// parseSyncDirs 解析多个目录：支持逗号、分号、换行分隔，去重并清理空白。
func parseSyncDirs(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r'
	})
	out := make([]string, 0, len(fields))
	seen := map[string]bool{}
	for _, f := range fields {
		d := strings.TrimSpace(f)
		if d == "" {
			continue
		}
		// 相对目录会让本地同步与远程同步按不同基准解析（远程要求绝对路径），统一转成绝对路径。
		if abs, err := filepath.Abs(d); err == nil {
			d = abs
		}
		if seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out
}

// run 执行全部启用的规则。force=true 时忽略指纹记录，把匹配文件全部重写一遍。
func (e *SyncEngine) run(trigger string, force bool) SyncRunResult {
	result := SyncRunResult{Events: []SyncEvent{}}
	if !e.Enabled() {
		return result
	}
	rules := e.store.ListSyncRules()
	if len(rules) == 0 {
		return result
	}
	all, err := e.certs.Scan()
	if err != nil {
		return result
	}
	ctx := &syncRunCtx{
		force:   force,
		seen:    e.store.SyncSeens(),
		updates: map[string]string{},
	}
	claims := certExactClaims(all)
	// 按「规则 + 目录」聚合本次成功写入的文件，自动推送只发给该规则选中的主机。
	type ruleDirKey struct{ rule, dir string }
	byRuleDir := map[ruleDirKey][]string{}
	ruleByID := map[string]SyncRule{}
	for _, dir := range e.dirs {
		// 目录不存在时静默跳过，避免挂载未就绪就刷错误日志。
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		for _, rule := range rules {
			if !rule.Enabled || !syncModeCodes[rule.Mode] {
				continue
			}
			ruleByID[rule.ID] = rule
			for _, ci := range all {
				if ci.Status == "invalid" || ci.Status == "expired" {
					continue
				}
				if rule.Source != "" && rule.Source != "*" && rule.Source != ci.Name {
					continue
				}
				ev := e.apply(rule, ci, dir, trigger, ctx, claims)
				// 未命中、或证书内容未变化时不写记录，避免每天刷屏。
				if ev.Result == "skip" {
					continue
				}
				ev.Target = dir + " → " + ev.Target
				result.Events = append(result.Events, ev)
				if ev.Result == "ok" && len(ev.WrittenFiles) > 0 {
					byRuleDir[ruleDirKey{rule.ID, dir}] = append(byRuleDir[ruleDirKey{rule.ID, dir}], ev.WrittenFiles...)
				}
			}
		}
	}
	// 指纹一次落盘；只有真正写入过的文件才会更新。
	_ = e.store.MarkSyncSeen(ctx.updates)
	result.Skipped = ctx.skipped

	// 自动同步同样只发给规则选中的主机；规则没选主机就不做远程同步。
	for key, files := range byRuleDir {
		if len(files) == 0 {
			continue
		}
		rule := ruleByID[key.rule]
		if len(rule.RemoteHosts) == 0 {
			continue
		}
		result.Events = append(result.Events, pushAllRemotes(e.store, key.dir, files, false, rule.RemoteHosts...)...)
	}

	if len(result.Events) > 0 {
		_ = e.store.AddSyncEvents(result.Events)
	}
	okCount, failCount := 0, 0
	for _, ev := range result.Events {
		if ev.Result == "ok" {
			okCount++
		} else if ev.Result == "fail" {
			failCount++
		}
	}
	if okCount > 0 {
		e.notify.Send("cert_synced", "证书同步成功 · "+trigger,
			fmt.Sprintf("成功覆盖 %d 个证书文件（触发：%s）", okCount, trigger))
	}
	if failCount > 0 {
		e.notify.Send("sync_failed", "证书同步失败 · "+trigger,
			fmt.Sprintf("%d 个目标文件写入失败（触发：%s）", failCount, trigger))
	}
	return result
}

// syncFingerprint 用源证书内容摘要判断「证书是否已续签」。
// 优先用完整证书链（续签必然变化），没有证书链时退化为私钥摘要。
func syncFingerprint(fullchain string, fullOK bool, key string, keyOK bool) (string, bool) {
	data := ""
	switch {
	case fullOK && fullchain != "":
		data = fullchain
	case keyOK && key != "":
		data = key
	default:
		return "", false
	}
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:]), true
}

// apply 对单张证书应用一条规则。claims 为精确归属映射（见 certExactClaims）。
func (e *SyncEngine) apply(rule SyncRule, ci CertInfo, dir, trigger string, ctx *syncRunCtx, claims map[string]string) SyncEvent {
	ev := SyncEvent{
		Time:   time.Now().Format(time.RFC3339),
		Rule:   rule.Name,
		RuleID: rule.ID,
		Dir:    dir,
		Source: ci.Name,
		Result: "skip",
		Detail: "未匹配到目标文件",
	}

	// 收集目录里所有证书相关文件（含私钥、证书链），按文件名分别处理。
	candidates, err := certCandidates(dir)
	if err != nil {
		ev.Result, ev.Detail = "fail", fmt.Sprintf("读取目录 %s 失败（%v）。%s", dir, err, syncPermHint(dir))
		return ev
	}

	// 源内容按需读取一次。
	var fullchain, chain, key string
	var fullOK, chainOK, keyOK bool
	fullchain, fullOK = e.tryPEM(ci.Name, "fullchain")
	chain, chainOK = e.tryPEM(ci.Name, "chain")
	key, keyOK = e.tryKey(ci.Name)
	fp, fpOK := syncFingerprint(fullchain, fullOK, key, keyOK)

	matched := 0
	skipped := 0
	written := []string{}
	for _, name := range candidates {
		target := filepath.Join(dir, name)
		domain := certFileDomain(name)
		if !e.match(rule, ci, name, domain, target, claims) {
			continue
		}
		// 同一证书已经同步过且内容未变化：跳过。手动勾选强制同步时才重写。
		seenKey := rule.ID + "|" + dir + "|" + name
		if !ctx.force && fpOK && ctx.seen[seenKey] == fp {
			skipped++
			ctx.skipped++
			continue
		}
		kind := syncFileKind(name)
		var data string
		var mode os.FileMode
		var ok bool
		switch kind {
		case "key":
			data, mode, ok = key, 0o600, keyOK
			if !ok {
				ev.Detail = "源文件无私钥，跳过 " + name
				continue
			}
		case "chain", "ca":
			data, mode, ok = chain, 0o644, chainOK
			if !ok {
				data, mode, ok = fullchain, 0o644, fullOK
			}
			if !ok {
				continue
			}
		default: // cert / fullchain / 其它证书文件
			data, mode, ok = fullchain, 0o644, fullOK
			if !ok {
				continue
			}
		}
		if err := writeAtomic(target, []byte(data), mode); err != nil {
			ev.Result, ev.Detail = "fail", "写入 "+name+" 失败: "+err.Error()+"。"+syncPermHint(dir)
			continue
		}
		if fpOK {
			ctx.updates[seenKey] = fp
		}
		written = append(written, name+"("+kind+")")
		ev.WrittenFiles = append(ev.WrittenFiles, name)
		matched++
	}

	if matched > 0 {
		ev.Result = "ok"
		ev.Count = matched
		ev.Files = written
		ev.Detail = fmt.Sprintf("覆盖 %d 个文件", matched)
		if skipped > 0 {
			ev.Detail += fmt.Sprintf("，跳过 %d 个未变化文件", skipped)
		}
		_ = e.store.TouchSyncRule(rule.ID, ev.Detail)
		e.store.Audit("system", "sync", "sync", rule.Name+" <- "+ci.Name+": "+ev.Detail)
	}
	return ev
}

func (e *SyncEngine) tryPEM(name, kind string) (string, bool) {
	s, err := e.certs.ReadPEM(name, kind)
	return s, err == nil
}

func (e *SyncEngine) tryKey(name string) (string, bool) {
	s, err := e.certs.ReadKey(name)
	return s, err == nil
}

// syncFileKind 按文件名判断这是私钥、证书链还是证书。
func syncFileKind(name string) string {
	lower := strings.ToLower(name)
	// 注意顺序：fullchain 同时含 "chain"，必须先判断，否则会被误判为证书链。
	switch {
	case strings.Contains(lower, "key") || strings.Contains(lower, "priv"):
		return "key"
	case strings.Contains(lower, "fullchain"):
		return "cert"
	case strings.Contains(lower, "chain") ||
		strings.Contains(lower, "_ca.") || strings.HasPrefix(lower, "ca."):
		// 不再用宽泛的 HasPrefix("ca")：caddy.example.com_cert.pem 会被误判成证书链
		return "chain"
	default:
		return "cert"
	}
}

// certExactClaims 建立「文件名域名 -> 拥有该域名证书的目录名」映射（主域名 + 非通配 SAN）。
// 用于同步匹配的精确归属判定：目标文件名里的域名与某张证书完全同名时，
// 只允许那张证书写入该文件，泛域名/子域匹配不得抢写，
// 避免同一文件被多张证书轮流覆盖（表现为文件内容与文件名域名对不上）。
func certExactClaims(all []CertInfo) map[string]string {
	claims := map[string]string{}
	for _, ci := range all {
		if ci.Status == "invalid" || ci.Status == "expired" {
			continue
		}
		if d := strings.ToLower(ci.Domain); d != "" {
			if _, exists := claims[d]; !exists {
				claims[d] = ci.Name
			}
		}
		for _, san := range ci.SANs {
			s := strings.ToLower(san)
			if s == "" || strings.HasPrefix(s, "*.") {
				continue
			}
			if _, exists := claims[s]; !exists {
				claims[s] = ci.Name
			}
		}
	}
	return claims
}

// match 判断目标文件是否命中规则。claims 为精确归属映射（见 certExactClaims），
// 目标文件已归属其它证书时，本证书不得通过子域/通配/SAN 途径认领。
// MatchNames 按文件名直接判断一条规则会命中哪些文件（不需要读取文件内容）。
// 用于远程目录的类型标注：远程文件读不到内容，按文件名域名参与匹配。
// 返回 文件名 -> 类型（key/cert/chain）。SAN 模式在远程场景退化为按文件名域名的常规判定；
// 精确归属判定与本地一致：文件名域名已有独立证书时只归那张证书，泛域不抢标。
func (e *SyncEngine) MatchNames(rule SyncRule, names []string) map[string]string {
	out := map[string]string{}
	if !rule.Enabled || !syncModeCodes[rule.Mode] {
		return out
	}
	all, err := e.certs.Scan()
	if err != nil {
		return out
	}
	return e.matchNames(rule, names, all)
}

func (e *SyncEngine) matchNames(rule SyncRule, names []string, all []CertInfo) map[string]string {
	out := map[string]string{}
	if !syncModeCodes[rule.Mode] {
		return out
	}
	claims := certExactClaims(all)
	for _, name := range names {
		domain := certFileDomain(name)
		for _, ci := range all {
			if ci.Status == "invalid" || ci.Status == "expired" {
				continue
			}
			if rule.Source != "" && rule.Source != "*" && rule.Source != ci.Name {
				continue
			}
			if e.matchName(rule, ci, name, domain, claims) {
				if _, exists := out[name]; !exists {
					out[name] = syncFileKind(name)
				}
				break
			}
		}
	}
	return out
}

// matchName 与 match 的判定规则一致，但不依赖目标文件内容（远程场景）：
// SAN 模式退化为文件名域名与证书域名的常规判定（相等或子域）。
func (e *SyncEngine) matchName(rule SyncRule, ci CertInfo, filename, domain string, claims map[string]string) bool {
	if domain != "" && len(claims) > 0 {
		if owner, ok := claims[strings.ToLower(domain)]; ok && !strings.EqualFold(owner, ci.Name) {
			return false
		}
	}
	switch rule.Mode {
	case syncExact:
		return domain != "" && strings.EqualFold(domain, ci.Domain)
	case syncSubdomain:
		return domainMatches(domain, ci)
	case syncWildcard:
		for _, san := range ci.SANs {
			if strings.HasPrefix(san, "*.") && isOneLevelSubdomain(strings.ToLower(domain), strings.TrimPrefix(san, "*.")) {
				return true
			}
		}
		return false
	case syncFilename:
		if rule.Pattern == "" {
			return false
		}
		ok, err := filepath.Match(rule.Pattern, filename)
		return err == nil && ok
	case syncSAN:
		return domainMatches(domain, ci)
	}
	return false
}

func (e *SyncEngine) match(rule SyncRule, ci CertInfo, filename, domain, fullPath string, claims map[string]string) bool {
	if domain != "" && len(claims) > 0 {
		if owner, ok := claims[strings.ToLower(domain)]; ok && !strings.EqualFold(owner, ci.Name) {
			return false
		}
	}
	switch rule.Mode {
	case syncExact:
		return domain != "" && strings.EqualFold(domain, ci.Domain)
	case syncSubdomain:
		return domainMatches(domain, ci)
	case syncWildcard:
		for _, san := range ci.SANs {
			if strings.HasPrefix(san, "*.") && isOneLevelSubdomain(strings.ToLower(domain), strings.TrimPrefix(san, "*.")) {
				return true
			}
		}
		return false
	case syncFilename:
		if rule.Pattern == "" {
			return false
		}
		ok, err := filepath.Match(rule.Pattern, filename)
		return err == nil && ok
	case syncSAN:
		return e.matchBySAN(ci, fullPath)
	}
	return false
}

// matchBySAN 读取目标证书，比较 CN/SAN 与源证书是否有交集，或目标是源证书的子域。
func (e *SyncEngine) matchBySAN(ci CertInfo, path string) bool {
	b, err := os.ReadFile(path)
	if err != nil || len(b) > 1<<20 {
		return false
	}
	block, _ := pem.Decode(b)
	if block == nil {
		// 私钥等无法解析为证书的文件：按文件名域名兜底匹配
		return domainMatches(certFileDomain(filepath.Base(path)), ci)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		// 私钥 PEM 的 block 存在但不是证书：同样按文件名域名兜底
		return domainMatches(certFileDomain(filepath.Base(path)), ci)
	}
	source := map[string]bool{}
	for _, s := range ci.SANs {
		source[strings.ToLower(s)] = true
	}
	source[strings.ToLower(ci.Domain)] = true
	for _, s := range cert.DNSNames {
		if source[strings.ToLower(s)] {
			return true
		}
	}
	if source[strings.ToLower(cert.Subject.CommonName)] {
		return true
	}
	// 通配 SAN 的常规副作用：目标证书是 *.xxx 的某个子域证书。
	if domainMatches(certFileDomain(filepath.Base(path)), ci) {
		return true
	}
	return false
}

// domainMatches 判断证书是否实际覆盖目标域名：只有证书里真实存在的域名才算——
// 非通配 CN/SAN 精确相等，或通配符 SAN 覆盖的同一级子域。
// 不做「主域名的任意子域」推断：证书只签了 a.b.com 就不能认领 x.b.com，
// 这是用户报告的「证书明明只覆盖 mypython.example.net 却匹配了别的 *.example.net 文件」的根因。
func domainMatches(domain string, ci CertInfo) bool {
	return certCoversDomain(domain, ci)
}

// certCoversDomain 按证书内容（CN/SAN）判断实际覆盖范围。
// ACME 通配符证书只覆盖一级子域：*.a.b 命中 x.a.b，不命中 x.y.a.b，也不命中 a.b 本身。
func certCoversDomain(domain string, ci CertInfo) bool {
	d := strings.ToLower(strings.TrimSpace(domain))
	if d == "" {
		return false
	}
	if strings.EqualFold(d, ci.Domain) {
		return true
	}
	for _, san := range ci.SANs {
		s := strings.ToLower(strings.TrimSpace(san))
		if strings.HasPrefix(s, "*.") {
			if isOneLevelSubdomain(d, strings.TrimPrefix(s, "*.")) {
				return true
			}
		} else if d == s {
			return true
		}
	}
	return false
}

// isOneLevelSubdomain 判断 domain 是否为 base 的直接子域（只差一级标签）：
// x.base 命中，x.y.base 不命中。head 是去掉 ".base" 后缀剩下的部分。
func isOneLevelSubdomain(domain, base string) bool {
	base = strings.ToLower(strings.TrimSpace(base))
	if domain == "" || base == "" || len(domain) <= len(base)+1 {
		return false
	}
	head, ok := strings.CutSuffix(domain, "."+base)
	if !ok {
		return false
	}
	return !strings.Contains(head, ".")
}

// isSubdomainOf 判断 domain 是否为 parent 的子域（任意层级）。
// 仅用于远程主机「负责的域名」过滤（用户配置的主机管辖范围，按子域理解是本意）；
// 证书匹配一律走 certCoversDomain（严格按证书实际签发的域名）。
func isSubdomainOf(domain, parent string) bool {
	if domain == "" || parent == "" {
		return false
	}
	return len(domain) > len(parent)+1 &&
		strings.HasSuffix(strings.ToLower(domain), "."+strings.ToLower(parent))
}

// certFileDomain 从证书文件名里提取域名：sub.example.com_cert.pem -> sub.example.com。
func certFileDomain(name string) string {
	s := strings.ToLower(name)
	for _, suffix := range []string{".pem", ".cer", ".crt"} {
		s = strings.TrimSuffix(s, suffix)
	}
	for _, suffix := range []string{"_fullchain", "_cert", "_chain", "_key", "-cert", "-key"} {
		s = strings.TrimSuffix(s, suffix)
	}
	return s
}

// certCandidates 收集目录里可作为同步目标的证书文件（排除私钥/链/CA）。
func certCandidates(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		lower := strings.ToLower(name)
		if !(strings.HasSuffix(lower, ".pem") || strings.HasSuffix(lower, ".cer") || strings.HasSuffix(lower, ".crt") || strings.HasSuffix(lower, ".key")) {
			continue
		}
		// 跳过明显无关的文件，但保留 key/chain/ca —— 它们也要按类型分别写入
		if strings.Contains(lower, ".lock") || strings.HasSuffix(lower, ".csr") {
			continue
		}
		out = append(out, name)
	}
	return out, nil
}

// DirStatus 是挂载目录的可访问状态，供 Web 提示。
type DirStatus struct {
	Dir       string `json:"dir"`
	Readable  bool   `json:"readable"`
	Writable  bool   `json:"writable"`
	FileCount int    `json:"file_count"`
	Hint      string `json:"hint"`
}

// CheckDirs 检查每个目录的读写权限，返回友好提示。
func (e *SyncEngine) CheckDirs() []DirStatus {
	out := []DirStatus{}
	for _, dir := range e.dirs {
		d := DirStatus{Dir: dir}
		if info, err := os.Stat(dir); err != nil {
			d.Hint = "目录不存在或未挂载。请检查 docker-compose 的 volumes 挂载。"
		} else if !info.IsDir() {
			d.Hint = "路径不是目录。"
		} else {
			files, err := certCandidates(dir)
			if err != nil {
				d.Hint = "无权限读取。容器以 uid 10001 运行，请在宿主机执行：chown -R 10001:10001 " + dir + " 或 chmod o+rx " + dir
			} else {
				d.Readable = true
				d.FileCount = len(files)
				// 用临时文件探测写权限
				probe, err := os.CreateTemp(dir, ".acme-write-test-*")
				if err != nil {
					d.Hint = "可读但不可写。请在宿主机执行：chown -R 10001:10001 " + dir
				} else {
					d.Writable = true
					name := probe.Name()
					probe.Close()
					os.Remove(name)
				}
			}
		}
		out = append(out, d)
	}
	return out
}

// ListFiles 列出所有挂载目录里的证书文件，供 Web 展示"目录里现在有什么"。
func (e *SyncEngine) ListFiles() []SyncFile {
	out := []SyncFile{}
	for _, dir := range e.dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			lower := strings.ToLower(name)
			if !(strings.HasSuffix(lower, ".pem") || strings.HasSuffix(lower, ".cer") || strings.HasSuffix(lower, ".crt") || strings.HasSuffix(lower, ".key")) {
				continue
			}
			info, err := entry.Info()
			if err != nil {
				continue
			}
			f := SyncFile{Dir: dir, Name: name, Domain: certFileDomain(name), Kind: syncFileKind(name), Size: info.Size()}
			if b, err := os.ReadFile(filepath.Join(dir, name)); err == nil && len(b) <= 1<<20 {
				if block, _ := pem.Decode(b); block != nil && strings.Contains(block.Type, "CERTIFICATE") {
					f.HasCert = true
					if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
						f.CN = cert.Subject.CommonName
					}
				}
			}
			out = append(out, f)
		}
	}
	return out
}

// Preview 只计算不写入：给定规则参数，返回会命中哪些目标文件。
func (e *SyncEngine) Preview(rule SyncRule) []SyncPreviewItem {
	out := []SyncPreviewItem{}
	if !syncModeCodes[rule.Mode] {
		return out
	}
	all, err := e.certs.Scan()
	if err != nil {
		return out
	}
	claims := certExactClaims(all)
	for _, dir := range e.dirs {
		candidates, err := certCandidates(dir)
		if err != nil {
			continue
		}
		for _, ci := range all {
			if ci.Status == "invalid" || ci.Status == "expired" {
				continue
			}
			if rule.Source != "" && rule.Source != "*" && rule.Source != ci.Name {
				continue
			}
			for _, name := range candidates {
				full := filepath.Join(dir, name)
				domain := certFileDomain(name)
				if !e.match(rule, ci, name, domain, full, claims) {
					continue
				}
				kind := syncFileKind(name)
				content := map[string]string{"key": "新私钥", "chain": "新证书链", "cert": "新证书"}[kind]
				out = append(out, SyncPreviewItem{
					Dir: dir, Source: ci.Name, SourceName: ci.Domain, Domain: domain,
					File: name, Kind: kind, Content: content,
				})
			}
		}
	}
	return out
}

// RuleMatchedFiles 用与本地同步完全相同的匹配逻辑算出一条规则会命中哪些文件，
// 按目录分组返回，供远程同步只推送"规则选中的文件"，而不是整个目录。
func (e *SyncEngine) RuleMatchedFiles(rule SyncRule) map[string][]string {
	out := map[string][]string{}
	if !rule.Enabled || !syncModeCodes[rule.Mode] {
		return out
	}
	all, err := e.certs.Scan()
	if err != nil {
		return out
	}
	claims := certExactClaims(all)
	for _, dir := range e.dirs {
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		candidates, err := certCandidates(dir)
		if err != nil || len(candidates) == 0 {
			continue
		}
		seen := map[string]bool{}
		for _, ci := range all {
			if ci.Status == "invalid" || ci.Status == "expired" {
				continue
			}
			if rule.Source != "" && rule.Source != "*" && rule.Source != ci.Name {
				continue
			}
			for _, name := range candidates {
				full := filepath.Join(dir, name)
				if !e.match(rule, ci, name, certFileDomain(name), full, claims) {
					continue
				}
				if seen[name] {
					continue
				}
				seen[name] = true
				out[dir] = append(out[dir], name)
			}
		}
	}
	return out
}

// RemoteCertMatch 是远程文件与面板已签名证书的内容匹配结果。
// Source 是面板证书目录名，Domain 是目标证书里命中的域名（用于展示与去重）。
type RemoteCertMatch struct {
	Source string `json:"source"`
	Domain string `json:"domain"`
	Kind   string `json:"kind"`
}

// remoteCertDomains 解析 PEM 内容里所有证书块的 CN 与 DNS SAN。
// 私有 key 文件不含证书块，返回空列表；调用方按文件名配对处理。
func remoteCertDomains(data []byte) []string {
	out := []string{}
	seen := map[string]bool{}
	add := func(s string) {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" || strings.HasPrefix(s, "*.") {
			return // 通配写法留到匹配阶段处理，避免 "*.a.com" 被当成真实域名
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	rest := data
	for {
		block, tail := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = tail
		if !strings.Contains(block.Type, "CERTIFICATE") {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		add(cert.Subject.CommonName)
		for _, dns := range cert.DNSNames {
			add(dns)
		}
	}
	return out
}

// matchSignedCertByDomains 用目标证书里的域名与面板已签名证书对比：
// 目标域名等于证书的 CN/非通配 SAN，或被证书的通配 SAN 覆盖（一级），即为命中。
// 多张证书都命中时优先精确域名（不含通配），再按证书名排序保证结果稳定。
func matchSignedCertByDomains(domains []string, all []CertInfo) (CertInfo, string, bool) {
	best := CertInfo{}
	bestDomain := ""
	bestScore := 0
	found := false
	for _, ci := range all {
		if ci.Status == "invalid" || ci.Status == "expired" {
			continue
		}
		for _, d := range domains {
			dl := strings.ToLower(strings.TrimSpace(d))
			if dl == "" {
				continue
			}
			score := 0
			if strings.EqualFold(dl, ci.Domain) {
				score = 3 // 精确主域名
			} else {
				for _, san := range ci.SANs {
					s := strings.ToLower(strings.TrimSpace(san))
					if s == dl {
						if score < 3 {
							score = 2 // 精确 SAN
						}
					} else if strings.HasPrefix(s, "*.") && isOneLevelSubdomain(dl, strings.TrimPrefix(s, "*.")) {
						if score < 1 {
							score = 1 // 通配覆盖的一级子域
						}
					}
				}
			}
			if score > bestScore || (score == bestScore && score > 0 && (best.Name == "" || ci.Name < best.Name)) {
				best, bestDomain, bestScore, found = ci, dl, score, true
			}
		}
	}
	return best, bestDomain, found
}

// matchRemoteCerts 把远程文件与面板证书按「内容」对比，返回文件名 -> 匹配结果。
// certContents 为远程证书文件的实际 PEM 内容（key 文件为空）；面板证书列表来自 CertScanner.Scan()。
// 私钥等读不出证书的文件：用文件名前缀（去 _key/_cert 等后缀）与已匹配的证书文件配对，
// 这样 dockge.xxx_cert.pem 命中后，配套的 dockge.xxx_key.pem 也会一起标注/同步。
func matchRemoteCerts(names []string, certContents map[string][]byte, all []CertInfo) map[string]RemoteCertMatch {
	out := map[string]RemoteCertMatch{}
	// 第一轮：能解析的证书文件按内容匹配。
	for _, name := range names {
		data, ok := certContents[name]
		if !ok || len(data) == 0 {
			continue
		}
		domains := remoteCertDomains(data)
		if len(domains) == 0 {
			continue
		}
		if ci, domain, ok := matchSignedCertByDomains(domains, all); ok {
			out[name] = RemoteCertMatch{Source: ci.Name, Domain: domain, Kind: syncFileKind(name)}
		}
	}
	// 第二轮：私钥/读不出内容的文件，按文件名域名兜底（与本地严格匹配同逻辑），
	// 或按同前缀已命中证书继承结果。
	for _, name := range names {
		if _, ok := out[name]; ok {
			continue
		}
		domain := certFileDomain(name)
		if domain == "" {
			continue
		}
		if ci, hitDomain, ok := matchSignedCertByDomains([]string{domain}, all); ok {
			out[name] = RemoteCertMatch{Source: ci.Name, Domain: hitDomain, Kind: syncFileKind(name)}
			continue
		}
		// 同前缀证书文件已命中时继承（例如文件名域名与证书域名不一致的部署）。
		for other, m := range out {
			if certFileDomain(other) == domain {
				out[name] = RemoteCertMatch{Source: m.Source, Domain: m.Domain, Kind: syncFileKind(name)}
				break
			}
		}
	}
	return out
}

// syncPermHint 给出修复指引。dir 是容器内路径，宿主机路径可能不同，
// 所以用 docker inspect 自动反查，避免让用户猜路径。
func syncPermHint(dir string) string {
	return fmt.Sprintf("修复方法：在宿主机执行 docker exec -u root acmesh-panel chown -R 10001:10001 %s（用容器内路径即可，不用找宿主机路径）", dir)
}

// writeAtomic 先写临时文件再 rename，避免目标被读到半截内容。
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".sync-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return errors.New("替换目标文件失败: " + err.Error())
	}
	return nil
}
