package main

import (
	"crypto/x509"
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
	{syncSubdomain, "子域名（推荐）", "文件名里的域名是证书的子域即可。例：面板证书 *.example.com，命中 sub.example.com_cert.pem"},
	{syncWildcard, "仅通配符", "只按证书里 *. 开头的域名匹配，精确域名不算。适合严格限制泛域名证书"},
	{syncFilename, "文件名模式", "用 * 或 ? 匹配文件名，不解析域名。例：*_cert.pem 匹配所有以 _cert.pem 结尾的文件"},
	{syncSAN, "按现有证书内容（推荐）", "读取目录里已有证书，比对里面的域名。适合目标文件名与域名不一致的情况"},
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
	ID       string `json:"id"`
	Name     string `json:"name"`
	Enabled  bool   `json:"enabled"`
	Mode     string `json:"mode"`
	Pattern  string `json:"pattern"`
	Source   string `json:"source"` // 面板证书目录名；* 或空表示全部
	CertTmpl string `json:"cert_tmpl"`
	KeyTmpl  string `json:"key_tmpl"`
	LastSync string `json:"last_sync"`
	LastInfo string `json:"last_info"`
}

// SyncEvent 是一次同步尝试的记录（成功/跳过/失败都会记）。
type SyncEvent struct {
	Time   string   `json:"time"`
	Rule   string   `json:"rule"`
	Source string   `json:"source"`
	Target string   `json:"target"`
	Result string   `json:"result"` // ok | skip | fail
	Detail string   `json:"detail"`
	Count  int      `json:"count"` // 覆盖的文件数
	Files  []string `json:"files"` // 覆盖的文件名列表（带类型标注，用于展示）

	WrittenFiles []string `json:"-"` // 真实写入的文件名（仅内部用于远程推送，不落盘）
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
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out
}

// run 执行全部启用的规则，返回本次产生的事件。
func (e *SyncEngine) run(trigger string) []SyncEvent {
	events := []SyncEvent{}
	if !e.Enabled() {
		return events
	}
	rules := e.store.ListSyncRules()
	if len(rules) == 0 {
		return events
	}
	all, err := e.certs.Scan()
	if err != nil {
		return events
	}
	// 按目录聚合本次成功写入的文件，用于远程主机同步。
	byDir := map[string][]string{}
	for _, dir := range e.dirs {
		// 目录不存在时静默跳过，避免挂载未就绪就刷错误日志。
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		for _, rule := range rules {
			if !rule.Enabled || !syncModeCodes[rule.Mode] {
				continue
			}
			for _, ci := range all {
				if ci.Status == "invalid" || ci.Status == "expired" {
					continue
				}
				if rule.Source != "" && rule.Source != "*" && rule.Source != ci.Name {
					continue
				}
				ev := e.apply(rule, ci, dir, trigger)
				ev.Target = dir + " → " + ev.Target
				events = append(events, ev)
				if ev.Result == "ok" {
					byDir[dir] = append(byDir[dir], ev.WrittenFiles...)
				}
			}
		}
	}

	// 推送到远程主机（每台启用的主机），并合并进事件列表。
	for dir, files := range byDir {
		if len(files) == 0 {
			continue
		}
		events = append(events, pushAllRemotes(e.store, dir, files)...)
	}

	if len(events) > 0 {
		_ = e.store.AddSyncEvents(events)
	}
	okCount, failCount := 0, 0
	for _, ev := range events {
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
	return events
}

// apply 对单张证书应用一条规则。
func (e *SyncEngine) apply(rule SyncRule, ci CertInfo, dir, trigger string) SyncEvent {
	ev := SyncEvent{
		Time:   time.Now().Format(time.RFC3339),
		Rule:   rule.Name,
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

	matched := 0
	written := []string{}
	for _, name := range candidates {
		target := filepath.Join(dir, name)
		domain := certFileDomain(name)
		if !e.match(rule, ci, name, domain, target) {
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
		written = append(written, name+"("+kind+")")
		ev.WrittenFiles = append(ev.WrittenFiles, name)
		matched++
	}

	if matched > 0 {
		ev.Result = "ok"
		ev.Count = matched
		ev.Files = written
		ev.Detail = fmt.Sprintf("覆盖 %d 个文件", matched)
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
	case strings.Contains(lower, "chain") || strings.Contains(lower, "ca.") || strings.HasPrefix(lower, "ca"):
		return "chain"
	default:
		return "cert"
	}
}

// match 判断目标文件是否命中规则。
func (e *SyncEngine) match(rule SyncRule, ci CertInfo, filename, domain, fullPath string) bool {
	switch rule.Mode {
	case syncExact:
		return domain != "" && strings.EqualFold(domain, ci.Domain)
	case syncSubdomain:
		return domainMatches(domain, ci)
	case syncWildcard:
		for _, san := range ci.SANs {
			if strings.HasPrefix(san, "*.") && isSubdomainOf(domain, strings.TrimPrefix(san, "*.")) {
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

// domainMatches 判断目标域名是否等于证书主域名、或是它的子域（含通配 SAN）。
func domainMatches(domain string, ci CertInfo) bool {
	if domain == "" {
		return false
	}
	if strings.EqualFold(domain, ci.Domain) || isSubdomainOf(domain, ci.Domain) {
		return true
	}
	for _, san := range ci.SANs {
		san = strings.TrimPrefix(san, "*.")
		if strings.EqualFold(domain, san) || isSubdomainOf(domain, san) {
			return true
		}
	}
	return false
}

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
				if !e.match(rule, ci, name, domain, full) {
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
