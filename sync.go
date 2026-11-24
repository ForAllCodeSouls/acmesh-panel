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
// 典型场景：挂载目录里已有 baihu.loveli.de5.net_cert.pem / _key.pem，
// 面板证书为 *.loveli.de5.net，续期后自动用新内容替换这两个文件。

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
	{syncExact, "精确域名", "目标文件名域名与证书主域名一致"},
	{syncSubdomain, "子域名（含通配）", "如 baihu.example.com 命中 example.com 或 *.example.com"},
	{syncWildcard, "仅通配符 SAN", "仅命中证书里 *. 开头的 SAN"},
	{syncFilename, "文件名模式", "用 * / ? 通配符匹配文件名，如 *_cert.pem"},
	{syncSAN, "现有证书 CN/SAN", "读取目标目录里的证书，按 CN 与 SAN 交集匹配"},
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
	Time   string `json:"time"`
	Rule   string `json:"rule"`
	Source string `json:"source"`
	Target string `json:"target"`
	Result string `json:"result"` // ok | skip | fail
	Detail string `json:"detail"`
}

var syncPresets = []struct {
	Name     string `json:"name"`
	Mode     string `json:"mode"`
	Pattern  string `json:"pattern"`
	CertTmpl string `json:"cert_tmpl"`
	KeyTmpl  string `json:"key_tmpl"`
}{
	{"按现有证书 CN/SAN 自动匹配", syncSAN, "", "{domain}_cert.pem", "{domain}_key.pem"},
	{"按子域名自动匹配", syncSubdomain, "", "{domain}_cert.pem", "{domain}_key.pem"},
	{"按精确域名匹配", syncExact, "", "{domain}_cert.pem", "{domain}_key.pem"},
	{"按文件名模式匹配", syncFilename, "*_cert.pem", "{domain}_cert.pem", "{domain}_key.pem"},
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
			}
		}
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
		Time:   time.Now().UTC().Format(time.RFC3339),
		Rule:   rule.Name,
		Source: ci.Name,
		Result: "skip",
		Detail: "未匹配到目标文件",
	}

	// 收集候选证书文件（只认常见的证书后缀，避免误写 P12/配置）。
	entries, err := os.ReadDir(dir)
	if err != nil {
		ev.Result, ev.Detail = "fail", "读取挂载目录失败: "+err.Error()
		return ev
	}
	candidates := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		lower := strings.ToLower(name)
		if !(strings.HasSuffix(lower, ".pem") || strings.HasSuffix(lower, ".cer") || strings.HasSuffix(lower, ".crt")) {
			continue
		}
		if strings.Contains(lower, "key") || strings.Contains(lower, "chain") || strings.Contains(lower, "ca.") {
			continue
		}
		candidates = append(candidates, name)
	}

	certTmpl := rule.CertTmpl
	if certTmpl == "" {
		certTmpl = "{domain}_cert.pem"
	}
	keyTmpl := rule.KeyTmpl
	if keyTmpl == "" {
		keyTmpl = "{domain}_key.pem"
	}

	matched := 0
	for _, name := range candidates {
		target := filepath.Join(dir, name)
		domain := certFileDomain(name)
		if !e.match(rule, ci, name, domain, target) {
			continue
		}
		fullchain, err := e.certs.ReadPEM(ci.Name, "fullchain")
		if err != nil {
			ev.Result, ev.Detail = "fail", "读取源证书失败: "+err.Error()
			continue
		}
		// 目标证书文件名：优先按模板，模板里 {domain} 用目标文件名域名替换。
		certPath := target
		if strings.Contains(certTmpl, "{domain}") {
			certPath = filepath.Join(dir, strings.ReplaceAll(certTmpl, "{domain}", domain))
		}
		if err := writeAtomic(certPath, []byte(fullchain), 0o644); err != nil {
			ev.Result, ev.Detail = "fail", "写入证书失败: "+err.Error()
			continue
		}
		written := []string{filepath.Base(certPath)}

		// 私钥：按模板推导_key 文件；源文件不存在则只更新证书。
		keyPath := filepath.Join(dir, strings.ReplaceAll(keyTmpl, "{domain}", domain))
		key, kerr := e.certs.ReadKey(ci.Name)
		if kerr == nil {
			if err := writeAtomic(keyPath, []byte(key), 0o600); err != nil {
				ev.Result, ev.Detail = "fail", "写入私钥失败: "+err.Error()
			} else {
				written = append(written, filepath.Base(keyPath))
			}
		}

		if ev.Result != "fail" {
			ev.Result, ev.Detail = "ok", "已覆盖: "+strings.Join(written, ", ")
			matched++
		}
	}

	if matched > 0 {
		_ = e.store.TouchSyncRule(rule.ID, ev.Detail)
		e.store.Audit("system", "sync", "sync", rule.Name+" <- "+ci.Name+": "+ev.Detail)
	}
	return ev
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
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
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

// certFileDomain 从证书文件名里提取域名：baihu.example.com_cert.pem -> baihu.example.com。
func certFileDomain(name string) string {
	s := strings.ToLower(name)
	for _, suffix := range []string{".pem", ".cer", ".crt"} {
		s = strings.TrimSuffix(s, suffix)
	}
	for _, suffix := range []string{"_cert", "_fullchain", "_chain", "-cert"} {
		s = strings.TrimSuffix(s, suffix)
	}
	return s
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
