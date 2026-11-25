package main

import (
	"testing"
)

// 复现用户真实环境的误同步场景：泛域名证书按子域匹配抢写
// 已有独立证书的子域文件，导致文件内容与文件名域名对不上。
func certInfoFor(name, domain string, sans []string) CertInfo {
	return CertInfo{
		Name:    name,
		Domain:  domain,
		Status:  "valid",
		Subject: "CN=" + domain,
		SANs:    sans,
		CA:      "zerossl",
	}
}

func subdomainRule() SyncRule {
	return SyncRule{ID: "r1", Name: "按子域名匹配（泛域名证书常用）", Enabled: true, Mode: syncSubdomain, Source: "*"}
}

func TestExactClaimPreventsWildcardOverwrite(t *testing.T) {
	// 面板里的证书：wild 泛域（SAN 含 *.wild.example.net）、
	// host1/host2 子域各自有独立证书、other 泛域。
	all := []CertInfo{
		certInfoFor("wild.example.net", "wild.example.net", []string{"wild.example.net", "*.wild.example.net"}),
		certInfoFor("host1.wild.example.net", "host1.wild.example.net", []string{"host1.wild.example.net"}),
		certInfoFor("host2.wild.example.net", "host2.wild.example.net", []string{"host2.wild.example.net"}),
		certInfoFor("other.example.net", "other.example.net", []string{"other.example.net", "*.other.example.net"}),
	}
	claims := certExactClaims(all)
	rule := subdomainRule()
	e := &SyncEngine{}

	// host1 文件只归 host1 证书所有；wild 泛域证书不得按子域抢写。
	if e.match(rule, all[0], "host1.wild.example.net_cert.pem", "host1.wild.example.net", "/certs/host1.wild.example.net_cert.pem", claims) {
		t.Fatal("泛域证书抢写了已有独立证书的子域文件（用户报告的乱同步根因）")
	}
	if !e.match(rule, all[1], "host1.wild.example.net_cert.pem", "host1.wild.example.net", "/certs/host1.wild.example.net_cert.pem", claims) {
		t.Fatal("文件名域名与证书完全同名时应命中")
	}
	// 私钥文件同样受精确归属保护。
	if e.match(rule, all[0], "host2.wild.example.net_key.pem", "host2.wild.example.net", "/certs/host2.wild.example.net_key.pem", claims) {
		t.Fatal("泛域证书抢写了子域私钥文件")
	}

	// 没有独立证书的子域文件（如 panel.other.example.net）仍由泛域证书认领，
	// 这是泛域名同步的本意。
	if !e.match(rule, all[3], "panel.other.example.net_cert.pem", "panel.other.example.net", "/certs/panel.other.example.net_cert.pem", claims) {
		t.Fatal("无独立证书的子域文件应由泛域证书认领")
	}

	// 无独立证书的场景下泛域匹配保持原行为：claims 为空时不过滤。
	if !e.match(rule, all[0], "host1.wild.example.net_cert.pem", "host1.wild.example.net", "/certs/host1.wild.example.net_cert.pem", nil) {
		t.Fatal("无归属映射时应保持泛域匹配原行为")
	}
}

func TestExactClaimIncludesNonWildcardSAN(t *testing.T) {
	// 证书 SAN 里明确列出的非通配域名也算精确归属。
	all := []CertInfo{
		certInfoFor("multi.example.net", "multi.example.net", []string{"multi.example.net", "api.example.net"}),
		certInfoFor("base.example.net", "base.example.net", []string{"base.example.net", "*.example.net"}),
	}
	claims := certExactClaims(all)
	rule := subdomainRule()
	e := &SyncEngine{}

	if e.match(rule, all[1], "api.example.net_cert.pem", "api.example.net", "/certs/api.example.net_cert.pem", claims) {
		t.Fatal("SAN 精确列出的域名应阻止其它证书按子域抢写")
	}
	if !e.match(rule, all[0], "api.example.net_cert.pem", "api.example.net", "/certs/api.example.net_cert.pem", claims) {
		t.Fatal("SAN 精确列出该域名的证书应命中")
	}
}

func TestExactClaimAppliesToWildcardAndSANModes(t *testing.T) {
	all := []CertInfo{
		certInfoFor("wild.example.net", "wild.example.net", []string{"wild.example.net", "*.wild.example.net"}),
		certInfoFor("news.wild.example.net", "news.wild.example.net", []string{"news.wild.example.net"}),
	}
	claims := certExactClaims(all)
	e := &SyncEngine{}

	wildcardRule := SyncRule{ID: "r2", Name: "仅通配符", Enabled: true, Mode: syncWildcard, Source: "*"}
	if e.match(wildcardRule, all[0], "news.wild.example.net_cert.pem", "news.wild.example.net", "/certs/news.wild.example.net_cert.pem", claims) {
		t.Fatal("仅通配符模式同样不得抢写已有独立证书的子域文件")
	}

	sanRule := SyncRule{ID: "r3", Name: "按现有证书内容", Enabled: true, Mode: syncSAN, Source: "*"}
	if e.match(sanRule, all[0], "news.wild.example.net_cert.pem", "news.wild.example.net", "/certs/news.wild.example.net_cert.pem", claims) {
		t.Fatal("SAN 模式同样不得抢写已有独立证书的子域文件")
	}
}

func TestCertExactClaimsBasics(t *testing.T) {
	all := []CertInfo{
		certInfoFor("example.net", "example.net", []string{"example.net", "*.example.net"}),
		{Name: "bad.example.net", Domain: "bad.example.net", Status: "expired"},
	}
	claims := certExactClaims(all)
	if _, ok := claims["example.net"]; !ok {
		t.Fatal("主域名应进入归属映射")
	}
	if _, ok := claims["sub.example.net"]; ok {
		t.Fatal("通配 SAN 不应作为精确归属")
	}
	if _, ok := claims["bad.example.net"]; ok {
		t.Fatal("过期证书不应进入归属映射")
	}
}

// 远程目录的类型标注：文件读不到内容，按文件名直接参与匹配（matchName/MatchNames）。
func TestMatchNamesRemote(t *testing.T) {
	all := []CertInfo{
		certInfoFor("wild.example.net", "wild.example.net", []string{"wild.example.net", "*.wild.example.net"}),
		certInfoFor("host1.wild.example.net", "host1.wild.example.net", []string{"host1.wild.example.net"}),
		certInfoFor("other.example.net", "other.example.net", []string{"other.example.net", "*.other.example.net"}),
	}
	names := []string{
		"host1.wild.example.net_cert.pem",
		"host1.wild.example.net_key.pem",
		"panel.other.example.net_cert.pem",
		"panel.other.example.net_key.pem",
		"ticket12.key",
		".kpanel-certificate.lock",
	}
	e := &SyncEngine{}

	// 子域名模式：子域证书文件归它自己，无独立证书的子域归泛域；无关文件不标。
	sub := subdomainRule()
	got := e.matchNames(sub, names, all)
	if got["host1.wild.example.net_cert.pem"] != "cert" {
		t.Fatalf("子域证书文件应标注 cert，got=%v", got)
	}
	if got["host1.wild.example.net_key.pem"] != "key" {
		t.Fatalf("子域私钥文件应标注 key，got=%v", got)
	}
	if got["panel.other.example.net_cert.pem"] != "cert" || got["panel.other.example.net_key.pem"] != "key" {
		t.Fatalf("无独立证书的子域文件应由泛域证书标注，got=%v", got)
	}
	if _, ok := got["ticket12.key"]; ok {
		t.Fatalf("无关文件不应被标注，got=%v", got)
	}
	if _, ok := got[".kpanel-certificate.lock"]; ok {
		t.Fatalf("锁文件不应被标注，got=%v", got)
	}

	// SAN 模式远程退化：读不到内容时按文件名域名与证书域名判定。
	san := SyncRule{ID: "r2", Name: "按现有证书内容（推荐）", Enabled: true, Mode: syncSAN, Source: "*"}
	got = e.matchNames(san, names, all)
	if got["host1.wild.example.net_cert.pem"] != "cert" || got["panel.other.example.net_cert.pem"] != "cert" {
		t.Fatalf("SAN 模式远程标注失败，got=%v", got)
	}

	// 精确域名模式：只有与证书主域名完全同名的文件命中。
	exact := SyncRule{ID: "r3", Name: "按精确域名匹配", Enabled: true, Mode: syncExact, Source: "*"}
	got = e.matchNames(exact, names, all)
	if _, ok := got["host1.wild.example.net_cert.pem"]; !ok {
		t.Fatalf("精确域名模式应命中同名文件，got=%v", got)
	}
	if _, ok := got["panel.other.example.net_cert.pem"]; ok {
		t.Fatalf("精确域名模式不应命中子域文件，got=%v", got)
	}

	// 来源过滤：规则只针对某张证书时，其它证书的文件不标注。
	src := SyncRule{ID: "r4", Name: "限定来源", Enabled: true, Mode: syncSubdomain, Source: "host1.wild.example.net"}
	got = e.matchNames(src, names, all)
	if _, ok := got["panel.other.example.net_cert.pem"]; ok {
		t.Fatalf("来源过滤未生效，got=%v", got)
	}
	if got["host1.wild.example.net_cert.pem"] != "cert" {
		t.Fatalf("来源证书自身的文件应命中，got=%v", got)
	}
}
