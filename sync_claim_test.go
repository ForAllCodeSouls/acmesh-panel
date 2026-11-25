package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
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

// 严格按证书实际签发的域名匹配（用户报告：证书只签了 mypython.example.net + *.mypython.example.net，
// 面板却按「主域名的子域」推断匹配了别的 *.example.net 层级文件）。夹具用 RFC 占位域名。
func TestCertCoversDomainStrict(t *testing.T) {
	// 证书 CN=mypython.example.net，SAN=mypython.example.net, *.mypython.example.net
	ci := certInfoFor("mypython.example.net", "mypython.example.net",
		[]string{"mypython.example.net", "*.mypython.example.net"})
	rule := subdomainRule()
	e := &SyncEngine{}
	match := func(name string) bool {
		return e.match(rule, ci, name, certFileDomain(name), "/certs/"+name, nil)
	}

	if !match("mypython.example.net_cert.pem") {
		t.Fatal("文件名域名与证书 CN 完全同名时应命中")
	}
	if !match("mypython.example.net_key.pem") {
		t.Fatal("同名私钥文件应命中")
	}
	if !match("a.mypython.example.net_cert.pem") {
		t.Fatal("通配 SAN 覆盖的一级子域应命中")
	}
	if match("a.b.mypython.example.net_cert.pem") {
		t.Fatal("通配 SAN 不覆盖两级子域")
	}
	if match("web.example.net_cert.pem") {
		t.Fatal("证书没签的同级域名不得命中（用户报告的乱匹配根因）")
	}
	if match("example.net_cert.pem") {
		t.Fatal("证书没签的父域名不得命中")
	}
	if !match("other.mypython.example.net_key.pem") {
		t.Fatal("一级子域私钥应命中")
	}

	// 没有通配 SAN 的证书：不认领任何子域。
	plain := certInfoFor("base.example.net", "base.example.net", []string{"base.example.net"})
	if e.match(rule, plain, "sub.base.example.net_cert.pem", "sub.base.example.net", "/c/sub.base.example.net_cert.pem", nil) {
		t.Fatal("无非通配 SAN 的证书不得按主域名子域推断认领")
	}

	// SAN 精确列出的额外域名应命中（含对应私钥）。
	extra := certInfoFor("multi.example.net", "multi.example.net",
		[]string{"multi.example.net", "api.example.net"})
	if !e.match(rule, extra, "api.example.net_cert.pem", "api.example.net", "/c/api.example.net_cert.pem", nil) {
		t.Fatal("SAN 精确列出的域名应命中")
	}
	if !e.match(rule, extra, "api.example.net_key.pem", "api.example.net", "/c/api.example.net_key.pem", nil) {
		t.Fatal("SAN 精确列出的域名对应私钥应命中")
	}
}

func TestIsOneLevelSubdomain(t *testing.T) {
	cases := []struct {
		domain, base string
		want         bool
	}{
		{"a.example.net", "example.net", true},
		{"a.b.example.net", "example.net", false},
		{"example.net", "example.net", false},
		{"subexample.net", "example.net", false},
		{"a.mypython.example.net", "mypython.example.net", true},
		{"x.y.mypython.example.net", "mypython.example.net", false},
		{"", "example.net", false},
		{"a.example.net", "", false},
	}
	for _, c := range cases {
		if got := isOneLevelSubdomain(c.domain, c.base); got != c.want {
			t.Fatalf("isOneLevelSubdomain(%q,%q)=%v, want %v", c.domain, c.base, got, c.want)
		}
	}
}

// 远程文件列表排序：目录在前，其余按名称升序（大小写不敏感）。
func TestSortRemoteFiles(t *testing.T) {
	items := []RemoteFileItem{
		{Name: "zoo.pem"},
		{Name: "subdir", IsDir: true},
		{Name: "Baihu.example.net_cert.pem"},
		{Name: "api.example.net_key.pem"},
		{Name: "another", IsDir: true},
	}
	sortRemoteFiles(items)
	want := []string{"another", "subdir", "api.example.net_key.pem", "Baihu.example.net_cert.pem", "zoo.pem"}
	for i, w := range want {
		if items[i].Name != w {
			t.Fatalf("排序结果不符: got %v, want %v",
				func() []string {
					out := []string{}
					for _, x := range items {
						out = append(out, x.Name)
					}
					return out
				}(), want)
		}
	}
}

// 远程主机「负责域名」过滤：规则命中的所有文件不再全推给规则选中的每台主机，
// 只推文件名域名属于该主机负责域名的文件（用户报告：某域名的文件被推到无关主机）。
func TestHostWantsFile(t *testing.T) {
	h := RemoteHost{ID: "h1", Domains: []string{"*.PYWORKER.example.net", "other.example.net"}}
	files := []string{
		"panel.pyworker.example.net_cert.pem", // 子域 → 推
		"panel.pyworker.example.net_key.pem",  // 子域 → 推
		"pyworker.example.net_cert.pem",       // 等于负责域名（通配前缀剥掉）→ 推
		"baihu.loveli.example.net_cert.pem",   // 无关域名 → 不推
		"ticket12.key",                        // 无域名语义 → 不推
	}
	got := filesForHost(h, files)
	want := []string{"panel.pyworker.example.net_cert.pem", "panel.pyworker.example.net_key.pem", "pyworker.example.net_cert.pem"}
	if len(got) != len(want) {
		t.Fatalf("应命中 %v，got=%v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("应命中 %v，got=%v", want, got)
		}
	}

	// 未配置负责域名：保持旧行为全推（向后兼容）。
	all := filesForHost(RemoteHost{ID: "h2"}, files)
	if len(all) != len(files) {
		t.Fatalf("未配置负责域名时应全推，got=%v", all)
	}

	// 多主机选择修复：pushAllRemotes 只推第一台的 bug 由 onlyHostID 任一匹配修复，
	// 此处验证 normalizeHostDomains 清理行为。
	n := normalizeHostDomains([]string{" *.A.example.com ", "*.a.example.com", "", "B.example.com"})
	if len(n) != 2 || n[0] != "a.example.com" || n[1] != "b.example.com" {
		t.Fatalf("负责域名清理异常: %v", n)
	}
}

// 生成测试用证书 PEM：带指定 CN 与 SAN（只用 RFC 占位域名）。
func testCertPEM(t *testing.T, cn string, sans ...string) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     sans,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// 用户场景：目标机器上的证书文件名与内容域名不一致（如 xxx_cert.pem），
// 文件内容里的证书 CN 是面板签发的其它域名（文件名与域名不一致）。
// 按内容对比必须命中，配套私钥按同前缀继承；文件名的「无关域名」不应造成漏标。
func TestMatchRemoteCertsByContent(t *testing.T) {
	all := []CertInfo{
		certInfoFor("wild.example.net", "wild.example.net", []string{"wild.example.net", "*.wild.example.net"}),
		certInfoFor("host.example.net", "host.example.net", []string{"host.example.net"}),
	}
	// 目标证书：CN=panel.wild.example.net（被 *.wild.example.net 覆盖），文件名与之无关。
	certData := testCertPEM(t, "panel.wild.example.net", "panel.wild.example.net")
	names := []string{
		"dockge.pythonscript.duckdns.example_cert.pem",
		"dockge.pythonscript.duckdns.example_key.pem",
		"unrelated.example.net_cert.pem",
	}
	contents := map[string][]byte{
		"dockge.pythonscript.duckdns.example_cert.pem": certData,
		"unrelated.example.net_cert.pem":               testCertPEM(t, "other.example.org", "other.example.org"),
	}
	got := matchRemoteCerts(names, contents, all)
	m, ok := got["dockge.pythonscript.duckdns.example_cert.pem"]
	if !ok || m.Source != "wild.example.net" || m.Domain != "panel.wild.example.net" {
		t.Fatalf("内容匹配应命中 wild 证书（CN=panel.wild.example.net），got=%v", got)
	}
	km, ok := got["dockge.pythonscript.duckdns.example_key.pem"]
	if !ok || km.Source != "wild.example.net" || km.Kind != "key" {
		t.Fatalf("私钥应按同前缀继承证书匹配结果，got=%v", got)
	}
	if _, ok := got["unrelated.example.net_cert.pem"]; ok {
		t.Fatalf("内容不匹配的证书不应被标注，got=%v", got)
	}
}

// 精确归属优先在内容匹配里同样生效：子域已有独立证书时，泛域证书不按内容抢写。
func TestMatchRemoteCertsExactClaimByContent(t *testing.T) {
	all := []CertInfo{
		certInfoFor("wild.example.net", "wild.example.net", []string{"wild.example.net", "*.wild.example.net"}),
		certInfoFor("host.wild.example.net", "host.wild.example.net", []string{"host.wild.example.net"}),
	}
	data := testCertPEM(t, "host.wild.example.net", "host.wild.example.net")
	got := matchRemoteCerts([]string{"target_cert.pem"}, map[string][]byte{"target_cert.pem": data}, all)
	if m, ok := got["target_cert.pem"]; !ok || m.Source != "host.wild.example.net" {
		t.Fatalf("内容匹配应优先精确证书而非泛域，got=%v", m)
	}
}

func TestRemoteCertDomains(t *testing.T) {
	data := testCertPEM(t, "panel.wild.example.net", "panel.wild.example.net", "*.wild.example.net")
	got := remoteCertDomains(data)
	want := []string{"panel.wild.example.net"}
	if len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("域名解析异常: got=%v want=%v", got, want)
	}
	if d := remoteCertDomains([]byte("not a pem")); len(d) != 0 {
		t.Fatalf("非 PEM 内容不应解析出域名: %v", d)
	}
}
