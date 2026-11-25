package main

import (
	"encoding/pem"
	"strings"
	"testing"
)

// 本地内容模式与远程内容对比必须对同一份证书得出相同结论。
func TestLocalAndRemoteContentMatchAgree(t *testing.T) {
	all := []CertInfo{
		certInfoFor("host.example.net", "host.example.net", []string{"host.example.net"}),
		certInfoFor("wild.example.net", "wild.example.net", []string{"wild.example.net", "*.wild.example.net"}),
	}
	rule := SyncRule{ID: "r1", Name: "内容", Enabled: true, Mode: syncSAN, Source: "*"}

	cases := []struct {
		name    string
		content []byte
		want    string // 期望归属证书；空表示不应命中
	}{
		{
			name:    "file-name-differs-from-content",
			content: testCertPEM(t, "host.example.net", "host.example.net"),
			want:    "host.example.net",
		},
		{
			name:    "wildcard-covers-one-level",
			content: testCertPEM(t, "app.wild.example.net", "app.wild.example.net"),
			want:    "wild.example.net",
		},
		{
			name:    "content-not-signed-by-panel",
			content: testCertPEM(t, "nope.example.org", "nope.example.org"),
			want:    "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// 文件名故意用与内容无关的域名，验证以内容为准。
			name := "unrelated-name_cert.pem"
			local := matchTarget(rule, all[0], name, certFileDomain(name), tc.content, nil) ||
				matchTarget(rule, all[1], name, certFileDomain(name), tc.content, nil)
			remote := matchRemoteCerts([]string{name}, map[string][]byte{name: tc.content}, all)
			if (tc.want == "") != (!local) {
				t.Fatalf("本地内容模式判定不符: want=%q local=%v", tc.want, local)
			}
			var remoteSource string
			for _, m := range remote {
				remoteSource = m.Source
			}
			if remoteSource != tc.want {
				t.Fatalf("远程内容判定不符: want=%q got=%q (%v)", tc.want, remoteSource, remote)
			}
		})
	}
}

// 内容可解析但不匹配时，不得再按文件名兜底放行（旧实现会误覆盖）。
func TestContentModeDoesNotFallBackToFileNameWhenReadable(t *testing.T) {
	all := []CertInfo{certInfoFor("host.example.net", "host.example.net", []string{"host.example.net"})}
	rule := SyncRule{ID: "r1", Name: "内容", Enabled: true, Mode: syncSAN, Source: "*"}
	e := &SyncEngine{}
	name := "host.example.net_cert.pem"
	content := testCertPEM(t, "other.example.org", "other.example.org")
	if matchTarget(rule, all[0], name, certFileDomain(name), content, nil) {
		t.Fatal("证书内容明确不匹配时不应按文件名放行")
	}
	// 内容读不出来（私钥、空文件）时仍按文件名域名兜底。
	if !e.matchName(rule, all[0], name, certFileDomain(name), nil) {
		t.Fatal("内容不可读时应按文件名域名兜底")
	}
}

// fullchain 里叶子证书可能在第二块，必须解析所有证书块。
func TestParseCertDomainsReadsAllChainBlocks(t *testing.T) {
	leaf := testCertPEM(t, "host.example.net", "host.example.net")
	ca := testCertPEM(t, "Example Root CA", "root.example.org")
	chain := append(ca, leaf...)
	got := parseCertDomains(chain)
	want := "host.example.net"
	found := false
	for _, d := range got {
		if d == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("fullchain 第二块的叶子证书域名未解析到: %v", got)
	}
	if len(got) < 2 {
		t.Fatalf("应解析出多块证书的域名: %v", got)
	}
	// 私钥 PEM 不含证书块，返回空。
	if d := parseCertDomains([]byte("-----BEGIN PRIVATE KEY-----\nAAA\n-----END PRIVATE KEY-----\n")); len(d) != 0 {
		t.Fatalf("私钥不应解析出域名: %v", d)
	}
	// 确认测试夹具本身是合法 PEM（防止用例假通过）。
	if block, _ := pem.Decode(leaf); block == nil || !strings.Contains(block.Type, "CERTIFICATE") {
		t.Fatal("测试夹具不是证书 PEM")
	}
}

// 匹配强度判定：精确主域 > 精确 SAN > 通配一级 > 不匹配。
func TestCertMatchScorePriority(t *testing.T) {
	ci := certInfoFor("base.example.net", "base.example.net",
		[]string{"base.example.net", "exact.example.net", "*.base.example.net"})
	cases := map[string]int{
		"base.example.net":     3,
		"exact.example.net":    2,
		"sub.base.example.net": 1,
		"nope.example.net":     0,
		"a.b.base.example.net": 0, // 通配只覆盖一级
		"example.net":          0, // 父域名不算
	}
	for domain, want := range cases {
		if got := certMatchScore(domain, ci); got != want {
			t.Fatalf("certMatchScore(%q)=%d, want %d", domain, got, want)
		}
	}
}

// 远程内容匹配也必须遵守精确归属优先：文件名域名已有独立证书时，
// 即使文件内容是泛域证书，也不能由泛域证书抢写。
func TestRemoteContentRespectsExactClaim(t *testing.T) {
	all := []CertInfo{
		certInfoFor("wild.example.net", "wild.example.net", []string{"wild.example.net", "*.wild.example.net"}),
		certInfoFor("host.wild.example.net", "host.wild.example.net", []string{"host.wild.example.net"}),
	}
	name := "host.wild.example.net_cert.pem"
	// 文件内容故意是一张泛域证书（只有 *.wild.example.net）。
	content := testCertPEM(t, "*.wild.example.net", "*.wild.example.net")
	got := matchRemoteCerts([]string{name}, map[string][]byte{name: content}, all)
	if m, ok := got[name]; !ok || m.Source != "host.wild.example.net" {
		t.Fatalf("文件名域名已有独立证书时应由它认领，got=%v", got)
	}
}
