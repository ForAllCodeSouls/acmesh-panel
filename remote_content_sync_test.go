package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// makePanelCert 构造一个 acme.sh 风格的面板证书目录。
func makePanelCert(t *testing.T, home, dirName, domain string, sans []string) {
	t.Helper()
	dir := filepath.Join(home, dirName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	certPEM := testCertPEM(t, domain, sans...)
	for name, data := range map[string][]byte{
		domain + ".conf": []byte("Le_API='letsencrypt'\n"),
		domain + ".cer":  certPEM,
		"fullchain.cer":  certPEM,
		domain + ".key":  []byte("PANEL-PRIVATE-KEY-NEW"),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// 复现用户场景：目标机器上的证书文件名是 dockge.<source-domain>_cert.pem，
// 文件内容里的 CN/SAN 才是面板签发域名；配套私钥必须一起标注并同步。
// 这里用真实 SSH + SFTP server 走完整 read -> match -> push 流程。
func TestRemoteContentSyncCertAndKey(t *testing.T) {
	for _, tc := range []struct {
		name        string
		panelSANs   []string
		oldCertCN   string
		oldCertSANs []string
		keySuffix   string
	}{
		{
			name: "exact-CN-file-name-differs", panelSANs: []string{"pyworker.example.net"},
			oldCertCN: "pyworker.example.net", oldCertSANs: []string{"pyworker.example.net"},
			keySuffix: "_key",
		},
		{
			name: "wildcard-SAN-covers-target", panelSANs: []string{"pyworker.example.net", "*.pyworker.example.net"},
			oldCertCN: "dockge.pyworker.example.net", oldCertSANs: []string{"dockge.pyworker.example.net"},
			keySuffix: "_key",
		},
		{
			// 目标证书内容只有通配 SAN（acme.sh 泛域证书常见形态），旧代码直接丢弃 -> 匹配不上。
			name: "target-cert-only-wildcard-SAN", panelSANs: []string{"pyworker.example.net", "*.pyworker.example.net"},
			oldCertCN: "*.pyworker.example.net", oldCertSANs: []string{"*.pyworker.example.net"},
			keySuffix: "_key",
		},
		{
			// 私钥命名变体：.key.pem 也应与同前缀证书配对。
			name: "key-name-variant-dot-key", panelSANs: []string{"pyworker.example.net", "*.pyworker.example.net"},
			oldCertCN: "dockge.pyworker.example.net", oldCertSANs: []string{"dockge.pyworker.example.net"},
			keySuffix: ".key",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			port, stop := startSFTPTestServer(t, "TestPass123!")
			defer stop()
			home := t.TempDir()
			makePanelCert(t, home, "pyworker.example.net_ecc", "pyworker.example.net", tc.panelSANs)
			certs := NewCertScanner(home)

			remoteDir := t.TempDir()
			oldCert := testCertPEM(t, tc.oldCertCN, tc.oldCertSANs...)
			certName := "dockge.pyworker.example.net_cert.pem"
			keyName := "dockge.pyworker.example.net" + tc.keySuffix + ".pem"
			for n, content := range map[string][]byte{
				certName: oldCert,
				keyName:  []byte("OLD-KEY"),
			} {
				if err := os.WriteFile(filepath.Join(remoteDir, n), content, 0o644); err != nil {
					t.Fatal(err)
				}
			}

			store := &Store{dir: t.TempDir()}
			h := RemoteHost{
				Name: "pyworker", Host: "127.0.0.1", Port: port, User: "deploy",
				RemoteDir: remoteDir, Password: "TestPass123!", Enabled: true,
			}

			contents, err := readRemoteCertFiles(store, h, []string{certName, keyName})
			if err != nil {
				t.Fatalf("读取远程证书失败: %v", err)
			}
			all, err := certs.Scan()
			if err != nil {
				t.Fatal(err)
			}
			matches := matchRemoteCerts([]string{certName, keyName}, contents, all)
			if len(matches) != 2 {
				t.Fatalf("证书与私钥都应匹配，got=%v (contents=%d)", matches, len(contents))
			}
			evs, skipped := pushMatchedToRemote(store, certs, h, matches, true, certName, keyName)
			if skipped != 0 || len(evs) != 2 {
				t.Fatalf("应同步 2 个文件（证书+私钥），got events=%d skipped=%d evs=%v", len(evs), skipped, evs)
			}
			certOut, err := os.ReadFile(filepath.Join(remoteDir, certName))
			if err != nil || !strings.Contains(string(certOut), "BEGIN CERTIFICATE") {
				t.Fatalf("证书未被新内容覆盖: %q err=%v", certOut, err)
			}
			keyOut, err := os.ReadFile(filepath.Join(remoteDir, keyName))
			if err != nil || string(keyOut) != "PANEL-PRIVATE-KEY-NEW" {
				t.Fatalf("私钥未被新内容覆盖: %q err=%v", keyOut, err)
			}
		})
	}
}

// 目标机器只有证书文件、没有配套私钥时，同步应补写 <域名>_key.pem。
func TestRemoteContentSyncCreatesMissingKey(t *testing.T) {
	port, stop := startSFTPTestServer(t, "TestPass123!")
	defer stop()
	home := t.TempDir()
	makePanelCert(t, home, "wild.example.net_ecc", "wild.example.net", []string{"wild.example.net", "*.wild.example.net"})
	certs := NewCertScanner(home)

	remoteDir := t.TempDir()
	certName := "app.wild.example.net_cert.pem"
	if err := os.WriteFile(filepath.Join(remoteDir, certName),
		testCertPEM(t, "app.wild.example.net", "app.wild.example.net"), 0o644); err != nil {
		t.Fatal(err)
	}
	store := &Store{dir: t.TempDir()}
	h := RemoteHost{
		Name: "wild", Host: "127.0.0.1", Port: port, User: "deploy",
		RemoteDir: remoteDir, Password: "TestPass123!", Enabled: true,
	}
	contents, err := readRemoteCertFiles(store, h, []string{certName})
	if err != nil {
		t.Fatal(err)
	}
	all, _ := certs.Scan()
	matches := matchRemoteCerts([]string{certName}, contents, all)
	evs, _ := pushMatchedToRemote(store, certs, h, matches, true, certName)
	if len(evs) != 2 {
		t.Fatalf("应同步证书 + 补建私钥，got=%v", evs)
	}
	keyOut, err := os.ReadFile(filepath.Join(remoteDir, "app.wild.example.net_key.pem"))
	if err != nil || string(keyOut) != "PANEL-PRIVATE-KEY-NEW" {
		t.Fatalf("缺失私钥未补写: %q err=%v", keyOut, err)
	}
}

// 面板证书没有私钥时，必须在同步记录里看到失败原因，而不是静默只同步证书。
func TestRemoteContentSyncReportsMissingPanelKey(t *testing.T) {
	port, stop := startSFTPTestServer(t, "TestPass123!")
	defer stop()
	home := t.TempDir()
	makePanelCert(t, home, "host.example.net_ecc", "host.example.net", []string{"host.example.net"})
	certs := NewCertScanner(home)
	// 删掉面板私钥：模拟「证书有、私钥缺」的部署。
	if err := os.Remove(filepath.Join(home, "host.example.net_ecc", "host.example.net.key")); err != nil {
		t.Fatal(err)
	}

	remoteDir := t.TempDir()
	names := []string{"host.example.net_cert.pem", "host.example.net_key.pem"}
	for _, n := range names {
		content := []byte("OLD")
		if strings.Contains(n, "_cert") {
			content = testCertPEM(t, "host.example.net", "host.example.net")
		}
		if err := os.WriteFile(filepath.Join(remoteDir, n), content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	store := &Store{dir: t.TempDir()}
	h := RemoteHost{
		Name: "host", Host: "127.0.0.1", Port: port, User: "deploy",
		RemoteDir: remoteDir, Password: "TestPass123!", Enabled: true,
	}
	contents, err := readRemoteCertFiles(store, h, names)
	if err != nil {
		t.Fatal(err)
	}
	all, _ := certs.Scan()
	matches := matchRemoteCerts(names, contents, all)
	evs, _ := pushMatchedToRemote(store, certs, h, matches, true, names...)
	failures := 0
	for _, ev := range evs {
		if ev.Result == "fail" && strings.Contains(ev.Detail, "私钥读取失败") {
			failures++
		}
	}
	if failures == 0 {
		t.Fatalf("面板缺私钥应产生可见失败记录，got=%v", evs)
	}
}

// 用户场景：主机名称 pyworker.example.net 只是备注，不能当域名参与匹配；
// 目标目录里 119 字节的无关文件（哪怕文件名看着像域名）也不能被标成证书。
// 只有内容确实是面板签发证书的文件才会命中，私钥按前缀继承。
func TestRemoteMatchUsesContentOnlyNotHostNameOrFilename(t *testing.T) {
	home := t.TempDir()
	makePanelCert(t, home, "real.example.net_ecc", "real.example.net", []string{"real.example.net"})
	certs := NewCertScanner(home)
	all, err := certs.Scan()
	if err != nil {
		t.Fatal(err)
	}

	names := []string{
		"wildcard.example.net",       // 119 字节无关文件，名字像域名
		"bogus.example.net_cert.pem", // 主机名里的 example.net 不能当域名
		"renamed-file_cert.pem",      // 文件名与内容域名不一致，内容命中
		"renamed-file_key.pem",       // 私钥按前缀继承
	}
	contents := map[string][]byte{
		"wildcard.example.net":       []byte("AUTO_CERT_RENEW=1\n"),
		"bogus.example.net_cert.pem": []byte("not a certificate"),
		// 内容才是 real.example.net 的证书；文件名故意完全无关。
		"renamed-file_cert.pem": testCertPEM(t, "real.example.net", "real.example.net"),
	}
	matches := matchRemoteCerts(names, contents, all)
	if len(matches) != 2 {
		t.Fatalf("只应命中内容匹配的证书与配套私钥，got=%v", matches)
	}
	for _, junk := range []string{"wildcard.example.net", "bogus.example.net_cert.pem"} {
		if _, ok := matches[junk]; ok {
			t.Fatalf("无关文件不得被标注: %s -> %v", junk, matches[junk])
		}
	}
	m, ok := matches["renamed-file_cert.pem"]
	if !ok || m.Source != "real.example.net_ecc" || m.Domain != "real.example.net" || m.Kind != "cert" {
		t.Fatalf("内容匹配的证书应命中，got=%v", matches)
	}
	km, ok := matches["renamed-file_key.pem"]
	if !ok || km.Source != "real.example.net_ecc" || km.Kind != "key" {
		t.Fatalf("私钥应按前缀继承，got=%v", matches)
	}
}

// 主机名称写成域名样式（pyworker.example.net）也不得影响负责域名过滤：
// 只有真实证书内容域名匹配时才同步，名字只是备注。
func TestHostNameNotUsedForDomainFilter(t *testing.T) {
	h := RemoteHost{Name: "pyworker.example.net", Domains: []string{"real.example.net"}}
	if hostWantsDomain(h, "other.example.net") {
		t.Fatal("主机名里的 example.net 不得成为负责域名")
	}
	if !hostWantsDomain(h, "real.example.net") || !hostWantsDomain(h, "sub.real.example.net") {
		t.Fatal("负责域名应按证书内容域名精确/子域判定")
	}
}
