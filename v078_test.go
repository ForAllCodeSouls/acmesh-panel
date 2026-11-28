package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestNormalizeChallengeAlias(t *testing.T) {
	cases := map[string]string{
		"  Alias.Example.NET.  ":            "alias.example.net",
		"_acme-challenge.alias.example.net": "alias.example.net",
		"":                                  "",
	}
	for in, want := range cases {
		got, err := normalizeChallengeAlias(in)
		if err != nil || got != want {
			t.Fatalf("normalizeChallengeAlias(%q)=%q,%v want %q", in, got, err, want)
		}
	}
	if _, err := normalizeChallengeAlias("bad host!"); err == nil {
		t.Fatal("非法委托域名应被拒绝")
	}
}

func TestBuildIssueArgsChallengeAlias(t *testing.T) {
	args := buildIssueArgs("dns_cf", 30, "", "ec-256", "letsencrypt", false,
		[]string{"a.example.net", "b.example.net"}, "alias.example.net")
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-d a.example.net --challenge-alias alias.example.net -d b.example.net") {
		t.Fatalf("--challenge-alias 必须紧跟首个 -d：%s", joined)
	}
	args = buildIssueArgs("dns_cf", 0, "", "", "letsencrypt", false, []string{"a.example.net"}, "")
	if strings.Contains(strings.Join(args, " "), "challenge-alias") {
		t.Fatal("留空时不应带委托参数")
	}
}

func TestARICertID(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	aki := []byte{0x69, 0x88, 0x5b, 0x6b, 0x87, 0x46, 0x40, 0x41}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(0x87654321),
		Subject:               pkix.Name{CommonName: "ari.example.net"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		AuthorityKeyId:        aki,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pemText := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	id, err := ariCertID(pemText)
	if err != nil {
		t.Fatal(err)
	}
	want := base64.RawURLEncoding.EncodeToString(aki) + "." + base64.RawURLEncoding.EncodeToString([]byte{0x00, 0x87, 0x65, 0x43, 0x21})
	if id != want {
		t.Fatalf("ariCertID=%q want %q", id, want)
	}
}

func TestNotifyFailureQueue(t *testing.T) {
	st, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	n := Notifier{ID: "n1", Name: "测试渠道", Kind: "generic", Events: []string{"issue_failed"}, Enabled: true}
	msg := NotifyMessage{Title: "签发失败", Event: "issue_failed", Time: time.Now().Format(time.RFC3339)}
	st.AddNotifyFailure(n, msg, errString("第一次失败"))
	st.AddNotifyFailure(n, msg, errString("第二次失败"))
	if got := st.CountNotifyFailures(); got != 1 {
		t.Fatalf("同类失败应去重，得到 %d 条", got)
	}
	list := st.ListNotifyFailures(10)
	if len(list) != 1 || list[0].Attempts != 2 || !strings.Contains(list[0].LastError, "第二次") {
		t.Fatalf("失败记录未正确更新: %+v", list)
	}
	st.UpdateNotifyFailure(list[0].ID, 5, time.Now().Add(-time.Hour), "已耗尽", "exhausted")
	if len(st.DueNotifyFailures(time.Now(), 10)) != 0 {
		t.Fatal("耗尽记录不应进入自动重试队列")
	}
	if !st.DeleteNotifyFailure(list[0].ID) || st.CountNotifyFailures() != 0 {
		t.Fatal("删除失败记录失败")
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func TestGenericHMACHeaders(t *testing.T) {
	body := []byte(`{"title":"test"}`)
	h := genericHMACHeaders("secret", "1700000000", body)
	mac := hmac.New(sha256.New, []byte("secret"))
	_, _ = mac.Write([]byte("1700000000." + string(body)))
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if h["X-ACMESH-Panel-Signature"] != want || h["X-ACMESH-Panel-Timestamp"] != "1700000000" {
		t.Fatalf("HMAC 头不符: %+v", h)
	}
	if reflect.ValueOf(h).Len() != 3 {
		t.Fatalf("签名头数量异常: %+v", h)
	}
}

func TestAuditExportAppliesFilter(t *testing.T) {
	st, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.Audit("admin", "203.0.113.10", "login_ok", "登录成功")
	st.Audit("admin", "203.0.113.10", "password_change", "修改密码")
	all := st.AuditExport(AuditFilter{})
	if len(all) != 2 {
		t.Fatalf("导出全部应含 2 条，得到 %d", len(all))
	}
	filtered := st.AuditExport(AuditFilter{Action: "password_change"})
	if len(filtered) != 1 || filtered[0]["action"] != "password_change" {
		t.Fatalf("导出未应用筛选: %+v", filtered)
	}
}

func TestCertImportHandler(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(filepath.Join(dir, "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "import.example.net"},
		DNSNames:              []string{"import.example.net"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	body, _ := json.Marshal(certImportReq{CertPEM: certPEM, KeyPEM: keyPEM})
	s := &Server{cfg: Config{AcmeHome: filepath.Join(dir, "acme"), DefaultCA: "letsencrypt"}, store: st,
		certs: NewCertScanner(filepath.Join(dir, "acme"))}
	if err := os.MkdirAll(s.cfg.AcmeHome, 0o700); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/certs/import", bytes.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), sessKey, &Session{User: "tester"}))
	w := httptest.NewRecorder()
	s.handleCertImport(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("导入失败: %d %s", w.Code, w.Body.String())
	}
	keyPath := filepath.Join(s.cfg.AcmeHome, "import.example.net", "import.example.net.key")
	fi, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	// Windows/NTFS 不保留 POSIX 权限位，权限断言只在类 Unix 上有效。
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("私钥权限应为 0600，得到 %v", fi.Mode().Perm())
	}
	certs, err := s.certs.Scan()
	if err != nil || len(certs) != 1 || certs[0].Domain != "import.example.net" {
		t.Fatalf("导入后扫描异常: %+v %v", certs, err)
	}
}
