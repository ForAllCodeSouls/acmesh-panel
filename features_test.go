package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCIDRAllowlist(t *testing.T) {
	nets, err := parseCIDRList([]string{"203.0.113.0/24", "2001:db8::/32", " 192.0.2.10 "})
	if err != nil || len(nets) != 3 {
		t.Fatalf("解析失败: %v / %d", err, len(nets))
	}
	if !ipAllowed("203.0.113.42", []string{"203.0.113.0/24"}, false) {
		t.Fatal("网段内 IP 应放行")
	}
	if ipAllowed("198.51.100.7", []string{"203.0.113.0/24"}, false) {
		t.Fatal("网段外 IP 应拒绝")
	}
	if !ipAllowed("127.0.0.1", []string{"203.0.113.0/24"}, true) {
		t.Fatal("本地回环豁免应放行")
	}
	if ipAllowed("127.0.0.1", []string{"203.0.113.0/24"}, false) {
		t.Fatal("关闭豁免后回环应拒绝")
	}
	if ipAllowed("203.0.113.1", []string{"not-a-cidr"}, true) {
		t.Fatal("非法配置应保守拒绝")
	}
	if !ipAllowed("10.0.0.1", nil, false) {
		t.Fatal("空白名单应不限制")
	}
}

func TestAPITokenLifecycle(t *testing.T) {
	tok, plain := newAPIToken("monitor", []string{"certs", "overview"})
	if !strings.HasPrefix(plain, apiTokenPrefix) {
		t.Fatal("明文令牌缺少前缀")
	}
	if !tokenMatches(tok, plain) {
		t.Fatal("令牌校验失败")
	}
	if tokenMatches(tok, plain+"x") {
		t.Fatal("错误令牌不应通过")
	}
	tok.Enabled = false
	if tokenMatches(tok, plain) {
		t.Fatal("停用令牌不应通过")
	}
	tok.Enabled = true
	if !tokenScopeAllowed(tok.Scopes, "/api/certs") || !tokenScopeAllowed(tok.Scopes, "/api/overview") {
		t.Fatal("授权范围应放行")
	}
	if tokenScopeAllowed(tok.Scopes, "/api/tokens") || tokenScopeAllowed(tok.Scopes, "/api/password") {
		t.Fatal("未授权端点应拒绝")
	}
	if tokenHash(plain) == plain || len(tokenHash(plain)) != 64 {
		t.Fatal("令牌必须以 SHA-256 存储")
	}
}

func TestRedactDiff(t *testing.T) {
	in := `{"password":"SecretPass123","name":"demo","api_key":"abc","token":"xyz"}`
	out := redactDiff(in)
	for _, secret := range []string{"SecretPass123", "abc", "xyz"} {
		if strings.Contains(out, secret) {
			t.Fatalf("敏感值未被打码: %s", out)
		}
	}
	if !strings.Contains(out, `"name":"demo"`) {
		t.Fatal("非敏感字段应保留")
	}
}

func TestFeatureDefaultsAndRestore(t *testing.T) {
	st, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := st.Snapshot()
	if !s.AllowLocalBypass || s.Locale != "zh" || s.AutoBackup.Keep != 7 {
		t.Fatalf("新存储默认值异常: %+v", s)
	}
	if !s.RetryPolicy.Enabled || s.RetryPolicy.MaxAttempts != 3 {
		t.Fatalf("重试策略默认值异常: %+v", s.RetryPolicy)
	}

	in := State{Locale: "xx", AutoBackup: AutoBackupConfig{Interval: "monthly", Keep: 999, Hour: 99},
		RetryPolicy: RetryPolicy{MaxAttempts: 99, BaseDelay: 0, MaxDelay: 1}}
	if err := st.Restore(in); err != nil {
		t.Fatal(err)
	}
	got := st.Snapshot()
	if got.Locale != "zh" || got.AutoBackup.Interval != "daily" || got.AutoBackup.Keep != 50 || got.AutoBackup.Hour != 23 {
		t.Fatalf("恢复未裁剪: %+v", got)
	}
	if got.RetryPolicy.MaxAttempts != 10 || got.RetryPolicy.BaseDelay != 5 || got.RetryPolicy.MaxDelay < got.RetryPolicy.BaseDelay {
		t.Fatalf("恢复重试策略未裁剪: %+v", got.RetryPolicy)
	}
}

func TestFeatureRecordTables(t *testing.T) {
	st, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.AddConfigDiff("admin", "127.0.0.1", "token_create", "安全", "", "secret=***")
	st.AddConfigDiff("admin", "127.0.0.1", "ip_allowlist_save", "安全", "", "203.0.113.0/24")
	items, total, err := st.QueryConfigDiffs("", "安全", 10, 0)
	if err != nil || total != 2 || len(items) != 2 {
		t.Fatalf("Diff 查询异常: total=%d len=%d err=%v", total, len(items), err)
	}
	if items[0].Action != "ip_allowlist_save" {
		t.Fatal("未按时间倒序")
	}
	filtered, total, _ := st.QueryConfigDiffs("token_create", "", 10, 0)
	if total != 1 || filtered[0].Category != "安全" {
		t.Fatal("动作筛选失败")
	}
	if len(st.ConfigDiffActions()) != 2 || len(st.ConfigDiffCategories()) != 1 {
		t.Fatal("筛选项提取失败")
	}

	st.AddHealthReport(HealthReport{TS: time.Now(), Overall: "ok", Checks: []HealthCheck{{Name: "acme.sh", Status: "ok"}}})
	hist := st.RecentHealthReports(5)
	if len(hist) != 1 || hist[0].Overall != "ok" {
		t.Fatalf("健康快照异常: %+v", hist)
	}

	id := st.AddBackupRecord(BackupRecord{TS: time.Now(), Name: "backup-test.json", Size: 10, Kind: "manual", Status: "ok"})
	list := st.ListBackups(10)
	if id == 0 || len(list) != 1 || list[0].Name != "backup-test.json" {
		t.Fatalf("备份记录异常: %+v", list)
	}
	if !st.DeleteBackupRecord(id) || len(st.ListBackups(10)) != 0 {
		t.Fatal("删除备份记录失败")
	}
}

func TestRetrySchedulerBackoff(t *testing.T) {
	st, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	mgr := NewJobManager(nil, st, 1)
	rs := NewRetryScheduler(mgr, func() RetryPolicy {
		return RetryPolicy{Enabled: true, MaxAttempts: 4, BaseDelay: 3600, MaxDelay: 7200}
	})
	defer rs.Close()
	if !rs.Schedule("job-1", 0, "timeout") {
		t.Fatal("首次失败应排入重试")
	}
	q := rs.Snapshot()
	if len(q) != 1 || q[0].Attempt != 1 {
		t.Fatalf("重试队列异常: %+v", q)
	}
	if !q[0].NextAt.After(time.Now().Add(50 * time.Minute)) {
		t.Fatal("退避延迟过短")
	}
	if !rs.Schedule("job-2", 1, "still failing") || rs.Snapshot()[1].Attempt != 2 {
		t.Fatal("第二次重试未排入")
	}
	if rs.Schedule("job-1", 0, "duplicate") {
		t.Fatal("同一任务不应重复排入")
	}
	rs.Cancel("job-1")
	if len(rs.Snapshot()) != 1 {
		t.Fatal("取消失败")
	}
}

func TestNextRunAt(t *testing.T) {
	if got := nextRunAt(false, 3, 0, "daily"); got != "已停用" {
		t.Fatalf("停用文案异常: %s", got)
	}
	if got := nextRunAt(true, 3, 0, "daily"); !strings.Contains(got, "03:00") {
		t.Fatalf("下次执行时间异常: %s", got)
	}
}

func TestScanACMEAccounts(t *testing.T) {
	dir := t.TempDir()
	body := "ACME_EMAIL=admin@example.net\nDEFAULT_ACME_SERVER=https://acme-v02.api.letsencrypt.org/directory\n"
	if err := os.WriteFile(filepath.Join(dir, "account.conf"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	accounts := scanACMEAccounts(dir, "letsencrypt")
	if len(accounts) != 1 || accounts[0].Email != "admin@example.net" || !accounts[0].Default {
		t.Fatalf("账户解析异常: %+v", accounts)
	}
	if accounts[0].KeyFingerprint == "" {
		t.Fatal("缺少账户指纹")
	}
}

func TestCertKeyMatch(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example.net"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := certKeyMatch(cert, keyPEM); err != nil {
		t.Fatalf("匹配私钥校验失败: %v", err)
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	badPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(other)})
	if err := certKeyMatch(cert, badPEM); err == nil {
		t.Fatal("不匹配私钥应报错")
	}
	if err := certKeyMatch(cert, []byte("not pem")); err == nil {
		t.Fatal("非法 PEM 应报错")
	}
}

func TestParseAllCerts(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "a.example.net"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	one := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	chain := append(append([]byte{}, one...), one...)
	certs, bad, err := parseAllCerts(chain)
	if err != nil || len(certs) != 2 || bad != 0 {
		t.Fatalf("解析证书链失败: %d bad=%d %v", len(certs), bad, err)
	}
	if _, err := parseFirstCert(chain); err != nil {
		t.Fatal(fmt.Sprintf("解析 leaf 失败: %v", err))
	}
	// DER 损坏的中间证书必须被计数，而不是静默跳过。
	broken := append(append([]byte{}, one...),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not-der")})...)
	certs, bad, err = parseAllCerts(broken)
	if err != nil || len(certs) != 1 || bad != 1 {
		t.Fatalf("损坏证书未被记录: %d bad=%d %v", len(certs), bad, err)
	}
	// 非证书类型的 PEM 块不应被计为坏证书。
	withKey := append(append([]byte{}, one...),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("placeholder")})...)
	certs, bad, err = parseAllCerts(withKey)
	if err != nil || len(certs) != 1 || bad != 0 {
		t.Fatalf("非证书块被误判: %d bad=%d %v", len(certs), bad, err)
	}
}
