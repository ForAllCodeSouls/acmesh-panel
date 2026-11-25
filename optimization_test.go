package main

import (
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestEventForJobFailedActions(t *testing.T) {
	for _, kind := range []string{"revoke", "remove", "install"} {
		got := eventForJob(&Job{Kind: kind, Status: "failed"})
		if got != "action_failed" {
			t.Fatalf("%s failed 事件 = %q，期望 action_failed", kind, got)
		}
		got = eventForJob(&Job{Kind: kind, Status: "success"})
		if got == "action_failed" || got == "" {
			t.Fatalf("%s success 事件异常: %q", kind, got)
		}
	}
	if eventForJob(&Job{Kind: "issue", Status: "skipped"}) != "" {
		t.Fatal("skipped 任务不应推送通知")
	}
}

func TestSafeURLBlocksPrivateTargets(t *testing.T) {
	t.Setenv("ACME_PANEL_ALLOW_LOCAL_WEBHOOK", "")
	for _, raw := range []string{
		"http://127.0.0.1:8080/hook",
		"http://169.254.169.254/latest/meta-data/",
		"http://10.0.0.1/hook",
		"file:///etc/passwd",
	} {
		if _, err := safeURL(raw); err == nil {
			t.Fatalf("危险 Webhook 地址未被拒绝: %s", raw)
		}
	}
	if _, err := safeURL("https://8.8.8.8/hook"); err != nil {
		t.Fatalf("公网 Webhook 被误拒: %v", err)
	}
	t.Setenv("ACME_PANEL_ALLOW_LOCAL_WEBHOOK", "1")
	if _, err := safeURL("http://127.0.0.1:18080/hook"); err != nil {
		t.Fatalf("测试模式应允许本地 Webhook: %v", err)
	}
}

func TestGotifyQueryWithExistingParams(t *testing.T) {
	// 直接用函数验证 token 追加到已有 query，而不是拼出 ?a=1?token=x
	u, err := safeURL("https://8.8.8.8/gotify?foo=1")
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("token", "SECRET")
	u.RawQuery = q.Encode()
	if got := u.String(); got != "https://8.8.8.8/gotify?foo=1&token=SECRET" {
		t.Fatalf("Gotify URL 拼接错误: %s", got)
	}
}

func TestClientIPTrustHops(t *testing.T) {
	old := trustedProxyHops
	defer func() { trustedProxyHops = old }()
	trustedProxyHops = 1
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Forwarded-For", "203.0.113.7, 10.0.0.1")
	if got := clientIP(r, true); got != "10.0.0.1" {
		t.Fatalf("应取最右侧可信地址（左侧可伪造）: %s", got)
	}
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8, 10.0.0.1")
	if got := clientIP(r, true); got != "10.0.0.1" {
		t.Fatalf("多跳代理取错地址: %s", got)
	}
	if got := clientIP(r, false); got == "1.2.3.4" {
		t.Fatal("非信任代理模式不应读取 XFF")
	}
}

func TestSyncFileKindPrecise(t *testing.T) {
	cases := map[string]string{
		"example.com_key.pem":        "key",
		"example.com_fullchain.pem":  "cert",
		"example.com_chain.pem":      "chain",
		"ca.cer":                     "chain",
		"caddy.example.com_cert.pem": "cert",
		"ca-cert-site.pem":           "cert",
	}
	for name, want := range cases {
		if got := syncFileKind(name); got != want {
			t.Fatalf("syncFileKind(%q) = %q，期望 %q", name, got, want)
		}
	}
}

func TestParseSyncDirsAbsolute(t *testing.T) {
	dirs := parseSyncDirs("./certs, /tmp/acme,./certs")
	if len(dirs) != 2 {
		t.Fatalf("期望去重后 2 个目录，实际 %v", dirs)
	}
	for _, d := range dirs {
		if !filepath.IsAbs(d) {
			t.Fatalf("同步目录未转成绝对路径: %s", d)
		}
	}
}
