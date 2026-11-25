package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newHTTPSTestServer(t *testing.T) (*Server, *Store) {
	t.Helper()
	st, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return &Server{store: st}, st
}

func TestForceHTTPSPersisted(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if st.ForceHTTPS() {
		t.Fatal("默认不应强制 HTTPS")
	}
	if err := st.SetForceHTTPS(true); err != nil {
		t.Fatal(err)
	}
	// 重新打开数据库仍能读到（配置持久化，重启不回退）。
	st2, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	if !st2.ForceHTTPS() {
		t.Fatal("重启后强制 HTTPS 开关丢失")
	}
	if err := st2.SetForceHTTPS(false); err != nil {
		t.Fatal(err)
	}
	if st2.ForceHTTPS() {
		t.Fatal("关闭开关未生效")
	}
}

func TestRequireHTTPSMiddleware(t *testing.T) {
	srv, st := newHTTPSTestServer(t)
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("passed"))
	})
	h := srv.requireHTTPS(ok)

	call := func(path, xfp, origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		if xfp != "" {
			r.Header.Set("X-Forwarded-Proto", xfp)
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	// 未开启：HTTP 一切正常。
	if w := call("/api/session", "", ""); w.Code != http.StatusOK {
		t.Fatalf("未开启时 HTTP 应放行，得到 %d", w.Code)
	}
	if err := st.SetForceHTTPS(true); err != nil {
		t.Fatal(err)
	}

	// 开启后 HTTP 页面与接口都被拒绝，但提示必须可执行恢复。
	w := call("/", "", "")
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "需要 HTTPS 访问") {
		t.Fatalf("HTTP 页面应返回说明页，得到 %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "ACME_PANEL_FORCE_HTTPS=0") {
		t.Fatal("拒绝页缺少恢复方式")
	}
	w = call("/api/session", "", "")
	if w.Code != http.StatusForbidden {
		t.Fatalf("HTTP API 应被拒绝，得到 %d", w.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || !strings.Contains(body["error"], "仅允许 HTTPS") {
		t.Fatalf("API 拒绝应返回可读错误，得到 %s", w.Body.String())
	}

	// 健康检查放行，避免容器因策略切换判定服务失活。
	if w := call("/api/health", "", ""); w.Code != http.StatusOK {
		t.Fatalf("健康检查应放行，得到 %d", w.Code)
	}

	// 经可信反代（XFP=https）放行；浏览器明确 http 来源时不视为 HTTPS。
	if w := call("/api/session", "https", "https://acme.example.net"); w.Code != http.StatusOK {
		t.Fatalf("HTTPS 反代请求应放行，得到 %d", w.Code)
	}
	if w := call("/api/session", "https", "http://38.76.218.20:8800"); w.Code != http.StatusForbidden {
		t.Fatalf("http 来源即使 XFP=https 也应拒绝，得到 %d", w.Code)
	}
}

func TestForceHTTPSEnvOverride(t *testing.T) {
	srv, st := newHTTPSTestServer(t)
	pass := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	h := srv.requireHTTPS(pass)
	isOK := func() bool {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/session", nil))
		return w.Code == http.StatusOK
	}

	if err := st.SetForceHTTPS(true); err != nil {
		t.Fatal(err)
	}
	// =0 是锁死后的恢复入口：覆盖界面开关，界面不可再改。
	t.Setenv("ACME_PANEL_FORCE_HTTPS", "0")
	enforced, pinned := srv.httpsOnly()
	if enforced || !pinned || !isOK() {
		t.Fatalf("=0 应强制关闭并锁定：enforced=%v pinned=%v ok=%v", enforced, pinned, isOK())
	}
	if err := st.SetForceHTTPS(false); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ACME_PANEL_FORCE_HTTPS", "1")
	enforced, pinned = srv.httpsOnly()
	if !enforced || !pinned || isOK() {
		t.Fatalf("=1 应强制开启并锁定：enforced=%v pinned=%v ok=%v", enforced, pinned, isOK())
	}
	// 无法识别的取值不生效，回落到面板内开关。
	t.Setenv("ACME_PANEL_FORCE_HTTPS", "maybe")
	enforced, pinned = srv.httpsOnly()
	if enforced || pinned {
		t.Fatalf("非法取值应回落到面板开关，得到 enforced=%v pinned=%v", enforced, pinned)
	}
}

func TestHTTPSSettingsHandlerPinned(t *testing.T) {
	srv, st := newHTTPSTestServer(t)
	t.Setenv("ACME_PANEL_FORCE_HTTPS", "1")
	r := httptest.NewRequest(http.MethodPost, "/api/https/settings", strings.NewReader(`{"force_https":false}`))
	r.Header.Set("Content-Type", "application/json")
	r = r.WithContext(context.WithValue(r.Context(), sessKey, &Session{User: "admin"}))
	w := httptest.NewRecorder()
	srv.handleHTTPSSettings(w, r)
	if w.Code != http.StatusConflict {
		t.Fatalf("环境变量锁定时应拒绝修改，得到 %d: %s", w.Code, w.Body.String())
	}
	if st.ForceHTTPS() {
		t.Fatal("被拒绝的修改不应写入数据库")
	}
}
