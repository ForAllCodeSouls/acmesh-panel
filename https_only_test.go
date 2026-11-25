package main

import (
	"bufio"
	"context"
	"net"
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

// silentDropWriter 记录是否发生过静默断连。httptest.ResponseRecorder 不实现
// http.Hijacker，无法直接验证「无响应」，因此用一个最小实现捕获 Hijack。
type silentDropWriter struct {
	header http.Header
	code   int
	body   strings.Builder
	closed bool
}

func (w *silentDropWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}
func (w *silentDropWriter) WriteHeader(code int) { w.code = code }
func (w *silentDropWriter) Write(b []byte) (int, error) {
	if w.code == 0 {
		w.code = http.StatusOK
	}
	return w.body.Write(b)
}
func (w *silentDropWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.closed = true
	client, server := net.Pipe()
	_ = client.Close() // 对端关闭后，net/http 不会写入任何响应
	return server, bufio.NewReadWriter(bufio.NewReader(server), bufio.NewWriter(server)), nil
}

func TestRequireHTTPSMiddleware(t *testing.T) {
	srv, st := newHTTPSTestServer(t)
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("passed"))
	})
	h := srv.requireHTTPS(ok)

	call := func(path, xfp, origin string) *silentDropWriter {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		if xfp != "" {
			r.Header.Set("X-Forwarded-Proto", xfp)
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := &silentDropWriter{}
		h.ServeHTTP(w, r)
		return w
	}

	// 未开启：HTTP 一切正常，不发生断连。
	if w := call("/api/session", "", ""); w.closed || w.code != http.StatusOK || w.body.String() != "passed" {
		t.Fatalf("未开启时 HTTP 应放行，得到 closed=%v code=%d body=%q", w.closed, w.code, w.body.String())
	}
	if err := st.SetForceHTTPS(true); err != nil {
		t.Fatal(err)
	}

	// 开启后 HTTP 页面与接口都被静默断连：没有任何响应字节，也没有说明页。
	for _, path := range []string{"/", "/api/session"} {
		w := call(path, "", "")
		if !w.closed || w.body.Len() != 0 || w.code != 0 {
			t.Fatalf("%s 应静默断连（无响应），得到 closed=%v code=%d body=%q", path, w.closed, w.code, w.body.String())
		}
	}

	// 健康检查放行，避免容器因策略切换判定服务失活。
	if w := call("/api/health", "", ""); w.closed || w.code != http.StatusOK {
		t.Fatalf("健康检查应放行，得到 closed=%v code=%d", w.closed, w.code)
	}

	// 经可信反代（XFP=https）放行；浏览器明确 http 来源时不视为 HTTPS。
	if w := call("/api/session", "https", "https://acme.example.net"); w.closed || w.code != http.StatusOK {
		t.Fatalf("HTTPS 反代请求应放行，得到 closed=%v code=%d", w.closed, w.code)
	}
	if w := call("/api/session", "https", "http://38.76.218.20:8800"); !w.closed {
		t.Fatal("http 来源即使 XFP=https 也应静默断连")
	}
}

func TestForceHTTPSEnvOverride(t *testing.T) {
	srv, st := newHTTPSTestServer(t)
	pass := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	h := srv.requireHTTPS(pass)
	isOK := func() bool {
		w := &silentDropWriter{}
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/session", nil))
		return !w.closed && w.code == http.StatusOK
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
