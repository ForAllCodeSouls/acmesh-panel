package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNoHSTSHeader(t *testing.T) {
	// 面板固定 HTTP，HSTS 交给反代；即使请求带了 X-Forwarded-Proto 也不下发。
	for _, xfp := range []string{"", "https", "http, https"} {
		r := httptest.NewRequest(http.MethodGet, "/api/session", nil)
		if xfp != "" {
			r.Header.Set("X-Forwarded-Proto", xfp)
		}
		w := httptest.NewRecorder()
		(&Server{}).securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(w, r)
		if got := w.Header().Get("Strict-Transport-Security"); got != "" {
			t.Fatalf("XFP=%q 时面板不应下发 HSTS，得到 %q", xfp, got)
		}
	}
}

func TestSessionCookieHTTPFriendly(t *testing.T) {
	w := httptest.NewRecorder()
	s := &Server{}
	s.setCookie(w, "sid", false)
	raw := w.Header().Get("Set-Cookie")
	if raw == "" {
		t.Fatal("登录响应应写入会话 Cookie")
	}
	if strings.Contains(strings.ToLower(raw), "secure") {
		t.Fatalf("面板只提供 HTTP，Cookie 不应带 Secure：%s", raw)
	}
	if strings.Contains(strings.ToLower(raw), "samesite") {
		t.Fatalf("Cookie 应为普通 Cookie，不显式写 SameSite：%s", raw)
	}
	if !strings.Contains(raw, "HttpOnly") || !strings.Contains(raw, "Path=/") {
		t.Fatalf("Cookie 缺少 HttpOnly/Path：%s", raw)
	}
}
