package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHSTSOnlyOnHTTPS(t *testing.T) {
	serve := func(r *http.Request) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		(&Server{}).securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(w, r)
		return w
	}

	// 纯 HTTP（含未透传 XFP 的反代）不下发，避免把 HTTP 站点锁死一年。
	for _, tc := range []struct {
		name string
		xfp  string
	}{
		{"无 XFP", ""},
		{"XFP=http", "http"},
		{"XFP=https, http（最右为 http）", "https, http"},
	} {
		r := httptest.NewRequest(http.MethodGet, "/api/session", nil)
		if tc.xfp != "" {
			r.Header.Set("X-Forwarded-Proto", tc.xfp)
		}
		if got := serve(r).Header().Get("Strict-Transport-Security"); got != "" {
			t.Fatalf("%s 不应下发 HSTS，得到 %q", tc.name, got)
		}
	}

	// 确认 HTTPS 时下发。
	for _, tc := range []struct {
		name   string
		xfp    string
		origin string
	}{
		{"XFP=https", "https", ""},
		{"XFP=http, https（最右 https）", "http, https", ""},
		{"XFP=https + https Origin", "https", "https://example.com"},
	} {
		r := httptest.NewRequest(http.MethodGet, "/api/session", nil)
		r.Header.Set("X-Forwarded-Proto", tc.xfp)
		if tc.origin != "" {
			r.Header.Set("Origin", tc.origin)
		}
		got := serve(r).Header().Get("Strict-Transport-Security")
		if !strings.Contains(got, "max-age=31536000") {
			t.Fatalf("%s 应下发 HSTS，得到 %q", tc.name, got)
		}
	}

	// 反代误配 XFP=https 但浏览器明确来自 http：不视为 HTTPS。
	r := httptest.NewRequest(http.MethodGet, "/api/session", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("Origin", "http://example.com")
	if got := serve(r).Header().Get("Strict-Transport-Security"); got != "" {
		t.Fatalf("浏览器明确 http 来源时不应下发 HSTS，得到 %q", got)
	}
}

func TestSessionCookieSmartSecure(t *testing.T) {
	set := func(r *http.Request) string {
		w := httptest.NewRecorder()
		(&Server{}).setCookie(w, r, "sid", false)
		return w.Header().Get("Set-Cookie")
	}

	// 纯 HTTP：普通 Cookie，HTTP 直连可登录。
	httpRaw := set(httptest.NewRequest(http.MethodPost, "/api/login", nil))
	if strings.Contains(strings.ToLower(httpRaw), "secure") {
		t.Fatalf("HTTP 下 Cookie 不应带 Secure：%s", httpRaw)
	}
	if strings.Contains(strings.ToLower(httpRaw), "samesite") {
		t.Fatalf("HTTP 下 Cookie 不应显式写 SameSite：%s", httpRaw)
	}
	if !strings.Contains(httpRaw, "HttpOnly") || !strings.Contains(httpRaw, "Path=/") {
		t.Fatalf("Cookie 缺少 HttpOnly/Path：%s", httpRaw)
	}

	// 确认 HTTPS：带 Secure + SameSite=Lax，加固且不影响 HTTPS 登录。
	r := httptest.NewRequest(http.MethodPost, "/api/login", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	httpsRaw := set(r)
	if !strings.Contains(httpsRaw, "Secure") || !strings.Contains(httpsRaw, "SameSite=Lax") {
		t.Fatalf("HTTPS 下 Cookie 应带 Secure + SameSite=Lax：%s", httpsRaw)
	}

	// 浏览器明确 http 来源：即使 XFP 误配也不加 Secure。
	r2 := httptest.NewRequest(http.MethodPost, "/api/login", nil)
	r2.Header.Set("X-Forwarded-Proto", "https")
	r2.Header.Set("Origin", "http://example.com")
	if got := set(r2); strings.Contains(got, "Secure") {
		t.Fatalf("http 来源不应带 Secure：%s", got)
	}
}
