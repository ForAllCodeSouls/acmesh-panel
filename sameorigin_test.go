package main

import (
	"net/http/httptest"
	"testing"
)

func TestHostNoPort(t *testing.T) {
	cases := map[string]string{
		"example.com":      "example.com",
		"example.com:8800": "example.com",
		"EXAMPLE.com:8080": "example.com",
		"[::1]:8080":       "::1",
		"[::1]":            "::1",
		"127.0.0.1:18080":  "127.0.0.1",
	}
	for in, want := range cases {
		if got := hostNoPort(in); got != want {
			t.Errorf("hostNoPort(%q) = %q, 期望 %q", in, got, want)
		}
	}
}

func TestSameOriginDoesNotBlockLogin(t *testing.T) {
	// 普通面板不按 Host/Origin/Referer 拦截登录；反代把 Host 改成内网地址、
	// 浏览器带公网 https Origin 时也必须放行。状态变更仍由 CSRF Token 保护。
	cases := []struct {
		host   string
		origin string
		ref    string
		xfh    string
	}{
		{"example.com", "http://example.com:8800", "", ""},
		{"example.com:8800", "http://example.com:8800", "", ""},
		{"example.com", "https://example.com", "", ""},
		{"127.0.0.1:8080", "https://example.com", "", "example.com"},
		{"example.com", "http://evil.example.net:8800", "", ""},
		{"127.0.0.1:8080", "https://example.com", "", "example.net"},
		{"example.com", "", "http://example.com:8800/login", ""},
		{"example.com", "", "", ""},
	}
	for _, tc := range cases {
		r := httptest.NewRequest("POST", "/api/login", nil)
		r.Host = tc.host
		if tc.origin != "" {
			r.Header.Set("Origin", tc.origin)
		}
		if tc.ref != "" {
			r.Header.Set("Referer", tc.ref)
		}
		if tc.xfh != "" {
			r.Header.Set("X-Forwarded-Host", tc.xfh)
		}
		if !sameOrigin(r) {
			t.Fatalf("sameOrigin 不应再拦截 Host=%q Origin=%q", tc.host, tc.origin)
		}
	}
}
