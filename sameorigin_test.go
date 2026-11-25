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

func TestSameOriginAllowsReverseProxy(t *testing.T) {
	// 合法场景必须放行：按主机名比较、忽略端口与协议，兼容反代改写 Host。
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
		{"example.com", "", "http://example.com:8800/login", ""},
		{"example.com", "", "", ""}, // curl 等非浏览器客户端
		// 反代把 Host 改成内网地址且未传 XFH：无法得知公网主机名，跳过比对。
		{"127.0.0.1:8080", "https://example.com", "", ""},
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
			t.Fatalf("合法请求不应被拦截 Host=%q Origin=%q XFH=%q", tc.host, tc.origin, tc.xfh)
		}
	}
}

func TestSameOriginBlocksCrossSite(t *testing.T) {
	// 公网 Host 已知时，跨站来源必须拒绝。
	r := httptest.NewRequest("POST", "/api/login", nil)
	r.Host = "example.com"
	r.Header.Set("Origin", "https://evil.example.net")
	if sameOrigin(r) {
		t.Fatal("公网 Host + 跨站 Origin 应拒绝")
	}

	// Host 是内网地址但 XFH 指示真实公网域名时，同样拒绝跨站。
	r = httptest.NewRequest("POST", "/api/login", nil)
	r.Host = "127.0.0.1:8080"
	r.Header.Set("X-Forwarded-Host", "example.com")
	r.Header.Set("Origin", "http://evil.example.net:8800")
	if sameOrigin(r) {
		t.Fatal("XFH 已知公网域名 + 跨站 Origin 应拒绝")
	}

	// Referer 也参与校验。
	r = httptest.NewRequest("POST", "/api/renew-all", nil)
	r.Host = "example.com"
	r.Header.Set("Referer", "https://evil.example.net/page")
	if sameOrigin(r) {
		t.Fatal("公网 Host + 跨站 Referer 应拒绝")
	}
}
