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

func TestSameOriginPortMismatch(t *testing.T) {
	// nginx 反代：Host 无端口，浏览器 Origin 带端口 —— 必须判为同源
	r := httptest.NewRequest("POST", "/api/login", nil)
	r.Host = "example.com"
	r.Header.Set("Origin", "http://example.com:8800")
	if !sameOrigin(r) {
		t.Fatal("Host 无端口 + Origin 带端口应判为同源（反代场景）")
	}

	// 直连带端口：两边都带端口也同源
	r = httptest.NewRequest("POST", "/api/login", nil)
	r.Host = "example.com:8800"
	r.Header.Set("Origin", "http://example.com:8800")
	if !sameOrigin(r) {
		t.Fatal("Host 与 Origin 同端口应判为同源")
	}

	// https 反代 + https Origin
	r = httptest.NewRequest("POST", "/api/login", nil)
	r.Host = "example.com"
	r.Header.Set("Origin", "https://example.com")
	if !sameOrigin(r) {
		t.Fatal("https 反代应判为同源")
	}

	// 真正跨站必须拒绝
	r = httptest.NewRequest("POST", "/api/login", nil)
	r.Host = "example.com"
	r.Header.Set("Origin", "http://evil.example.net:8800")
	if sameOrigin(r) {
		t.Fatal("不同主机名应判为跨站")
	}

	// Referer 路径同样忽略端口
	r = httptest.NewRequest("POST", "/api/login", nil)
	r.Host = "example.com"
	r.Header.Set("Referer", "http://example.com:8800/login")
	if !sameOrigin(r) {
		t.Fatal("Referer 端口差异应判为同源")
	}

	// 无 Origin 无 Referer（curl）保持放行
	r = httptest.NewRequest("POST", "/api/login", nil)
	r.Host = "example.com"
	if !sameOrigin(r) {
		t.Fatal("无 Origin/Referer 的非浏览器客户端应放行")
	}
}
