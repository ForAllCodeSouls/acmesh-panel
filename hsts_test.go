package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequestIsHTTPS(t *testing.T) {
	// 直连 TLS
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.TLS = &tls.ConnectionState{}
	if !requestIsHTTPS(r, false) {
		t.Fatal("直连 TLS 应判定为 HTTPS")
	}

	// 纯 HTTP
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	if requestIsHTTPS(r, false) {
		t.Fatal("纯 HTTP 不应判定为 HTTPS")
	}

	// 未信任代理时，X-Forwarded-Proto 不可信
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	if requestIsHTTPS(r, false) {
		t.Fatal("未信任代理时 XFP=https 不应判定为 HTTPS")
	}

	// 信任代理 + XFP=https
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	if !requestIsHTTPS(r, true) {
		t.Fatal("信任代理 + XFP=https 应判定为 HTTPS")
	}

	// 信任代理 + XFP=http
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-Proto", "http")
	if requestIsHTTPS(r, true) {
		t.Fatal("信任代理 + XFP=http 不应判定为 HTTPS")
	}

	// 多跳：客户端伪造左侧 https，可信代理写入右侧 http，取右侧
	oldHops := trustedProxyHops
	trustedProxyHops = 1
	defer func() { trustedProxyHops = oldHops }()
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-Proto", "https, http")
	if requestIsHTTPS(r, true) {
		t.Fatal("多跳时右侧可信值为 http，不应判定为 HTTPS")
	}
	r.Header.Set("X-Forwarded-Proto", "http, https")
	if !requestIsHTTPS(r, true) {
		t.Fatal("多跳时右侧可信值为 https，应判定为 HTTPS")
	}
}

func TestHSTSConfigDefaultAndToggle(t *testing.T) {
	t.Setenv("ACME_PANEL_HSTS", "")
	if !loadConfig().HSTS {
		t.Fatal("HSTS 默认应开启")
	}
	t.Setenv("ACME_PANEL_HSTS", "0")
	if loadConfig().HSTS {
		t.Fatal("ACME_PANEL_HSTS=0 应关闭 HSTS")
	}
	t.Setenv("ACME_PANEL_HSTS", "1")
	if !loadConfig().HSTS {
		t.Fatal("ACME_PANEL_HSTS=1 应开启 HSTS")
	}
}
