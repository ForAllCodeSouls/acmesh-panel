package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ARI（ACME Renewal Information，RFC 9773）只是一次「未认证 GET」：
// 目录里的 renewalInfo 是基础 URL，证书标识由 AKI keyIdentifier 与序列号拼成。
// 返回的建议窗口仅供展示与提示，不自动改变续期调度；不支持的 CA 会降级为空结果。

type ARIWindow struct {
	Start          time.Time `json:"start"`
	End            time.Time `json:"end"`
	ExplanationURL string    `json:"explanation_url,omitempty"`
}

type ariDirCache struct {
	base    string
	fetched time.Time
}

type ariCertCache struct {
	window    ARIWindow
	nextCheck time.Time
}

type ARIService struct {
	mu     sync.Mutex
	dirs   map[string]ariDirCache
	certs  map[string]ariCertCache
	client *http.Client
}

func NewARIService() *ARIService {
	return &ARIService{
		dirs:   map[string]ariDirCache{},
		certs:  map[string]ariCertCache{},
		client: &http.Client{Timeout: 8 * time.Second},
	}
}

// ariCACode 把证书 conf 里的 Le_API（可能是 URL）归一到 caDirectoryURL 的键。
// 无法识别时回退到面板默认 CA，由调用方传入 effectiveCA() 的结果。
func ariCACode(ca, fallback string) string {
	v := strings.ToLower(strings.TrimSpace(ca))
	if _, ok := caDirectoryURL[v]; ok {
		return v
	}
	if strings.Contains(v, "staging") {
		return "letsencrypt_test"
	}
	for _, code := range []string{"zerossl", "buypass", "google", "letsencrypt"} {
		if strings.Contains(v, code) {
			return code
		}
	}
	if _, ok := caDirectoryURL[fallback]; ok {
		return fallback
	}
	return "letsencrypt"
}

// ariCertID 按 RFC 9773 生成 base64url(AKI) + "." + base64url(serial DER content)。
func ariCertID(pemText string) (string, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return "", errors.New("证书 PEM 无法解析")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", errors.New("证书解析失败")
	}
	if len(cert.AuthorityKeyId) == 0 {
		return "", errors.New("证书缺少 Authority Key Identifier，CA 可能不支持 ARI")
	}
	serial := cert.SerialNumber.Bytes()
	if len(serial) == 0 {
		return "", errors.New("证书序列号为空")
	}
	// DER INTEGER 的正数内容八位组：最高位为 1 时需要补 0x00。
	if serial[0]&0x80 != 0 {
		serial = append([]byte{0}, serial...)
	}
	return base64.RawURLEncoding.EncodeToString(cert.AuthorityKeyId) + "." +
		base64.RawURLEncoding.EncodeToString(serial), nil
}

// ariSafeURL 防止被目录响应指回内网；面板自身只访问固定 CA 目录。
func ariSafeURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.User != nil || u.Scheme != "https" {
		return "", errors.New("ARI 地址必须是合法的 https URL")
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return "", errors.New("ARI 地址不允许指向内网")
		}
		return u.String(), nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(context.Background(), host)
	if err != nil || len(addrs) == 0 {
		return "", errors.New("ARI 地址无法解析")
	}
	for _, a := range addrs {
		ip := a.IP
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return "", errors.New("ARI 地址不允许指向内网")
		}
	}
	return u.String(), nil
}

// renewalInfoBase 读取并缓存 CA 目录里的 renewalInfo 基础地址。
func (a *ARIService) renewalInfoBase(ctx context.Context, ca string) (string, error) {
	a.mu.Lock()
	if c, ok := a.dirs[ca]; ok && time.Since(c.fetched) < 12*time.Hour {
		a.mu.Unlock()
		return c.base, nil
	}
	a.mu.Unlock()

	dirURL, ok := caDirectoryURL[ca]
	if !ok {
		return "", errors.New("未知的 CA")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dirURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("读取 CA 目录失败: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("CA 目录返回 HTTP %d", resp.StatusCode)
	}
	var dir struct {
		RenewalInfo string `json:"renewalInfo"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&dir); err != nil {
		return "", errors.New("CA 目录 JSON 解析失败")
	}
	if dir.RenewalInfo == "" {
		return "", errors.New("该 CA 未提供 renewalInfo（不支持 ARI）")
	}
	base, err := ariSafeURL(dir.RenewalInfo)
	if err != nil {
		return "", err
	}
	a.mu.Lock()
	a.dirs[ca] = ariDirCache{base: base, fetched: time.Now()}
	a.mu.Unlock()
	return base, nil
}

// Query 返回某张证书的 CA 建议窗口。cached=true 表示命中本地缓存，未重新请求 CA。
func (a *ARIService) Query(ctx context.Context, ca, certID string) (ARIWindow, bool, error) {
	key := ca + "|" + certID
	a.mu.Lock()
	if c, ok := a.certs[key]; ok && time.Now().Before(c.nextCheck) {
		a.mu.Unlock()
		return c.window, true, nil
	}
	a.mu.Unlock()

	base, err := a.renewalInfoBase(ctx, ca)
	if err != nil {
		return ARIWindow{}, false, err
	}
	endpoint := strings.TrimSuffix(base, "/") + "/" + certID
	if _, err := ariSafeURL(endpoint); err != nil {
		return ARIWindow{}, false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ARIWindow{}, false, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		return ARIWindow{}, false, fmt.Errorf("查询续期建议失败: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return ARIWindow{}, false, errors.New("CA 没有这张证书的续期建议")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ARIWindow{}, false, fmt.Errorf("CA 返回 HTTP %d", resp.StatusCode)
	}
	var info struct {
		SuggestedWindow struct {
			Start string `json:"start"`
			End   string `json:"end"`
		} `json:"suggestedWindow"`
		ExplanationURL string `json:"explanationURL"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&info); err != nil {
		return ARIWindow{}, false, errors.New("续期建议 JSON 解析失败")
	}
	start, err := time.Parse(time.RFC3339, info.SuggestedWindow.Start)
	if err != nil {
		return ARIWindow{}, false, errors.New("续期建议缺少合法 start")
	}
	end, err := time.Parse(time.RFC3339, info.SuggestedWindow.End)
	if err != nil || !end.After(start) {
		return ARIWindow{}, false, errors.New("续期建议的窗口无效")
	}
	window := ARIWindow{Start: start, End: end, ExplanationURL: info.ExplanationURL}
	next := time.Now().Add(6 * time.Hour)
	if raw := resp.Header.Get("Retry-After"); raw != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil && n > 0 {
			if n < 60 {
				n = 60
			}
			if n > 24*3600 {
				n = 24 * 3600
			}
			next = time.Now().Add(time.Duration(n) * time.Second)
		} else if t, err := http.ParseTime(raw); err == nil {
			d := time.Until(t)
			if d < time.Minute {
				d = time.Minute
			}
			if d > 24*time.Hour {
				d = 24 * time.Hour
			}
			next = time.Now().Add(d)
		}
	}
	a.mu.Lock()
	a.certs[key] = ariCertCache{window: window, nextCheck: next}
	a.mu.Unlock()
	return window, false, nil
}

// handleARI 给到期看板提供建议窗口；逐张证书查询，单张失败不影响其它证书。
// 已过期的证书按 RFC 9773 不再查询。
func (s *Server) handleARI(w http.ResponseWriter, r *http.Request) {
	certs, err := s.certs.Scan()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取证书失败: "+err.Error())
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	fallback := s.effectiveCA()
	items := make([]map[string]any, 0, len(certs))
	for _, c := range certs {
		if name != "" && c.Name != name {
			continue
		}
		item := map[string]any{"name": c.Name, "domain": c.Domain, "supported": false}
		if time.Now().After(c.NotAfter) {
			item["error"] = "证书已过期，不再查询 ARI"
			items = append(items, item)
			continue
		}
		pemText, e := s.certs.ReadPEM(c.Name, "fullchain")
		if e != nil {
			pemText, e = s.certs.ReadPEM(c.Name, "cert")
		}
		if e != nil {
			item["error"] = "证书文件不可读"
			items = append(items, item)
			continue
		}
		certID, e := ariCertID(pemText)
		if e != nil {
			item["error"] = e.Error()
			items = append(items, item)
			continue
		}
		item["cert_id"] = certID
		window, cached, e := s.ari.Query(r.Context(), ariCACode(c.CA, fallback), certID)
		if e != nil {
			item["error"] = e.Error()
			items = append(items, item)
			continue
		}
		now := time.Now()
		item["supported"] = true
		item["cached"] = cached
		item["start"] = window.Start
		item["end"] = window.End
		if window.ExplanationURL != "" {
			item["explanation_url"] = window.ExplanationURL
		}
		switch {
		case now.Before(window.Start):
			item["phase"] = "early"
		case now.After(window.End):
			item["phase"] = "late"
		default:
			item["phase"] = "window"
		}
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "now": time.Now()})
}
