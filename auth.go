package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const sessionCookie = "acmesh_sid"

func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand 不可用: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

type Session struct {
	ID        string
	User      string
	CSRF      string
	Created   time.Time
	LastSeen  time.Time
	IP        string
	UA        string
	LongLived bool // "保持登录"：空闲 30 天、最长 90 天
}

func (s *SessionStore) idleFor(v *Session) time.Duration {
	if v.LongLived {
		return 30 * 24 * time.Hour
	}
	return s.idle
}

func (s *SessionStore) lifeFor(v *Session) time.Duration {
	if v.LongLived {
		return 90 * 24 * time.Hour
	}
	return s.life
}

type SessionStore struct {
	mu   sync.Mutex
	m    map[string]*Session
	idle time.Duration
	life time.Duration
}

func NewSessionStore(idle, life time.Duration) *SessionStore {
	s := &SessionStore{m: map[string]*Session{}, idle: idle, life: life}
	go func() {
		t := time.NewTicker(5 * time.Minute)
		for range t.C {
			s.gc()
		}
	}()
	return s
}

func (s *SessionStore) gc() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.m {
		if now.Sub(v.LastSeen) > s.idleFor(v) || now.Sub(v.Created) > s.lifeFor(v) {
			delete(s.m, k)
		}
	}
}

// Create 生成新会话；每次登录都会新建（防会话固定攻击）。
func (s *SessionStore) Create(user, ip, ua string, longLived bool) *Session {
	now := time.Now()
	sess := &Session{
		ID:        randToken(32),
		User:      user,
		CSRF:      randToken(32),
		Created:   now,
		LastSeen:  now,
		IP:        ip,
		UA:        ua,
		LongLived: longLived,
	}
	s.mu.Lock()
	s.m[sess.ID] = sess
	s.mu.Unlock()
	return sess
}

func (s *SessionStore) Get(id string) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.m[id]
	if !ok {
		return nil
	}
	now := time.Now()
	if now.Sub(sess.LastSeen) > s.idleFor(sess) || now.Sub(sess.Created) > s.lifeFor(sess) {
		delete(s.m, id)
		return nil
	}
	sess.LastSeen = now
	return sess
}

func (s *SessionStore) Delete(id string) {
	s.mu.Lock()
	delete(s.m, id)
	s.mu.Unlock()
}

// DeleteUser 在改密码后注销该用户的所有其它会话。
func (s *SessionStore) DeleteUserExcept(user, keepID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k, v := range s.m {
		if v.User == user && k != keepID {
			delete(s.m, k)
			n++
		}
	}
	return n
}

// ---- 登录失败限流（按来源 IP + 用户名的指数退避锁定）----

type attempt struct {
	fails    int
	lockTill time.Time
	last     time.Time
}

type Limiter struct {
	mu sync.Mutex
	m  map[string]*attempt
}

func NewLimiter() *Limiter {
	l := &Limiter{m: map[string]*attempt{}}
	go func() {
		t := time.NewTicker(10 * time.Minute)
		for range t.C {
			cut := time.Now().Add(-2 * time.Hour)
			l.mu.Lock()
			for k, v := range l.m {
				if v.last.Before(cut) {
					delete(l.m, k)
				}
			}
			l.mu.Unlock()
		}
	}()
	return l
}

// Locked 返回剩余锁定时间（0 表示未锁定）。
func (l *Limiter) Locked(key string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	a, ok := l.m[key]
	if !ok {
		return 0
	}
	if d := time.Until(a.lockTill); d > 0 {
		return d
	}
	return 0
}

func (l *Limiter) Fail(key string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	a, ok := l.m[key]
	if !ok {
		a = &attempt{}
		l.m[key] = a
	}
	a.fails++
	a.last = time.Now()
	if a.fails >= 5 {
		// 5 次失败起锁：5min, 10min, 20min ... 上限 1h
		exp := a.fails - 5
		if exp > 4 {
			exp = 4
		}
		d := 5 * time.Minute << exp
		if d > time.Hour {
			d = time.Hour
		}
		a.lockTill = time.Now().Add(d)
		return d
	}
	return 0
}

func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	delete(l.m, key)
	l.mu.Unlock()
}

// ---- 请求辅助 ----

// trustedProxyHops 是可信反向代理层数，由 ACME_PANEL_TRUST_PROXY_HOPS 配置。
// X-Forwarded-For 由每层代理在右侧追加「它看到的对端 IP」，因此默认 1 层时
// 取最右侧值（代理写入的真实客户端）；链上每多一层可信代理，就向左多跳一格。
var trustedProxyHops = 1

func clientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			// 从右往左取值；客户端可伪造左侧任意条目，最右侧才是可信代理写入的对端 IP。
			if idx := len(parts) - trustedProxyHops; idx >= 0 && idx < len(parts) {
				if ip := strings.TrimSpace(parts[idx]); ip != "" {
					return ip
				}
			}
		}
		if xr := r.Header.Get("X-Real-IP"); xr != "" {
			return strings.TrimSpace(xr)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// hostNoPort 把 host 归一到「主机名」：去掉端口、统一小写、去方括号。
// nginx 反代常用 proxy_set_header Host $host（不带端口），而浏览器 Origin
// 带端口（如 http://example.com:8800）。按主机名比较才能兼容反代，否则
// 同源校验会把合法登录误判为跨站，导致「登录登不进」。
func hostNoPort(h string) string {
	h = strings.TrimSpace(h)
	// [IPv6] 或 [IPv6]:port —— 方括号内整体是主机名，不按冒号切端口。
	if strings.HasPrefix(h, "[") {
		if end := strings.IndexByte(h, ']'); end >= 0 {
			return strings.ToLower(h[1:end])
		}
	}
	if i := strings.LastIndexByte(h, ':'); i >= 0 {
		// 仅当冒号后全是数字时视为端口。
		port := h[i+1:]
		allDigit := port != ""
		for _, c := range port {
			if c < '0' || c > '9' {
				allDigit = false
				break
			}
		}
		if allDigit {
			h = h[:i]
		}
	}
	return strings.ToLower(h)
}

// originHost 从 Origin / Referer 中取出主机名；只接受 http/https，忽略端口与路径。
func originHost(v string) (string, bool) {
	v = strings.TrimSpace(v)
	for _, p := range []string{"http://", "https://"} {
		if !strings.HasPrefix(v, p) {
			continue
		}
		rest := strings.TrimPrefix(v, p)
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			rest = rest[:i]
		}
		return hostNoPort(rest), true
	}
	return "", false
}

// requestIsHTTPS 判断「到客户端这一段」是否为 HTTPS，用于决定是否给 Cookie
// 加 Secure、是否下发 HSTS。面板固定只监听 HTTP，所以主要看反代传来的
// X-Forwarded-Proto；同时用 Origin/Referer 交叉验证，避免反代误配 XFP 时
// 把纯 HTTP 的登录锁死（浏览器会明确带 http:// 来源）。
// 无需任何开关：最坏情况只是自己拿不到 Cookie，不会引入越权。
func requestIsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	xfp := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))
	if xfp == "" {
		return false
	}
	parts := strings.Split(xfp, ",")
	// 与 XFF 一致：取最右侧、最近一层代理写入的值。
	last := strings.TrimSpace(parts[len(parts)-1])
	if !strings.EqualFold(last, "https") {
		return false
	}
	if v := strings.ToLower(strings.TrimSpace(r.Header.Get("Origin"))); strings.HasPrefix(v, "http://") {
		return false
	}
	if v := strings.ToLower(strings.TrimSpace(r.Header.Get("Referer"))); strings.HasPrefix(v, "http://") {
		return false
	}
	return true
}

// forceHTTPSOverride 解析部署环境的显式覆盖。
// ok=false 表示未设置，使用面板内开关；ok=true 时 v 为强制值。
// 这是防止反代未透传 X-Forwarded-Proto 把自己锁死在 HTTP 之外的恢复入口：
// 设 ACME_PANEL_FORCE_HTTPS=0 重启即可临时关闭，无需数据库或界面访问。
func forceHTTPSOverride() (v, ok bool) {
	raw, exists := os.LookupEnv("ACME_PANEL_FORCE_HTTPS")
	if !exists || strings.TrimSpace(raw) == "" {
		return false, false
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true, true
	case "0", "false", "no", "off":
		return false, true
	default:
		return false, false
	}
}

// isInternalHost 判断主机名是否为本机/内网地址（反代把 Host 改写后的常见形态）。
func isInternalHost(h string) bool {
	switch strings.ToLower(h) {
	case "localhost", "127.0.0.1", "::1", "0.0.0.0":
		return true
	}
	ip := net.ParseIP(h)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

// sameOrigin 校验 Origin/Referer 与请求目标是否同源，按「主机名」比较，
// 忽略端口与协议差异，并兼容反代把 Host 改写成内网地址的场景。
// 候选主机名同时取 Host 与 X-Forwarded-Host（逗号列表的第一项）。
// 若反代既改写 Host 又不传 XFH，本侧无法得知公网主机名，此时跳过比对——
// 状态变更接口仍由 CSRF Token 保护，不会因为这种配置把合法登录挡在门外。
func sameOrigin(r *http.Request) bool {
	hosts := []string{}
	if h := hostNoPort(r.Host); h != "" {
		hosts = append(hosts, h)
	}
	if xfh := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); xfh != "" {
		if h := hostNoPort(strings.Split(xfh, ",")[0]); h != "" {
			hosts = append(hosts, h)
		}
	}

	check := func(v string) bool {
		h, ok := originHost(v)
		if !ok {
			return false
		}
		for _, want := range hosts {
			if want != "" && h == want {
				return true
			}
		}
		return false
	}

	value := r.Header.Get("Origin")
	if value == "" {
		value = r.Header.Get("Referer")
	}
	if value == "" {
		return true // curl 等非浏览器客户端由 CSRF Token 保护
	}
	if check(value) {
		return true
	}
	// 只有候选主机全是内网地址时才放行：说明反代隐去了公网主机名。
	// 只要有一个候选是公网域名，跨站就必须拒绝。
	allInternal := len(hosts) > 0
	for _, h := range hosts {
		if !isInternalHost(h) {
			allInternal = false
			break
		}
	}
	return allInternal
}

func constantTimeEq(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
