package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net"
	"net/http"
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

// requestIsHTTPS 判断到客户端的这一段连接是否为 HTTPS。
// 只有确认是 HTTPS 才允许下发 HSTS——否则纯 HTTP 访问也会被浏览器永久升级，
// 配错一次就把自己锁死一年。
// 直连 TLS：r.TLS 非空；反代终结 TLS：仅在信任代理时按可信跳数取 X-Forwarded-Proto。
func requestIsHTTPS(r *http.Request, trustProxy bool) bool {
	if r.TLS != nil {
		return true
	}
	if !trustProxy {
		return false
	}
	xfp := r.Header.Get("X-Forwarded-Proto")
	if xfp == "" {
		return false
	}
	parts := strings.Split(xfp, ",")
	// 与 clientIP 一致：从右侧可信跳取值，客户端可伪造左侧条目。
	idx := len(parts) - trustedProxyHops
	if idx < 0 || idx >= len(parts) {
		idx = 0
	}
	return strings.EqualFold(strings.TrimSpace(parts[idx]), "https")
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

// sameOrigin 校验 Origin/Referer 与目标主机一致，抵御跨站表单提交（登录接口的第一道闸）。
// 比较按「主机名」进行，忽略端口差异，兼容 nginx 反代把 Host 去掉端口的场景。
func sameOrigin(r *http.Request) bool {
	want := hostNoPort(r.Host)
	origin := r.Header.Get("Origin")
	if origin != "" {
		origin = strings.TrimSuffix(origin, "/")
		for _, p := range []string{"http://", "https://"} {
			if strings.HasPrefix(origin, p) {
				return hostNoPort(strings.TrimPrefix(origin, p)) == want
			}
		}
		return false
	}
	// 没有 Origin 时看 Referer（部分浏览器同源 POST 不带 Origin）
	ref := r.Header.Get("Referer")
	if ref == "" {
		return true // 非浏览器客户端（curl 等）自行通过 CSRF token 防护
	}
	for _, p := range []string{"http://", "https://"} {
		if strings.HasPrefix(ref, p) {
			rest := strings.TrimPrefix(ref, p)
			if i := strings.IndexByte(rest, '/'); i >= 0 {
				rest = rest[:i]
			}
			return hostNoPort(rest) == want
		}
	}
	return false
}

func constantTimeEq(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
