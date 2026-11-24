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
	ID       string
	User     string
	CSRF     string
	Created  time.Time
	LastSeen time.Time
	IP       string
	UA       string
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
		if now.Sub(v.LastSeen) > s.idle || now.Sub(v.Created) > s.life {
			delete(s.m, k)
		}
	}
}

// Create 生成新会话；每次登录都会新建（防会话固定攻击）。
func (s *SessionStore) Create(user, ip, ua string) *Session {
	now := time.Now()
	sess := &Session{
		ID:       randToken(32),
		User:     user,
		CSRF:     randToken(32),
		Created:  now,
		LastSeen: now,
		IP:       ip,
		UA:       ua,
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
	if now.Sub(sess.LastSeen) > s.idle || now.Sub(sess.Created) > s.life {
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

func clientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if i := strings.IndexByte(xff, ','); i > 0 {
				return strings.TrimSpace(xff[:i])
			}
			return strings.TrimSpace(xff)
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

// sameOrigin 校验 Origin/Referer 与 Host 一致，抵御跨站表单提交（登录接口的第一道闸）。
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	host := r.Host
	if origin != "" {
		origin = strings.TrimSuffix(origin, "/")
		for _, p := range []string{"http://", "https://"} {
			if strings.HasPrefix(origin, p) && strings.TrimPrefix(origin, p) == host {
				return true
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
			return rest == host
		}
	}
	return false
}

func constantTimeEq(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
