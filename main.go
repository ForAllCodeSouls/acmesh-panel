package main

import (
	"context"
	"embed"
	"errors"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

//go:embed web/*
var webFS embed.FS

type Config struct {
	Listen       string
	AcmeHome     string
	AcmeBin      string
	DataDir      string
	User         string
	Password     string
	CookieSecure bool
	TrustProxy   bool
	TrustHops    int
	Cron         bool
	DefaultCA    string
	Email        string
	TLSCert      string
	TLSKey       string
	Parallel     int
	SyncDirs     []string
}

func env(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		return v
	}
	return def
}

func envBool(k string, def bool) bool {
	v, ok := os.LookupEnv(k)
	if !ok || v == "" {
		return def
	}
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
}

func loadConfig() Config {
	c := Config{
		Listen:       env("ACME_PANEL_LISTEN", "0.0.0.0:8080"),
		AcmeHome:     env("ACME_HOME", "/acme.sh"),
		AcmeBin:      env("ACME_BIN", ""),
		DataDir:      env("ACME_PANEL_DATA", "/data"),
		User:         env("ACME_PANEL_USER", "admin"),
		Password:     os.Getenv("ACME_PANEL_PASSWORD"),
		CookieSecure: envBool("ACME_PANEL_COOKIE_SECURE", false),
		TrustProxy:   envBool("ACME_PANEL_TRUST_PROXY", false),
		TrustHops:    parseInt(env("ACME_PANEL_TRUST_PROXY_HOPS", "1")),
		Cron:         envBool("ACME_PANEL_CRON", true),
		DefaultCA:    env("ACME_PANEL_CA", "letsencrypt"),
		Email:        env("ACME_PANEL_EMAIL", ""),
		TLSCert:      os.Getenv("ACME_PANEL_TLS_CERT"),
		TLSKey:       os.Getenv("ACME_PANEL_TLS_KEY"),
		Parallel:     parseInt(env("ACME_PANEL_PARALLEL", "2")),
		SyncDirs:     parseSyncDirs(env("ACME_PANEL_SYNC_DIR", "")),
	}
	if c.AcmeBin == "" {
		c.AcmeBin = filepath.Join(c.AcmeHome, "acme.sh")
	}
	if c.TLSCert != "" && c.TLSKey != "" {
		c.CookieSecure = true
	}
	if _, ok := allowedCA[c.DefaultCA]; !ok {
		c.DefaultCA = "letsencrypt"
	}
	if c.TrustHops < 0 {
		c.TrustHops = 0
	}
	trustedProxyHops = c.TrustHops
	return c
}

type Server struct {
	cfg    Config
	store  *Store
	sess   *SessionStore
	limit  *Limiter
	jobs   *JobManager
	certs  *CertScanner
	acme   *ACME
	notify *NotifyEngine
	sync   *SyncEngine
	boot   time.Time
	static http.Handler
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	logRemoteInfof = log.Printf
	cfg := loadConfig()

	store, err := NewStore(cfg.DataDir)
	if err != nil {
		log.Fatalf("初始化数据目录失败: %v", err)
	}
	acme := &ACME{Home: cfg.AcmeHome, Bin: cfg.AcmeBin, Log: filepath.Join(cfg.DataDir, "acme.log")}

	// 账号初始化：环境变量优先（可找回密码）；若两者都没有，进入首次注册模式，
	// 由 Web 页面设置账号密码，不再悄悄生成随机密码打印在日志里。
	if cfg.User != "" && store.Username() == "" {
		if err := store.SetUsername(cfg.User); err != nil {
			log.Fatalf("设置用户名失败: %v", err)
		}
	}
	generated := false
	var initialPwd string
	if cfg.Password != "" {
		if !store.HasPassword() || !store.CheckPassword(cfg.Password) {
			if err := store.SetPassword(cfg.Password); err != nil {
				log.Fatalf("设置密码失败: %v", err)
			}
			log.Printf("已按 ACME_PANEL_PASSWORD 同步登录密码")
		}
	} else if !store.HasPassword() {
		log.Printf("尚未设置登录密码：请在 Web 页面完成首次注册（仅首次可用）")
	}

	// 环境变量里给了邮箱则以它为准；否则沿用 Web 界面里保存的默认邮箱。
	if cfg.Email != "" {
		if err := store.SetDefaultEmail(cfg.Email); err != nil {
			log.Printf("保存默认邮箱失败: %v", err)
		}
	}

	srv := &Server{
		cfg:    cfg,
		store:  store,
		sess:   NewSessionStore(30*time.Minute, 12*time.Hour),
		limit:  NewLimiter(),
		jobs:   NewJobManager(acme, store, cfg.Parallel),
		certs:  NewCertScanner(cfg.AcmeHome),
		acme:   acme,
		notify: NewNotifyEngine(store),
		boot:   time.Now(),
	}
	srv.sync = NewSyncEngine(store, srv.certs, srv.notify, cfg.SyncDirs)
	srv.jobs.certs = srv.certs
	srv.jobs.onDone = func(j *Job) {
		srv.notify.OnJob(j)
		// 签发/续期成功后自动同步到挂载目录。
		if j.Status == "success" && (j.Kind == "issue" || j.Kind == "renew" || j.Kind == "cron") {
			_ = srv.sync.run("任务完成: "+j.Title, false)
		}
	}
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatalf("内嵌前端资源异常: %v", err)
	}
	srv.static = http.FileServer(http.FS(sub))

	mux := srv.routes()
	handler := srv.securityHeaders(mux)

	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      0, // SSE 需要长连接
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go srv.cronLoop(ctx)

	go func() {
		banner(cfg, store.Username(), generated, initialPwd, acme.Version(ctx), store.DefaultEmail())
		var err error
		if cfg.TLSCert != "" && cfg.TLSKey != "" {
			err = httpSrv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
		} else {
			err = httpSrv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("HTTP 服务退出: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("收到退出信号，正在关闭...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	log.Println("已退出")
}

func banner(cfg Config, user string, generated bool, pwd, acmeVer, defaultEmail string) {
	log.Printf("acmesh-panel 启动")
	log.Printf("  监听       : %s", cfg.Listen)
	log.Printf("  acme.sh    : %s (%s)", cfg.AcmeBin, orNone(acmeVer))
	log.Printf("  证书目录   : %s", cfg.AcmeHome)
	log.Printf("  数据目录   : %s", cfg.DataDir)
	log.Printf("  自动续期   : %v", cfg.Cron)
	log.Printf("  默认邮箱   : %s", orNone(defaultEmail))
	log.Printf("  登录账号   : %s", user)
	if generated {
		log.Printf("  ⚠ 初始密码 : %s  （仅本次显示，请登录后立即在「设置」中修改）", pwd)
	}
}

func orNone(s string) string {
	if s == "" {
		return "未检测到"
	}
	return s
}

func randPassword(n int) string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
	b := make([]byte, n)
	// 复用 crypto/rand 的 base64 输出，再映射到无歧义字符集，避免引入额外随机源。
	raw := randToken(n*2 + 8)
	for i := 0; i < n; i++ {
		b[i] = alphabet[int(raw[i])%len(alphabet)]
	}
	return string(b)
}

// securityHeaders 统一注入安全响应头。CSP 不允许内联脚本/样式，前端全部外链。
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		if s.cfg.CookieSecure {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		} else if r.URL.Path == "/" || strings.HasSuffix(r.URL.Path, ".html") {
			// 退出登录后浏览器不应从缓存里翻出面板页面
			h.Set("Cache-Control", "no-cache, must-revalidate")
		}
		next.ServeHTTP(w, r)
	})
}

// cronLoop 用面板内置调度替代 acme.sh 的 crontab（容器里通常没有 cron 守护进程）。
// 每天在配置的小时执行一次；执行日期记录在 state.json，重启当天不会重复检测。
func (s *Server) cronLoop(ctx context.Context) {
	timer := time.NewTicker(time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			s.maybeRunDaily()
		}
	}
}

// maybeRunDaily 判断当前是否到了每日检测时间，且今天尚未执行过。
func (s *Server) maybeRunDaily() {
	hour, lastDay := s.store.CronSchedule()
	now := time.Now()
	if now.Hour() != hour {
		return
	}
	today := now.Format("2006-01-02")
	if lastDay == today {
		return
	}
	// 每天首次调度时顺带清理过期数据（保留天数可在设置页调整，0 表示不清理）
	if removed, err := s.store.Cleanup(s.store.RetentionDays()); err == nil && len(removed) > 0 {
		log.Printf("已清理过期数据: %v", removed)
	}
	if err := s.store.MarkCronRun(today); err != nil {
		log.Printf("记录自动检测日期失败: %v", err)
		return
	}
	if s.cfg.Cron {
		s.runCronOnce()
	} else {
		s.checkExpiring()
	}
	log.Printf("已执行每日自动检测（%02d:00）", hour)
}

func (s *Server) checkExpiring() {
	certs, err := s.certs.Scan()
	if err == nil {
		s.notify.CheckExpiring(certs)
	}
}

func (s *Server) runCronOnce() {
	for _, j := range s.jobs.List() {
		if j.Kind == "cron" && (j.Status == "running" || j.Status == "queued") {
			return
		}
	}
	s.jobs.StartAuto("cron", "自动续期检查", "", "acme.sh --cron", nil, []string{"--cron"})
	s.checkExpiring()
	log.Printf("已触发自动续期检查与临期提醒")
}

func (s *Server) routes() *http.ServeMux {
	mux := http.NewServeMux()

	// 公开端点
	mux.HandleFunc("GET /api/health", s.handleHealth)
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("GET /api/setup/status", s.handleSetupStatus)
	mux.HandleFunc("POST /api/setup", s.handleSetup)

	// 需要登录
	mux.HandleFunc("POST /api/logout", s.requireAuth(s.handleLogout))
	mux.HandleFunc("GET /api/session", s.requireAuth(s.handleSession))
	mux.HandleFunc("GET /api/update/check", s.requireAuth(s.handleUpdateCheck))
	mux.HandleFunc("GET /api/storage", s.requireAuth(s.handleStorage))
	mux.HandleFunc("GET /api/overview", s.requireAuth(s.handleOverview))
	mux.HandleFunc("GET /api/certs", s.requireAuth(s.handleListCerts))
	mux.HandleFunc("GET /api/certs/{name}", s.requireAuth(s.handleCertDetail))
	mux.HandleFunc("GET /api/certs/{name}/pem/{kind}", s.requireAuth(s.handleCertPEM))
	mux.HandleFunc("POST /api/certs/{name}/key", s.requireAuth(s.handleCertKey))
	mux.HandleFunc("POST /api/certs/{name}/renew", s.requireAuth(s.handleRenew))
	mux.HandleFunc("POST /api/certs/{name}/revoke", s.requireAuth(s.handleRevoke))
	mux.HandleFunc("POST /api/certs/{name}/remove", s.requireAuth(s.handleRemove))
	mux.HandleFunc("POST /api/certs/{name}/install", s.requireAuth(s.handleInstall))
	mux.HandleFunc("POST /api/issue", s.requireAuth(s.handleIssue))
	mux.HandleFunc("POST /api/renew-all", s.requireAuth(s.handleRenewAll))
	mux.HandleFunc("GET /api/providers", s.requireAuth(s.handleProviders))
	mux.HandleFunc("POST /api/providers", s.requireAuth(s.handleSaveProvider))
	mux.HandleFunc("DELETE /api/providers/{name}", s.requireAuth(s.handleDeleteProvider))
	mux.HandleFunc("GET /api/jobs", s.requireAuth(s.handleJobs))
	mux.HandleFunc("GET /api/jobs/{id}", s.requireAuth(s.handleJob))
	mux.HandleFunc("GET /api/jobs/{id}/events", s.requireAuth(s.handleJobEvents))
	mux.HandleFunc("POST /api/jobs/{id}/cancel", s.requireAuth(s.handleCancelJob))
	mux.HandleFunc("GET /api/audit", s.requireAuth(s.handleAudit))
	mux.HandleFunc("POST /api/password", s.requireAuth(s.handlePassword))
	mux.HandleFunc("POST /api/cron/schedule", s.requireAuth(s.handleCronSchedule))
	mux.HandleFunc("POST /api/retention", s.requireAuth(s.handleRetention))
	mux.HandleFunc("POST /api/cleanup", s.requireAuth(s.handleCleanup))
	mux.HandleFunc("GET /api/catalog", s.requireAuth(s.handleCatalog))

	// 通知渠道与按域名邮箱
	mux.HandleFunc("GET /api/notify/catalog", s.requireAuth(s.handleNotifyCatalog))
	mux.HandleFunc("GET /api/notify", s.requireAuth(s.handleNotifyList))
	mux.HandleFunc("POST /api/notify", s.requireAuth(s.handleNotifySave))
	mux.HandleFunc("DELETE /api/notify/{id}", s.requireAuth(s.handleNotifyDelete))
	mux.HandleFunc("POST /api/notify/{id}/test", s.requireAuth(s.handleNotifyTest))
	mux.HandleFunc("POST /api/notify/default-email", s.requireAuth(s.handleDefaultEmail))
	mux.HandleFunc("POST /api/certs/{name}/email", s.requireAuth(s.handleCertEmail))

	// 证书同步规则
	mux.HandleFunc("GET /api/sync/catalog", s.requireAuth(s.handleSyncCatalog))
	mux.HandleFunc("GET /api/sync/rules", s.requireAuth(s.handleSyncRules))
	mux.HandleFunc("POST /api/sync/rules", s.requireAuth(s.handleSyncSave))
	mux.HandleFunc("DELETE /api/sync/rules/{id}", s.requireAuth(s.handleSyncDelete))
	mux.HandleFunc("GET /api/sync/events", s.requireAuth(s.handleSyncEvents))
	mux.HandleFunc("DELETE /api/sync/events", s.requireAuth(s.handleSyncClearEvents))
	mux.HandleFunc("POST /api/sync/run", s.requireAuth(s.handleSyncRun))
	mux.HandleFunc("POST /api/sync/preview", s.requireAuth(s.handleSyncPreview))

	// 远程主机证书同步
	mux.HandleFunc("GET /api/remote/hosts", s.requireAuth(s.handleRemoteList))
	mux.HandleFunc("POST /api/remote/hosts", s.requireAuth(s.handleRemoteSave))
	mux.HandleFunc("DELETE /api/remote/hosts/{id}", s.requireAuth(s.handleRemoteDelete))
	mux.HandleFunc("POST /api/remote/test", s.requireAuth(s.handleRemoteTest))
	mux.HandleFunc("POST /api/remote/files", s.requireAuth(s.handleRemoteFiles))
	mux.HandleFunc("POST /api/remote/push", s.requireAuth(s.handleRemotePush))

	// 静态资源（内嵌，无 CDN 依赖）
	mux.Handle("/", s.static)
	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	_, err := os.Stat(s.cfg.AcmeBin)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"uptime":  int(time.Since(s.boot).Seconds()),
		"acme_ok": err == nil,
	})
}

var _ = strconv.Itoa
