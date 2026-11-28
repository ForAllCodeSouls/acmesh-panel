package main

import (
	"context"
	"crypto/rand"
	"embed"
	"errors"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

//go:embed web/*
var webFS embed.FS

type Config struct {
	Listen           string
	AcmeHome         string
	AcmeBin          string
	DataDir          string
	User             string
	Password         string
	ResetCredentials bool
	TrustProxy       bool
	TrustHops        int
	Cron             bool
	DefaultCA        string
	Email            string
	Parallel         int
	SyncDirs         []string
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
		Listen:           env("ACME_PANEL_LISTEN", "0.0.0.0:8080"),
		AcmeHome:         env("ACME_HOME", "/acme.sh"),
		AcmeBin:          env("ACME_BIN", ""),
		DataDir:          env("ACME_PANEL_DATA", "/data"),
		User:             env("ACME_PANEL_USER", "admin"),
		Password:         os.Getenv("ACME_PANEL_PASSWORD"),
		ResetCredentials: envBool("ACME_PANEL_RESET_CREDENTIALS", false),
		TrustProxy:       envBool("ACME_PANEL_TRUST_PROXY", false),
		TrustHops:        parseInt(env("ACME_PANEL_TRUST_PROXY_HOPS", "1")),
		Cron:             envBool("ACME_PANEL_CRON", true),
		DefaultCA:        env("ACME_PANEL_CA", "letsencrypt"),
		Email:            env("ACME_PANEL_EMAIL", ""),
		Parallel:         parseInt(env("ACME_PANEL_PARALLEL", "2")),
		SyncDirs:         parseSyncDirs(env("ACME_PANEL_SYNC_DIR", "")),
	}
	if c.AcmeBin == "" {
		c.AcmeBin = filepath.Join(c.AcmeHome, "acme.sh")
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
	retry  *RetryScheduler
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

	// 账号密码：env 只在「首次启动」（库里还没有密码）时用于初始化，之后重启不再覆盖，
	// Web 上「修改账号 / 修改密码」的结果持久生效。
	// 忘记密码时可用 ACME_PANEL_RESET_CREDENTIALS=1 配合 env 显式重置一次（默认关闭）。
	generated := false
	var initialPwd string
	if cfg.ResetCredentials && cfg.Password != "" {
		if err := store.SetUsername(cfg.User); err != nil {
			log.Fatalf("重置登录账号失败: %v", err)
		}
		if err := store.SetPassword(cfg.Password); err != nil {
			log.Fatalf("重置登录密码失败: %v", err)
		}
		if err := store.SetCredSource("env"); err != nil {
			log.Fatalf("记录凭据来源失败: %v", err)
		}
		log.Printf("已按 ACME_PANEL_RESET_CREDENTIALS 用 env 重置登录凭据（仅本次启动执行）")
	} else if !store.HasPassword() {
		if err := store.SetUsername(cfg.User); err != nil {
			log.Fatalf("设置初始登录账号失败: %v", err)
		}
		if cfg.Password != "" {
			if err := store.SetPassword(cfg.Password); err != nil {
				log.Fatalf("设置初始登录密码失败: %v", err)
			}
			if err := store.SetCredSource("env"); err != nil {
				log.Fatalf("记录凭据来源失败: %v", err)
			}
			log.Printf("已按 ACME_PANEL_PASSWORD 初始化登录密码（仅首次启动生效）")
		} else {
			initialPwd = randPassword(16)
			generated = true
			if err := store.SetPassword(initialPwd); err != nil {
				log.Fatalf("设置初始密码失败: %v", err)
			}
			if err := store.SetCredSource("generated"); err != nil {
				log.Fatalf("记录凭据来源失败: %v", err)
			}
		}
	}
	if cfg.ResetCredentials && cfg.Password == "" {
		log.Printf("⚠ 已设置 ACME_PANEL_RESET_CREDENTIALS=1，但未配置 ACME_PANEL_PASSWORD，忽略本次重置")
	}
	// 兼容 v0.1.28 及更早版本：旧 state 没有 cred_source，按当前 env 推断一次并落盘。
	if store.CredSource() == "" {
		src := "generated"
		if cfg.Password != "" && store.CheckPassword(cfg.Password) {
			src = "env"
		}
		if err := store.SetCredSource(src); err != nil {
			log.Printf("迁移凭据来源失败: %v", err)
		}
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
	srv.retry = NewRetryScheduler(srv.jobs, func() RetryPolicy { return store.Snapshot().RetryPolicy })
	srv.jobs.retryScheduler = srv.retry
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
	handler := srv.securityHeaders(srv.requireHTTPS(srv.requireIPAllowlist(mux)))

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
	go srv.updateLoop(ctx)
	go srv.backupLoop(ctx)
	defer srv.retry.Close()

	go func() {
		enforce, pinned := srv.httpsOnly()
		banner(cfg, store.Username(), generated, initialPwd, acme.Version(ctx), store.DefaultEmail(), enforce, pinned)
		// 面板固定纯 HTTP；TLS 由用户自己的 nginx/Caddy 终结。
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
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

func banner(cfg Config, user string, generated bool, pwd, acmeVer, defaultEmail string, httpsOnly, pinned bool) {
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
	if httpsOnly {
		source := "面板设置"
		if pinned {
			source = "环境变量 ACME_PANEL_FORCE_HTTPS"
		}
		log.Printf("  HTTPS 强制 : 已开启（%s）；HTTP 直连将静默断连（同空端口），恢复用 ACME_PANEL_FORCE_HTTPS=0 并 docker compose up -d 重建容器", source)
	}
}

func orNone(s string) string {
	if s == "" {
		return "未检测到"
	}
	return s
}

func randPassword(n int) string {
	// 三类字符分别取样，保证结果一定同时含大写/小写/数字——否则约 9% 的
	// 16 位密码会缺数字，被 strongPassword 拒绝后 log.Fatalf 让首次启动崩溃。
	const uppers = "ABCDEFGHJKLMNPQRSTUVWXYZ"
	const lowers = "abcdefghijkmnopqrstuvwxyz"
	const digits = "23456789"
	const alphabet = uppers + lowers + digits
	if n < 3 {
		n = 3
	}

	// 单次拒绝采样：丢弃超出整段的字节，避免取模偏置。
	pick := func(set string) byte {
		limit := 256 - (256 % len(set))
		var raw [1]byte
		for {
			if _, err := rand.Read(raw[:]); err != nil {
				panic("crypto/rand 不可用: " + err.Error())
			}
			if int(raw[0]) < limit {
				return set[int(raw[0])%len(set)]
			}
		}
	}

	b := make([]byte, 0, n)
	b = append(b, pick(uppers), pick(lowers), pick(digits))
	for len(b) < n {
		b = append(b, pick(alphabet))
	}
	// Fisher-Yates 打乱，避免前三位固定为大写/小写/数字的可预测顺序。
	// 索引采样同样用拒绝采样，保证每个下标等概率。
	randIndex := func(m int) int {
		limit := 256 - (256 % m)
		var raw [1]byte
		for {
			if _, err := rand.Read(raw[:]); err != nil {
				panic("crypto/rand 不可用: " + err.Error())
			}
			if int(raw[0]) < limit {
				return int(raw[0]) % m
			}
		}
	}
	for i := len(b) - 1; i > 0; i-- {
		j := randIndex(i + 1)
		b[i], b[j] = b[j], b[i]
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
		// 智能恢复 HSTS：只在确认客户端这一段确为 HTTPS 时下发。
		// 纯 HTTP（含反代未透传 XFP）不下发，避免配错一次就把 HTTP 锁死一年。
		if requestIsHTTPS(r) {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		} else if r.URL.Path == "/" || strings.HasSuffix(r.URL.Path, ".html") {
			// 退出登录后浏览器不应从缓存里翻出面板页面
			h.Set("Cache-Control", "no-cache, must-revalidate")
		} else if strings.HasSuffix(r.URL.Path, ".js") || strings.HasSuffix(r.URL.Path, ".css") {
			// 前端脚本/样式必须每次取最新的，否则升级后浏览器仍跑旧版 JS，
			// 会把首屏 401 显示成旧文案「未登录」，误导排查。
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// httpsOnly 返回「仅允许 HTTPS」的生效值，以及是否被环境变量锁定。
// 环境变量优先：=1 强制开启（界面不可关），=0 强制关闭（反代未透传 XFP 时的恢复入口），
// 未设置时才使用设置页保存的值。
func (s *Server) httpsOnly() (enforced, pinned bool) {
	if v, ok := forceHTTPSOverride(); ok {
		return v, true
	}
	if s.store == nil {
		return false, false
	}
	return s.store.ForceHTTPS(), false
}

// dropConnection 静默断开连接：不写任何 HTTP 响应，直接关闭底层 TCP 连接。
// 客户端看到的效果与访问一个没有服务监听的端口一致（连接被重置 / 无响应），
// 既不暴露面板存在，也不会给出任何可供探测的指纹。
// 这是「仅允许 HTTPS」的拒绝方式：宁可看起来像空端口，也不回一个说明页。
func dropConnection(w http.ResponseWriter) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		return
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	_ = conn.Close()
}

// requireHTTPS 在开关生效时静默断连非 HTTPS 请求。
// 面板固定只监听纯 HTTP，HTTPS 由用户自己的反代终结，因此判定统一走
// requestIsHTTPS（直连 TLS 或可信反代的 X-Forwarded-Proto: https）。
// 放行 /api/health 是为了容器健康检查不因策略切换而判定服务失活；该接口
// 只返回运行状态，不含任何凭证。
func (s *Server) requireHTTPS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		enforced, _ := s.httpsOnly()
		if !enforced || requestIsHTTPS(r) || r.URL.Path == "/api/health" {
			next.ServeHTTP(w, r)
			return
		}
		dropConnection(w)
	})
}

// cronLoop 用面板内置调度替代 acme.sh 的 crontab（容器里通常没有 cron 守护进程）。
// 每天在配置的小时执行一次；执行日期记录在 state.json，重启当天不会重复检测。
func (s *Server) cronLoop(ctx context.Context) {
	// 启动时立即检查一次：若面板恰好在配置小时的最后一分钟重启，等下一次 tick
	// 就跨过窗口了；立即执行可以补偿当天检测。
	s.maybeRunDaily()
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
// 用「当前小时 >= 配置小时」而非精确相等：即使 tick 延迟或启动时已过窗口，
// 当天仍能补跑一次（lastDay 保证同一天不会重复）。
func (s *Server) maybeRunDaily() {
	hour, lastDay := s.store.CronSchedule()
	now := time.Now()
	if now.Hour() < hour {
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

	// 需要登录
	mux.HandleFunc("POST /api/logout", s.requireAuth(s.handleLogout))
	mux.HandleFunc("GET /api/session", s.requireAuth(s.handleSession))
	mux.HandleFunc("GET /api/update/check", s.requireAuth(s.handleUpdateCheck))
	mux.HandleFunc("POST /api/update/check", s.requireAuth(s.handleUpdateCheck))
	mux.HandleFunc("POST /api/update/settings", s.requireAuth(s.handleUpdateSettings))
	mux.HandleFunc("GET /api/storage", s.requireRead(s.handleStorage))
	mux.HandleFunc("GET /api/overview", s.requireRead(s.handleOverview))
	mux.HandleFunc("GET /api/certs", s.requireRead(s.handleListCerts))
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
	mux.HandleFunc("GET /api/eab-creds", s.requireRead(s.handleEABCreds))
	mux.HandleFunc("POST /api/eab-creds", s.requireAuth(s.handleSaveEABCred))
	mux.HandleFunc("DELETE /api/eab-creds/{name}", s.requireAuth(s.handleDeleteEABCred))
	mux.HandleFunc("GET /api/jobs", s.requireRead(s.handleJobs))
	mux.HandleFunc("GET /api/jobs/{id}", s.requireAuth(s.handleJob))
	mux.HandleFunc("GET /api/jobs/{id}/reissue", s.requireAuth(s.handleJobReissue))
	mux.HandleFunc("GET /api/jobs/{id}/events", s.requireAuth(s.handleJobEvents))
	mux.HandleFunc("POST /api/jobs/{id}/cancel", s.requireAuth(s.handleCancelJob))
	mux.HandleFunc("POST /api/jobs/{id}/retry", s.requireAuth(s.handleRetryJob))
	mux.HandleFunc("GET /api/audit", s.requireRead(s.handleAudit))
	mux.HandleFunc("POST /api/password", s.requireAuth(s.handlePassword))
	mux.HandleFunc("POST /api/username", s.requireAuth(s.handleUsername))
	mux.HandleFunc("POST /api/cron/schedule", s.requireAuth(s.handleCronSchedule))
	mux.HandleFunc("POST /api/retention", s.requireAuth(s.handleRetention))
	mux.HandleFunc("POST /api/https/settings", s.requireAuth(s.handleHTTPSSettings))
	mux.HandleFunc("POST /api/cleanup", s.requireAuth(s.handleCleanup))
	mux.HandleFunc("GET /api/catalog", s.requireAuth(s.handleCatalog))
	mux.HandleFunc("GET /api/backup", s.requireAuth(s.handleBackupExport))
	mux.HandleFunc("POST /api/backup", s.requireAuth(s.handleBackupImport))

	// 通知渠道与按域名邮箱
	mux.HandleFunc("GET /api/notify/catalog", s.requireAuth(s.handleNotifyCatalog))
	mux.HandleFunc("GET /api/notify", s.requireAuth(s.handleNotifyList))
	mux.HandleFunc("POST /api/notify", s.requireAuth(s.handleNotifySave))
	mux.HandleFunc("DELETE /api/notify/{id}", s.requireAuth(s.handleNotifyDelete))
	mux.HandleFunc("POST /api/notify/{id}/test", s.requireAuth(s.handleNotifyTest))
	mux.HandleFunc("POST /api/notify/default-email", s.requireAuth(s.handleDefaultEmail))
	mux.HandleFunc("POST /api/certs/{name}/email", s.requireAuth(s.handleCertEmail))

	// 证书同步规则
	mux.HandleFunc("GET /api/sync/catalog", s.requireRead(s.handleSyncCatalog))
	mux.HandleFunc("GET /api/sync/rules", s.requireRead(s.handleSyncRules))
	mux.HandleFunc("POST /api/sync/rules", s.requireAuth(s.handleSyncSave))
	mux.HandleFunc("DELETE /api/sync/rules/{id}", s.requireAuth(s.handleSyncDelete))
	mux.HandleFunc("GET /api/sync/events", s.requireRead(s.handleSyncEvents))
	mux.HandleFunc("DELETE /api/sync/events", s.requireAuth(s.handleSyncClearEvents))
	mux.HandleFunc("POST /api/sync/run", s.requireAuth(s.handleSyncRun))
	mux.HandleFunc("POST /api/sync/preview", s.requireAuth(s.handleSyncPreview))

	// 远程主机证书同步
	mux.HandleFunc("GET /api/remote/hosts", s.requireRead(s.handleRemoteList))
	mux.HandleFunc("POST /api/remote/hosts", s.requireAuth(s.handleRemoteSave))
	mux.HandleFunc("DELETE /api/remote/hosts/{id}", s.requireAuth(s.handleRemoteDelete))
	mux.HandleFunc("POST /api/remote/test", s.requireAuth(s.handleRemoteTest))
	mux.HandleFunc("POST /api/remote/files", s.requireAuth(s.handleRemoteFiles))
	mux.HandleFunc("POST /api/remote/push", s.requireAuth(s.handleRemotePush))

	// v0.1.70 新增：会话管理 / IP 白名单
	mux.HandleFunc("GET /api/sessions", s.requireAuth(s.handleSessions))
	mux.HandleFunc("DELETE /api/sessions/{id}", s.requireAuth(s.handleSessionRevoke))
	mux.HandleFunc("POST /api/sessions/revoke-others", s.requireAuth(s.handleSessionsRevokeOthers))
	mux.HandleFunc("GET /api/ip-allowlist", s.requireAuth(s.handleIPAllowlist))
	mux.HandleFunc("POST /api/ip-allowlist", s.requireAuth(s.handleIPAllowlistSave))
	mux.HandleFunc("POST /api/ip-allowlist/test", s.requireAuth(s.handleIPAllowlistTest))

	// v0.1.70 新增：健康自检 / 到期看板 / 备份 / 退避重试 / 配置 Diff
	mux.HandleFunc("POST /api/health/check", s.requireAuth(s.handleHealthCheck))
	mux.HandleFunc("GET /api/health/report", s.requireRead(s.handleHealthHistory))
	mux.HandleFunc("GET /api/expiry", s.requireRead(s.handleExpiry))
	mux.HandleFunc("GET /api/backups/config", s.requireAuth(s.handleBackupSettings))
	mux.HandleFunc("POST /api/backups/config", s.requireAuth(s.handleBackupSettingsSave))
	mux.HandleFunc("GET /api/backups", s.requireAuth(s.handleBackupList))
	mux.HandleFunc("POST /api/backups/run", s.requireAuth(s.handleBackupRun))
	mux.HandleFunc("GET /api/backups/{id}/content", s.requireAuth(s.handleBackupContent))
	mux.HandleFunc("DELETE /api/backups/{id}", s.requireAuth(s.handleBackupDelete))
	mux.HandleFunc("GET /api/retry/policy", s.requireAuth(s.handleRetryPolicy))
	mux.HandleFunc("POST /api/retry/policy", s.requireAuth(s.handleRetryPolicySave))
	mux.HandleFunc("GET /api/retry/queue", s.requireAuth(s.handleRetryQueue))
	mux.HandleFunc("GET /api/config-diffs", s.requireRead(s.handleConfigDiffs))

	// v0.1.70 新增：证书生命周期
	mux.HandleFunc("POST /api/issue/batch", s.requireAuth(s.handleIssueBatch))
	mux.HandleFunc("POST /api/certs/{name}/verify", s.requireAuth(s.handleCertVerify))
	mux.HandleFunc("GET /api/acme/accounts", s.requireAuth(s.handleACMEAccounts))

	// v0.1.70 新增：只读令牌 / 计划任务 / CSV 导出 / 界面语言
	mux.HandleFunc("GET /api/tokens", s.requireAuth(s.handleTokens))
	mux.HandleFunc("POST /api/tokens", s.requireAuth(s.handleTokenCreate))
	mux.HandleFunc("DELETE /api/tokens/{id}", s.requireAuth(s.handleTokenDelete))
	mux.HandleFunc("GET /api/tokens/usage", s.requireAuth(s.handleTokenUsage))
	mux.HandleFunc("GET /api/schedules", s.requireAuth(s.handleSchedules))
	mux.HandleFunc("GET /api/export.csv", s.requireAuth(s.handleCSVExport))
	mux.HandleFunc("POST /api/locale", s.requireAuth(s.handleLocaleSave))

	// v0.1.71 新增：批量续期 / 通知静默 / ACME 账户管理增强
	mux.HandleFunc("POST /api/expiry/renew", s.requireAuth(s.handleExpiryRenewBatch))
	mux.HandleFunc("GET /api/notify/quiet", s.requireAuth(s.handleQuietHours))
	mux.HandleFunc("POST /api/notify/quiet", s.requireAuth(s.handleQuietHoursSave))
	mux.HandleFunc("POST /api/acme/accounts/default", s.requireAuth(s.handleDefaultCASet))
	mux.HandleFunc("POST /api/acme/accounts/key", s.requireAuth(s.handleACMEAccountKey))

	// 首页：把 __VER__ 换成实际版本，使 app.js/style.css 的 URL 随版本变化，
	// 绕开反代（nginx proxy_cache）对同名静态文件的旧缓存，升级后无需手动清缓存。
	mux.HandleFunc("GET /{$}", s.serveIndex)
	// 其它静态资源（内嵌，无 CDN 依赖）
	mux.Handle("/", s.static)
	return mux
}

func (s *Server) serveIndex(w http.ResponseWriter, r *http.Request) {
	body, err := webFS.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, "页面读取失败", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(strings.ReplaceAll(string(body), "__VER__", appVersion)))
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	_, err := os.Stat(s.cfg.AcmeBin)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"uptime":  int(time.Since(s.boot).Seconds()),
		"acme_ok": err == nil,
	})
}
