package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type ctxKey int

const sessKey ctxKey = 1

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) error {
	return readJSONLimit(w, r, v, 1<<20)
}

// readJSONLimit 与 readJSON 一致，但允许调用方指定 body 上限；所有写接口都拒绝未知字段，
// 避免把 enable 写成 enabled 这类拼写错误静默变成 false。
func readJSONLimit(w http.ResponseWriter, r *http.Request, v any, limit int64) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func sess(r *http.Request) *Session {
	s, _ := r.Context().Value(sessKey).(*Session)
	return s
}

// requireAuth 是认证 + CSRF + 跨站来源校验的统一入口。
func (s *Server) requireAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "未登录")
			return
		}
		sess := s.sess.Get(c.Value)
		if sess == nil {
			s.clearCookie(w, r)
			writeErr(w, http.StatusUnauthorized, "会话已过期，请重新登录")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !sameOrigin(r) {
				s.store.Audit(sess.User, clientIP(r, s.cfg.TrustProxy), "csrf_block", r.URL.Path)
				writeErr(w, http.StatusForbidden, "跨站请求已被拒绝")
				return
			}
			if !constantTimeEq(r.Header.Get("X-CSRF-Token"), sess.CSRF) {
				s.store.Audit(sess.User, clientIP(r, s.cfg.TrustProxy), "csrf_block", r.URL.Path)
				writeErr(w, http.StatusForbidden, "CSRF 校验失败，请刷新页面后重试")
				return
			}
			if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/json") {
				writeErr(w, http.StatusUnsupportedMediaType, "请求体必须是 application/json")
				return
			}
		}
		ctx := context.WithValue(r.Context(), sessKey, sess)
		h(w, r.WithContext(ctx))
	}
}

// setCookie 写会话 Cookie。智能加固：只有确认本次访问是 HTTPS 时才加
// Secure 与 SameSite=Lax；纯 HTTP 直连仍是普通 Cookie（HttpOnly/Path/MaxAge），
// 所以 nginx HTTPS 反代和 HTTP 直连都能正常登录，无需任何开关。
func (s *Server) setCookie(w http.ResponseWriter, r *http.Request, id string, longLived bool) {
	maxAge := int(12 * time.Hour / time.Second)
	if longLived {
		maxAge = int(90 * 24 * time.Hour / time.Second)
	}
	c := &http.Cookie{
		Name:     sessionCookie,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   maxAge,
	}
	if requestIsHTTPS(r) {
		c.Secure = true
		c.SameSite = http.SameSiteLaxMode
	}
	http.SetCookie(w, c)
}

func (s *Server) clearCookie(w http.ResponseWriter, r *http.Request) {
	c := &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	}
	if requestIsHTTPS(r) {
		c.Secure = true
		c.SameSite = http.SameSiteLaxMode
	}
	http.SetCookie(w, c)
}

// ---------------- 登录 ----------------

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Remember bool   `json:"remember"`
}

// validUsername 校验账号格式（改账号与密码策略共用）。
func validUsername(u string) bool {
	if len(u) < 3 || len(u) > 32 {
		return false
	}
	for i, c := range u {
		letter := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		if !letter && !(c >= '0' && c <= '9') && c != '_' && c != '-' {
			return false
		}
		if i == 0 && !letter {
			return false
		}
	}
	return true
}

func strongPassword(p string) bool {
	if len(p) < 12 || len(p) > 200 {
		return false
	}
	var upper, lower, digit bool
	for _, c := range p {
		switch {
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= '0' && c <= '9':
			digit = true
		}
	}
	return upper && lower && digit
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		writeErr(w, http.StatusForbidden, "跨站请求已被拒绝")
		return
	}
	var req loginReq
	if err := readJSON(w, r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	ip := clientIP(r, s.cfg.TrustProxy)
	key := ip + "|" + strings.ToLower(req.Username)

	if d := s.limit.Locked(key); d > 0 {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(d.Seconds())))
		writeErr(w, http.StatusTooManyRequests, fmt.Sprintf("失败次数过多，请在 %d 秒后重试", int(d.Seconds())))
		return
	}

	okUser := s.store.CheckUsername(req.Username)
	okPass := s.store.CheckPassword(req.Password)
	if !okUser || !okPass {
		d := s.limit.Fail(key)
		s.store.Audit(req.Username, ip, "login_failed", "密码或用户名错误")
		if d > 0 {
			s.notify.Send("security_alert", "⛔ 登录失败次数过多", fmt.Sprintf(
				"来源 %s 尝试登录账号 %s 连续失败，已锁定 %d 秒。", ip, req.Username, int(d.Seconds())))
			w.Header().Set("Retry-After", fmt.Sprintf("%d", int(d.Seconds())))
			writeErr(w, http.StatusTooManyRequests, fmt.Sprintf("失败次数过多，已锁定 %d 秒", int(d.Seconds())))
			return
		}
		writeErr(w, http.StatusUnauthorized, "用户名或密码错误")
		return
	}

	s.limit.Reset(key)
	sess := s.sess.Create(s.store.Username(), ip, r.UserAgent(), req.Remember)
	s.setCookie(w, r, sess.ID, req.Remember)
	s.store.Audit(s.store.Username(), ip, "login_ok", "登录成功")
	writeJSON(w, http.StatusOK, map[string]any{
		"user": sess.User,
		"csrf": sess.CSRF,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	sess := sess(r)
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.sess.Delete(c.Value)
	}
	s.clearCookie(w, r)
	s.store.Audit(sess.User, clientIP(r, s.cfg.TrustProxy), "logout", "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// versionNewer 判断版本号 a 是否比 b 新（只比较数字段，兼容 v0.1.15 这类格式）。
func versionNewer(a, b string) bool {
	parse := func(s string) []int {
		parts := strings.Split(strings.TrimPrefix(s, "v"), ".")
		out := make([]int, len(parts))
		for i, p := range parts {
			n := 0
			for _, c := range p {
				if c < '0' || c > '9' {
					break
				}
				n = n*10 + int(c-'0')
			}
			out[i] = n
		}
		return out
	}
	x, y := parse(a), parse(b)
	for i := 0; i < len(x) || i < len(y); i++ {
		var xv, yv int
		if i < len(x) {
			xv = x[i]
		}
		if i < len(y) {
			yv = y[i]
		}
		if xv != yv {
			return xv > yv
		}
	}
	return false
}

// updateStatePayload 把持久化的检测状态转成接口响应，前端据此渲染徽标与检测时间。
func updateStatePayload(st UpdateState) map[string]any {
	return map[string]any{
		"ok":          st.LastResult == "",
		"current":     appVersion,
		"latest":      st.Latest,
		"need_update": st.NeedUpdate,
		"url":         st.URL,
		"last_check":  st.LastCheck,
		"error":       st.LastResult,
		"auto_check":  st.AutoCheck,
		"interval":    st.Interval,
	}
}

// handleUpdateCheck 返回最近一次检测结果。带 force=1 时立即请求 GitHub 刷新。
// 默认走缓存，避免打开设置页就打一次 GitHub，也便于后台自动检测统一口径。
func (s *Server) handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	// 强制检测会真实请求 GitHub 并写状态，属于有副变更的操作：只接受 POST（受 CSRF 保护）。
	if r.Method == http.MethodPost {
		st := s.runUpdateCheck(r.Context())
		writeJSON(w, http.StatusOK, updateStatePayload(st))
		return
	}
	writeJSON(w, http.StatusOK, updateStatePayload(s.store.UpdateConfig()))
}

// handleUpdateSettings 保存自动检测开关与频次。
func (s *Server) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AutoCheck *bool  `json:"auto_check"`
		Interval  string `json:"interval"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "参数解析失败")
		return
	}
	cur := s.store.UpdateConfig()
	auto := cur.AutoCheck
	if req.AutoCheck != nil {
		auto = *req.AutoCheck
	}
	interval := cur.Interval
	if req.Interval != "" {
		interval = req.Interval
	}
	if !validUpdateInterval(interval) {
		writeErr(w, http.StatusBadRequest, "检测频次无效")
		return
	}
	if err := s.store.SetUpdateConfig(auto, interval); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.store.Audit(sess(r).User, clientIP(r, s.cfg.TrustProxy), "update_settings",
		fmt.Sprintf("auto=%v interval=%s", auto, interval))
	writeJSON(w, http.StatusOK, updateStatePayload(s.store.UpdateConfig()))
}

// handleStorage 返回 SQLite 数据库位置与各类记录数量，让持久化状态可见。
func (s *Server) handleStorage(w http.ResponseWriter, r *http.Request) {
	path := filepath.Join(s.cfg.DataDir, "panel.db")
	var size int64
	if info, err := os.Stat(path); err == nil {
		size = info.Size()
	}
	var jobs, audits int
	if db := s.store.DB(); db != nil {
		_ = db.QueryRow(`SELECT COUNT(*) FROM jobs`).Scan(&jobs)
		_ = db.QueryRow(`SELECT COUNT(*) FROM audit`).Scan(&audits)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"path": path, "size": size,
		"jobs": jobs, "audit": audits,
		"sync_events": len(s.store.Snapshot().SyncEvents),
		"sync_seen":   s.store.SyncSeenCount(),
		"remote_seen": s.store.RemoteSeenCount(),
		"data_dir":    s.cfg.DataDir,
	})
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	sess := sess(r)
	cronHour, lastDay := s.store.CronSchedule()
	// cred_source 描述当前凭据来源；username_source / password_source 作为兼容别名保留。
	credSource := s.store.CredSource()
	j := map[string]any{
		"user":            sess.User,
		"cred_source":     credSource,
		"username_source": credSource,
		"csrf":            sess.CSRF,
		"acme_version":    s.acme.Version(r.Context()),
		"acme_home":       s.cfg.AcmeHome,
		"default_ca":      s.effectiveCA(),
		"default_email":   s.store.DefaultEmail(),
		"cookie_secure":   requestIsHTTPS(r),
		"tls":             requestIsHTTPS(r),
		"cron":            s.cfg.Cron,
		"cron_hour":       cronHour,
		"cron_last_day":   lastDay,
		"password_source": credSource,
		"retention_days":  s.store.RetentionDays(),
		"update":          s.store.UpdateConfig(),
		"locale":          s.store.Snapshot().Locale,
		"server_time":     time.Now(),
	}
	enforced, pinned := s.httpsOnly()
	j["force_https"] = enforced
	j["force_https_pinned"] = pinned
	j["https_now"] = requestIsHTTPS(r)
	writeJSON(w, http.StatusOK, j)
}

// handleHTTPSSettings 切换「仅允许 HTTPS 访问」。
// 环境变量已显式指定时拒绝修改界面状态，避免用户以为保存成功但策略未生效。
func (s *Server) handleHTTPSSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ForceHTTPS *bool `json:"force_https"`
	}
	if err := readJSON(w, r, &req); err != nil || req.ForceHTTPS == nil {
		writeErr(w, http.StatusBadRequest, "请求格式错误：需要 force_https 布尔值")
		return
	}
	if _, pinned := s.httpsOnly(); pinned {
		writeErr(w, http.StatusConflict, "仅允许 HTTPS 访问已由环境变量 ACME_PANEL_FORCE_HTTPS 锁定，请在部署环境修改后重启面板")
		return
	}
	if err := s.store.SetForceHTTPS(*req.ForceHTTPS); err != nil {
		writeErr(w, http.StatusInternalServerError, "保存失败："+err.Error())
		return
	}
	s.store.Audit(sess(r).User, clientIP(r, s.cfg.TrustProxy), "https_settings", strconv.FormatBool(*req.ForceHTTPS))
	enforced, pinned := s.httpsOnly()
	writeJSON(w, http.StatusOK, map[string]any{
		"force_https":        enforced,
		"force_https_pinned": pinned,
		"https_now":          requestIsHTTPS(r),
	})
}

// ---------------- 概览 ----------------

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	certs, err := s.certs.Scan()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "扫描证书失败: "+err.Error())
		return
	}
	var valid, warning, expired int
	next := []CertInfo{}
	for _, c := range certs {
		switch c.Status {
		case "valid":
			valid++
		case "warning", "critical":
			warning++
		case "expired":
			expired++
		}
		if c.Status != "expired" {
			next = append(next, c)
		}
	}
	if len(next) > 5 {
		next = next[:5]
	}
	jobs := s.jobs.List()
	if len(jobs) > 5 {
		jobs = jobs[:5]
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"total":      len(certs),
		"valid":      valid,
		"warning":    warning,
		"expired":    expired,
		"next":       next,
		"jobs":       jobs,
		"acme":       s.acme.Version(r.Context()),
		"version":    appVersion,
		"uptime_sec": int(time.Since(s.boot).Seconds()),
	})
}

// ---------------- 证书 ----------------

// attachEmails 把按域名保存的 ACME 邮箱附到证书信息里（空值表示使用全局默认）。
func (s *Server) attachEmails(certs []CertInfo) {
	emails := s.store.AllCertEmails()
	for i := range certs {
		if email, ok := emails[certs[i].Name]; ok {
			certs[i].Email = email
		}
	}
}

func (s *Server) handleListCerts(w http.ResponseWriter, r *http.Request) {
	certs, err := s.certs.Scan()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "扫描失败: "+err.Error())
		return
	}
	s.attachEmails(certs)
	writeJSON(w, http.StatusOK, map[string]any{"certs": certs})
}

func (s *Server) handleCertDetail(w http.ResponseWriter, r *http.Request) {
	ci, err := s.certs.Get(r.PathValue("name"))
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	ci.Email = s.store.CertEmail(ci.Name)
	writeJSON(w, http.StatusOK, ci)
}

func (s *Server) handleCertPEM(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	switch kind {
	case "cert", "fullchain", "chain":
	default:
		writeErr(w, http.StatusBadRequest, "不支持的文件类型")
		return
	}
	pemStr, err := s.certs.ReadPEM(r.PathValue("name"), kind)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=%q", kind+".pem"))
	_, _ = w.Write([]byte(pemStr))
}

type keyReq struct {
	Confirm string `json:"confirm"`
}

// handleCertKey 是唯一返回私钥的通道：POST + CSRF + 显式确认 + 审计。
func (s *Server) handleCertKey(w http.ResponseWriter, r *http.Request) {
	var req keyReq
	if err := readJSON(w, r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if req.Confirm != "I-UNDERSTAND" {
		writeErr(w, http.StatusForbidden, "需要显式确认后才能查看私钥")
		return
	}
	name := r.PathValue("name")
	pemStr, err := s.certs.ReadKey(name)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	sess := sess(r)
	ip := clientIP(r, s.cfg.TrustProxy)
	s.store.Audit(sess.User, ip, "private_key_view", name)
	go s.notify.Send("security_alert", "🔑 私钥被查看", fmt.Sprintf(
		"用户 %s 从 %s 查看了证书 %s 的私钥，已记录审计。", sess.User, ip, name))
	writeJSON(w, http.StatusOK, map[string]any{
		"name": name,
		"pem":  pemStr,
	})
}

// ---------------- 签发 / 续期 / 吊销 / 删除 ----------------

type issueReq struct {
	Domains        []string          `json:"domains"`
	Credential     string            `json:"credential"` // 已保存凭证名
	Code           string            `json:"code"`       // 或直接指定 provider 类型
	Env            map[string]string `json:"env"`        // 临时凭证（不落盘）
	SaveAs         string            `json:"save_as"`    // 可选：同时保存为新凭证
	KeyLength      string            `json:"keylength"`
	CA             string            `json:"ca"`
	Force          bool              `json:"force"`
	Email          string            `json:"email"`     // 该域名专用的 ACME 通知邮箱；留空用默认
	DNSSleep       int               `json:"dns_sleep"` // 跳过 acme.sh 公共 DNS 轮询的固定等待秒数；0 表示沿用 acme.sh 默认
	EABKid         string            `json:"eab_kid"`   // ACME 外部账户绑定（Google / ZeroSSL 注册账户用），不回显、不落 args
	EABHMACKey     string            `json:"eab_hmac_key"`
	EABCred        string            `json:"eab_cred"`        // 已保存 EAB 凭证名；与临时 kid/hmac 二选一
	ChallengeAlias string            `json:"challenge_alias"` // DNS 委托（CNAME）别名；留空表示直连验证
}

// normalizeChallengeAlias 归一化 acme.sh 的 --challenge-alias 参数。
// 用户常直接粘贴 CNAME 记录值 "_acme-challenge.alias.example.net."，需要去掉前缀与根点。
func normalizeChallengeAlias(v string) (string, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.TrimSuffix(v, ".")
	v = strings.TrimPrefix(v, "_acme-challenge.")
	if v == "" {
		return "", nil
	}
	if len(v) > 253 || !validDomain(v) {
		return "", fmt.Errorf("DNS 委托域名格式非法: %s", v)
	}
	return v, nil
}

func normalizeDomains(in []string) ([]string, error) {
	if len(in) == 0 {
		return nil, fmt.Errorf("至少填写一个域名")
	}
	if len(in) > 50 {
		return nil, fmt.Errorf("单次最多 50 个域名")
	}
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, d := range in {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if !validDomain(d) {
			return nil, fmt.Errorf("域名格式非法: %s", d)
		}
		if seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("至少填写一个域名")
	}
	return out, nil
}

// filterEnv 只保留 provider 定义中的字段，杜绝注入 PATH/LD_PRELOAD 等环境变量。
func filterEnv(code string, in map[string]string) (map[string]string, error) {
	def, ok := providerByCode[code]
	if !ok {
		return nil, fmt.Errorf("不支持的 DNS 服务商: %s", code)
	}
	allowed := make(map[string]bool, len(def.Fields))
	for _, f := range def.Fields {
		allowed[f.Name] = true
	}
	for k := range in {
		if !allowed[k] {
			return nil, fmt.Errorf("不允许的凭证字段: %s", k)
		}
	}
	out := map[string]string{}
	for _, f := range def.Fields {
		v := strings.TrimSpace(in[f.Name])
		if v == "" {
			if f.Optional {
				continue
			}
			return nil, fmt.Errorf("缺少必填凭证字段: %s", f.Label)
		}
		out[f.Name] = v
	}
	return out, nil
}

// prepareEAB 解析请求里的 EAB（已保存凭证或临时填写）并合入凭证 env；单签发/批量共用。
// 已保存凭证按名字从加密存储取出，CA 必须与本次签发一致，避免 Google 的 EAB 用到 ZeroSSL。
func (s *Server) prepareEAB(req issueReq, env map[string]string, ca string) (map[string]string, error) {
	kid, hmac := req.EABKid, req.EABHMACKey
	if req.EABCred != "" {
		credCA, ck, ch, err := s.store.GetEAB(req.EABCred)
		if err != nil {
			return nil, fmt.Errorf("读取 EAB 凭证失败：%v", err)
		}
		if credCA != ca {
			return nil, fmt.Errorf("EAB 凭证「%s」适用于 %s，与本次 CA (%s) 不符", req.EABCred, credCA, ca)
		}
		if kid == "" && hmac == "" {
			kid, hmac = ck, ch
		}
	}
	extra, err := eabEnv(kid, hmac)
	if err != nil {
		return nil, err
	}
	return mergeEAB(env, extra), nil
}

// buildIssueArgs 组装 acme.sh 签发参数；单个签发与批量签发共用，避免两处漂移。
func buildIssueArgs(code string, dnsSleep int, email, keylength, ca string, force bool, domains []string, alias string) []string {
	args := []string{"--issue", "--dns", code}
	if dnsSleep > 0 {
		// 指定秒数会让 acme.sh 跳过公共 DNS(DoH) 轮询，避免动态 DNS 长时间卡在预检。
		args = append(args, "--dnssleep", strconv.Itoa(dnsSleep))
	}
	if email != "" {
		args = append(args, "--accountemail", email)
	}
	if keylength != "" {
		args = append(args, "--keylength", keylength)
	}
	if ca != "letsencrypt" {
		args = append(args, "--server", ca)
	}
	if force {
		args = append(args, "--force")
	}
	for i, d := range domains {
		args = append(args, "-d", d)
		// acme.sh 的 --challenge-alias 是「跟随前一个 -d」的逐域名参数；
		// 面板整体委托到同一个别名域，因此紧跟首个域名即可覆盖本批全部域名。
		if i == 0 && alias != "" {
			args = append(args, "--challenge-alias", alias)
		}
	}
	return args
}

func (s *Server) handleIssue(w http.ResponseWriter, r *http.Request) {
	var req issueReq
	if err := readJSON(w, r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	domains, err := normalizeDomains(req.Domains)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !validKeyLength(req.KeyLength) {
		writeErr(w, http.StatusBadRequest, "不支持的密钥类型")
		return
	}
	if req.DNSSleep < 0 || req.DNSSleep > 600 {
		writeErr(w, http.StatusBadRequest, "DNS 生效等待需在 0～600 秒之间")
		return
	}
	alias, err := normalizeChallengeAlias(req.ChallengeAlias)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ca := req.CA
	if ca == "" {
		ca = s.effectiveCA()
	}
	if _, ok := allowedCA[ca]; !ok {
		writeErr(w, http.StatusBadRequest, "不支持的 CA")
		return
	}

	var code string
	var env map[string]string
	if req.Credential != "" {
		code, env, err = s.store.GetProvider(req.Credential)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "读取凭证失败: "+err.Error())
			return
		}
		code = normalizeProviderCode(code)
		if _, ok := providerByCode[code]; !ok {
			writeErr(w, http.StatusBadRequest, "已保存凭证类型不受支持")
			return
		}
	} else {
		code = normalizeProviderCode(req.Code)
		env, err = filterEnv(code, req.Env)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if req.SaveAs != "" && req.Credential == "" {
		if !validCertName(req.SaveAs) {
			writeErr(w, http.StatusBadRequest, "凭证名称只能包含字母、数字、点、下划线和短横线")
			return
		}
		if err := s.store.PutProvider(req.SaveAs, code, env); err != nil {
			writeErr(w, http.StatusInternalServerError, "保存凭证失败")
			return
		}
		s.store.Audit(sess(r).User, clientIP(r, s.cfg.TrustProxy), "provider_save", req.SaveAs+" / "+code)
	}

	// EAB 必须成对出现且合法；合入 env 后随凭证一起加密落盘，绝不进 args / 重选快照。
	env, err = s.prepareEAB(req, env, ca)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// 邮箱优先级：本次签发指定 > 该域名已保存的邮箱 > 全局默认邮箱。
	email := strings.TrimSpace(req.Email)
	if email == "" {
		email = s.store.CertEmail(domains[0])
	}
	if email == "" {
		email = s.store.DefaultEmail()
	}
	if email != "" && !emailRe.MatchString(email) {
		writeErr(w, http.StatusBadRequest, "ACME 邮箱格式不合法")
		return
	}
	certKey := domains[0]
	if strings.HasPrefix(req.KeyLength, "ec-") {
		certKey += "_ecc"
	}
	if strings.TrimSpace(req.Email) != "" {
		if err := s.store.SetCertEmail(certKey, email); err != nil {
			writeErr(w, http.StatusInternalServerError, "保存域名邮箱失败")
			return
		}
	}

	args := buildIssueArgs(code, req.DNSSleep, email, req.KeyLength, ca, req.Force, domains, alias)

	preview := "acme.sh --issue --dns " + code
	if req.DNSSleep > 0 {
		preview += " --dnssleep " + strconv.Itoa(req.DNSSleep)
	}
	if alias != "" {
		preview += " --challenge-alias " + alias
	}
	for _, d := range domains {
		preview += " -d " + d
	}
	job := s.jobs.Start("issue", "签发 "+domains[0], domains[0], preview, env, args)
	// 重选快照：只记录非敏感参数；临时凭证的明文 env 绝不回显。
	s.jobs.SetReissue(job.ID, &ReissueInfo{
		Kind: "issue", Domains: domains, Credential: req.Credential, Code: code,
		KeyLength: req.KeyLength, CA: ca, Email: req.Email,
		DNSSleep: req.DNSSleep, Force: req.Force, TempEnv: req.Credential == "",
		HasEAB: req.EABKid != "" || req.EABCred != "", ChallengeAlias: alias,
	})
	s.store.Audit(sess(r).User, clientIP(r, s.cfg.TrustProxy), "issue", strings.Join(domains, ",")+" via "+code)
	writeJSON(w, http.StatusAccepted, map[string]any{"job": job})
}

func (s *Server) handleRenew(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	ci, err := s.certs.Get(name)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	var body struct {
		Force bool `json:"force"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body)

	args := []string{"--renew", "-d", ci.Domain}
	if ci.IsECC {
		args = append(args, "--ecc")
	}
	if body.Force {
		args = append(args, "--force")
	}
	preview := "acme.sh --renew -d " + ci.Domain
	if ci.IsECC {
		preview += " --ecc"
	}
	if body.Force {
		preview += " --force"
	}
	job := s.jobs.Start("renew", "续期 "+ci.Domain, ci.Domain, preview, nil, args)
	s.store.Audit(sess(r).User, clientIP(r, s.cfg.TrustProxy), "renew", name)
	writeJSON(w, http.StatusAccepted, map[string]any{"job": job})
}

func (s *Server) handleRenewAll(w http.ResponseWriter, r *http.Request) {
	job := s.jobs.Start("cron", "手动检查全部续期", "", "acme.sh --cron", nil, []string{"--cron"})
	s.checkExpiring() // 手动检查时也顺带推送临期提醒
	s.store.Audit(sess(r).User, clientIP(r, s.cfg.TrustProxy), "renew_all", "")
	writeJSON(w, http.StatusAccepted, map[string]any{"job": job})
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	ci, err := s.certs.Get(name)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	args := []string{"--revoke", "-d", ci.Domain}
	if ci.IsECC {
		args = append(args, "--ecc")
	}
	job := s.jobs.Start("revoke", "吊销 "+ci.Domain, ci.Domain, "acme.sh --revoke -d "+ci.Domain, nil, args)
	s.store.Audit(sess(r).User, clientIP(r, s.cfg.TrustProxy), "revoke", name)
	writeJSON(w, http.StatusAccepted, map[string]any{"job": job})
}

func (s *Server) handleRemove(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	ci, err := s.certs.Get(name)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	var body struct {
		Purge bool `json:"purge"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body)

	args := []string{"--remove", "-d", ci.Domain}
	if ci.IsECC {
		args = append(args, "--ecc")
	}
	var job *Job
	if body.Purge {
		// 先同步移除续期条目，再清理磁盘目录（都走白名单路径校验）。
		job = s.jobs.Start("remove", "删除 "+name, ci.Domain, "acme.sh --remove -d "+ci.Domain+" && 删除目录", nil, args)
		// 一次性完成钩子：任务真正结束后才决定是否删目录，不再用固定 60s 轮询
		// （任务超时是 15min，轮询会在慢 CA 场景漏掉清理）。钩子在 finish 内触发。
		s.jobs.mu.Lock()
		s.jobs.purgeHooks[job.ID] = func() {
			cur := s.jobs.Get(job.ID)
			// 只有 acme.sh --remove 真正成功才删目录；失败/取消保留目录，
			// 避免「acme.sh 仍认为证书存在但磁盘文件已没了」的不一致。
			if cur == nil || cur.Status != "success" {
				s.jobs.push(job, "✗ 未删除目录 "+name+"：移除证书未成功，请确认后手动清理")
				return
			}
			if err := s.certs.Purge(name); err == nil {
				s.jobs.push(job, "✓ 已删除目录 "+name)
			} else {
				s.jobs.push(job, "✗ 删除目录失败: "+err.Error())
			}
		}
		s.jobs.mu.Unlock()
		s.store.Audit(sess(r).User, clientIP(r, s.cfg.TrustProxy), "remove_purge", name)
	} else {
		job = s.jobs.Start("remove", "移除 "+name, ci.Domain, "acme.sh --remove -d "+ci.Domain, nil, args)
		s.store.Audit(sess(r).User, clientIP(r, s.cfg.TrustProxy), "remove", name)
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"job": job})
}

func (s *Server) handleInstall(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	ci, err := s.certs.Get(name)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	outDir := filepath.Join(s.cfg.DataDir, "output", name)
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		writeErr(w, http.StatusInternalServerError, "创建输出目录失败")
		return
	}
	args := []string{"--install-cert", "-d", ci.Domain}
	if ci.IsECC {
		args = append(args, "--ecc")
	}
	args = append(args,
		"--key-file", filepath.Join(outDir, "key.pem"),
		"--fullchain-file", filepath.Join(outDir, "fullchain.pem"),
		"--cert-file", filepath.Join(outDir, "cert.pem"),
		"--ca-file", filepath.Join(outDir, "chain.pem"),
	)
	job := s.jobs.Start("install", "部署 "+name, ci.Domain, "acme.sh --install-cert -d "+ci.Domain+" → "+outDir, nil, args)
	s.store.Audit(sess(r).User, clientIP(r, s.cfg.TrustProxy), "install", name+" -> "+outDir)
	writeJSON(w, http.StatusAccepted, map[string]any{"job": job, "output_dir": outDir})
}

// ---------------- 服务商凭证 ----------------

func (s *Server) handleCatalog(w http.ResponseWriter, r *http.Request) {
	type caItem struct {
		Code        string `json:"code"`
		Name        string `json:"name"`
		RequiresEAB bool   `json:"requires_eab"` // 注册新账户必须提供 EAB（Google）
		SupportsEAB bool   `json:"supports_eab"` // 接受可选 EAB（Google / ZeroSSL）
		Hint        string `json:"hint,omitempty"`
	}
	cas := []caItem{
		{"letsencrypt", "Let's Encrypt", false, false, ""},
		{"letsencrypt_test", "Let's Encrypt (测试环境)", false, false, ""},
		{"zerossl", "ZeroSSL", false, true, "EAB 可留空，acme.sh 会用 ACME 邮箱自动获取；频繁重试可能触发 CA 限流（Retry-After 86400 秒），失败后请等待 24 小时再试。"},
		{"buypass", "Buypass", false, false, "部分网络无法解析其 API 域名；若初始化失败请更换 CA。"},
		{"google", "Google Trust Services", true, true, "必须先启用 Google Cloud 的 Public CA API 并申请 EAB kid / HMAC key，否则新账户注册会被拒绝；签发弹窗内附直达链接。"},
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"providers":  providerCatalog,
		"cas":        cas,
		"default_ca": s.effectiveCA(),
		"ca_locked":  env("ACME_PANEL_CA", "") != "",
		"ca_options": caOptions(),
		"keylengths": []string{"ec-256", "ec-384", "2048", "4096"},
		"version":    appVersion,
		"cookie_sec": requestIsHTTPS(r),
		"output_dir": filepath.Join(s.cfg.DataDir, "output"),
		"acme_home":  s.cfg.AcmeHome,
	})
}

func (s *Server) handleProviders(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"catalog":    providerCatalog,
		"saved":      s.store.ListProviders(),
		"output_dir": filepath.Join(s.cfg.DataDir, "output"),
	})
}

func (s *Server) handleSaveProvider(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string            `json:"name"`
		Code string            `json:"code"`
		Env  map[string]string `json:"env"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if !validCertName(req.Name) {
		writeErr(w, http.StatusBadRequest, "凭证名称非法")
		return
	}
	code := normalizeProviderCode(req.Code)
	env, err := filterEnv(code, req.Env)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.PutProvider(req.Name, code, env); err != nil {
		writeErr(w, http.StatusInternalServerError, "保存失败")
		return
	}
	s.store.Audit(sess(r).User, clientIP(r, s.cfg.TrustProxy), "provider_save", req.Name+" / "+code)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleDeleteProvider(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.store.DeleteProvider(name); err != nil {
		writeErr(w, http.StatusBadRequest, "删除失败")
		return
	}
	s.store.Audit(sess(r).User, clientIP(r, s.cfg.TrustProxy), "provider_delete", name)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---------------- EAB 凭证 ----------------

func (s *Server) handleEABCreds(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"saved": s.store.ListEABs()})
}

func (s *Server) handleSaveEABCred(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
		CA   string `json:"ca"`
		Kid  string `json:"kid"`
		HMAC string `json:"hmac"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if !validCertName(req.Name) {
		writeErr(w, http.StatusBadRequest, "凭证名称非法")
		return
	}
	ca := strings.TrimSpace(req.CA)
	if ca != "google" && ca != "zerossl" {
		writeErr(w, http.StatusBadRequest, "EAB 凭证仅支持 google 或 zerossl")
		return
	}
	norm, err := eabEnv(req.Kid, req.HMAC)
	if err != nil || norm == nil {
		writeErr(w, http.StatusBadRequest, "EAB kid / HMAC key 不合法：需成对填写，长度 8～256 字符")
		return
	}
	if err := s.store.PutEAB(req.Name, ca, norm[eabKidEnv], norm[eabHMACEnv]); err != nil {
		writeErr(w, http.StatusInternalServerError, "保存失败")
		return
	}
	s.store.Audit(sess(r).User, clientIP(r, s.cfg.TrustProxy), "eab_cred_save", req.Name+" / "+ca)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleDeleteEABCred(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.store.DeleteEAB(name); err != nil {
		writeErr(w, http.StatusBadRequest, "删除失败")
		return
	}
	s.store.Audit(sess(r).User, clientIP(r, s.cfg.TrustProxy), "eab_cred_delete", name)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---------------- 任务 / SSE ----------------

func (s *Server) handleJobs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"jobs": s.jobs.List()})
}

func (s *Server) handleJob(w http.ResponseWriter, r *http.Request) {
	j := s.jobs.Get(r.PathValue("id"))
	if j == nil {
		writeErr(w, http.StatusNotFound, "任务不存在")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"job": j, "logs": j.logs})
}

// handleJobReissue 返回任务的非敏感签发参数，供「重选」回到签发弹窗预填。
// 凭证明文绝不输出：已保存凭证只回名字，临时凭证只标记 temp_env。
func (s *Server) handleJobReissue(w http.ResponseWriter, r *http.Request) {
	info := s.jobs.ReissueInfo(r.PathValue("id"))
	if info == nil {
		writeErr(w, http.StatusNotFound, "该任务没有可重选的签发参数")
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (s *Server) handleCancelJob(w http.ResponseWriter, r *http.Request) {
	if !s.jobs.Cancel(r.PathValue("id")) {
		writeErr(w, http.StatusBadRequest, "任务无法取消")
		return
	}
	s.retry.Cancel(r.PathValue("id"))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleRetryJob(w http.ResponseWriter, r *http.Request) {
	j, err := s.jobs.Retry(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.retry.Cancel(r.PathValue("id"))
	s.store.Audit(sess(r).User, clientIP(r, s.cfg.TrustProxy), "job_retry", j.Title)
	writeJSON(w, http.StatusAccepted, map[string]any{"job": j})
}

func (s *Server) handleJobEvents(w http.ResponseWriter, r *http.Request) {
	j := s.jobs.Get(r.PathValue("id"))
	if j == nil {
		writeErr(w, http.StatusNotFound, "任务不存在")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "不支持流式输出")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	hist, ch, cancel := s.jobs.Subscribe(j.ID)
	defer cancel()

	send := func(line string) {
		if strings.HasPrefix(line, "__done__:") {
			fmt.Fprintf(w, "event: done\ndata: %s\n\n", strings.TrimPrefix(line, "__done__:"))
		} else {
			fmt.Fprintf(w, "data: %s\n\n", strings.ReplaceAll(line, "\n", " "))
		}
		flusher.Flush()
	}
	for _, line := range hist {
		send(line)
	}
	flusher.Flush()

	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case line, ok := <-ch:
			if !ok {
				return
			}
			send(line)
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}

// handleAudit 返回审计日志。支持 q/action/user/ip/from/to 筛选与 limit/offset 分页；
// 不带参数时返回最近 200 条，保持旧行为兼容。
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filters := q.Get("q") != "" || q.Get("action") != "" || q.Get("user") != "" ||
		q.Get("ip") != "" || q.Get("from") != "" || q.Get("to") != "" ||
		q.Get("limit") != "" || q.Get("offset") != ""
	if !filters {
		writeJSON(w, http.StatusOK, map[string]any{
			"entries": s.store.AuditTail(200), "total": s.store.AuditCount(),
			"actions": s.store.AuditActions(), "users": s.store.AuditUsers(),
		})
		return
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	f := AuditFilter{
		Query: q.Get("q"), Action: q.Get("action"), User: q.Get("user"), IP: q.Get("ip"),
		From: q.Get("from"), To: q.Get("to"), Limit: limit, Offset: offset,
	}
	entries, total := s.store.AuditQuery(f)
	writeJSON(w, http.StatusOK, map[string]any{
		"entries": entries, "total": total,
		"actions": s.store.AuditActions(), "users": s.store.AuditUsers(),
	})
}

// ---------------- 通知渠道与邮箱 ----------------

func (s *Server) handleNotifyCatalog(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"events":        notifyEvents,
		"kinds":         notifierKinds,
		"default_email": s.store.DefaultEmail(),
		"quiet_hours":   s.store.Snapshot().QuietHours,
	})
}

func (s *Server) handleNotifyList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"notifiers":     s.store.ListNotifiers(),
		"default_email": s.store.DefaultEmail(),
		"cert_emails":   s.store.AllCertEmails(),
	})
}

type notifySaveReq struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Kind       string   `json:"kind"`
	Target     string   `json:"target"`
	Secret     string   `json:"secret"`
	Events     []string `json:"events"`
	Enabled    bool     `json:"enabled"`
	KeepTarget bool     `json:"keep_target"`
	KeepSecret bool     `json:"keep_secret"`
}

func (s *Server) handleNotifySave(w http.ResponseWriter, r *http.Request) {
	var req notifySaveReq
	if err := readJSON(w, r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if !validCertName(req.Name) {
		writeErr(w, http.StatusBadRequest, "渠道名称只能包含字母、数字、点、下划线和短横线")
		return
	}
	def, ok := notifierKindByCode[req.Kind]
	if !ok {
		writeErr(w, http.StatusBadRequest, "不支持的通知渠道类型")
		return
	}
	events := req.Events
	if events == nil {
		events = []string{}
	}
	for _, ev := range events {
		if !notifyEventCodes[ev] {
			writeErr(w, http.StatusBadRequest, "未知通知事件: "+ev)
			return
		}
	}

	id := strings.TrimSpace(req.ID)
	target := strings.TrimSpace(req.Target)
	secret := strings.TrimSpace(req.Secret)
	if id != "" {
		old, err := s.store.GetNotifier(id)
		if err != nil {
			writeErr(w, http.StatusNotFound, "通知渠道不存在")
			return
		}
		if req.KeepTarget {
			target = old.Target
		}
		if req.KeepSecret {
			secret = old.Secret
		}
	} else {
		id = randToken(8)
	}
	if def.NeedTarget && target == "" {
		writeErr(w, http.StatusBadRequest, "请填写"+def.TargetLabel)
		return
	}
	if def.NeedSecret && secret == "" {
		writeErr(w, http.StatusBadRequest, "请填写"+def.SecretLabel)
		return
	}
	if target != "" {
		if _, err := safeURL(target); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	n := Notifier{
		ID: id, Name: req.Name, Kind: req.Kind,
		Target: target, Secret: secret, Events: events, Enabled: req.Enabled,
	}
	if err := s.store.PutNotifier(n); err != nil {
		writeErr(w, http.StatusInternalServerError, "保存通知渠道失败")
		return
	}
	s.store.Audit(sess(r).User, clientIP(r, s.cfg.TrustProxy), "notifier_save", n.Name+" / "+n.Kind)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": n.ID})
}

func (s *Server) handleNotifyDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	n, err := s.store.GetNotifier(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "通知渠道不存在")
		return
	}
	_ = s.store.DeleteNotifier(id)
	s.store.Audit(sess(r).User, clientIP(r, s.cfg.TrustProxy), "notifier_delete", n.Name)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleNotifyTest(w http.ResponseWriter, r *http.Request) {
	n, err := s.store.GetNotifier(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "通知渠道不存在")
		return
	}
	if err := s.notify.SendTest(n); err != nil {
		s.store.Audit(sess(r).User, clientIP(r, s.cfg.TrustProxy), "notifier_test_failed", n.Name+": "+err.Error())
		writeErr(w, http.StatusBadGateway, "推送失败: "+err.Error())
		return
	}
	s.store.Audit(sess(r).User, clientIP(r, s.cfg.TrustProxy), "notifier_test", n.Name)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleDefaultEmail(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	email := strings.TrimSpace(req.Email)
	if email != "" && !emailRe.MatchString(email) {
		writeErr(w, http.StatusBadRequest, "邮箱格式不合法")
		return
	}
	if err := s.store.SetDefaultEmail(email); err != nil {
		writeErr(w, http.StatusInternalServerError, "保存失败")
		return
	}
	s.store.Audit(sess(r).User, clientIP(r, s.cfg.TrustProxy), "default_email", email)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleCertEmail(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, err := s.certs.Get(name); err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	var req struct {
		Email string `json:"email"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	email := strings.TrimSpace(req.Email)
	if email != "" && !emailRe.MatchString(email) {
		writeErr(w, http.StatusBadRequest, "邮箱格式不合法")
		return
	}
	if err := s.store.SetCertEmail(name, email); err != nil {
		writeErr(w, http.StatusInternalServerError, "保存失败")
		return
	}
	s.store.Audit(sess(r).User, clientIP(r, s.cfg.TrustProxy), "cert_email", name+" -> "+orEmpty(email))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func orEmpty(s string) string {
	if s == "" {
		return "（恢复默认）"
	}
	return s
}

// handleCronSchedule 设置每日自动检测时间。
func (s *Server) handleCronSchedule(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Hour int `json:"hour"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if req.Hour < 0 || req.Hour > 23 {
		writeErr(w, http.StatusBadRequest, "小时必须在 0-23 之间")
		return
	}
	if err := s.store.SetCronHour(req.Hour); err != nil {
		writeErr(w, http.StatusInternalServerError, "保存失败")
		return
	}
	s.store.Audit(sess(r).User, clientIP(r, s.cfg.TrustProxy), "cron_schedule", fmt.Sprintf("每日 %02d:00", req.Hour))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "hour": req.Hour})
}

// handleRetention 设置任务/审计/同步记录的保留天数（0 表示永不清理）。
func (s *Server) handleRetention(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Days int `json:"days"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if err := s.store.SetRetentionDays(req.Days); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.store.Audit(sess(r).User, clientIP(r, s.cfg.TrustProxy), "retention_days", fmt.Sprintf("%d 天", req.Days))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "days": req.Days})
}

// handleCleanup 手动触发一次过期数据清理（每天也会自动执行）。
func (s *Server) handleCleanup(w http.ResponseWriter, r *http.Request) {
	removed, err := s.store.Cleanup(s.store.RetentionDays())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "清理失败")
		return
	}
	s.store.Audit(sess(r).User, clientIP(r, s.cfg.TrustProxy), "cleanup", fmt.Sprintf("%v", removed))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "removed": removed, "days": s.store.RetentionDays()})
}

func (s *Server) handlePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Old string `json:"old"`
		New string `json:"new"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	sess := sess(r)
	ip := clientIP(r, s.cfg.TrustProxy)
	if d := s.limit.Locked(ip + "|pwd"); d > 0 {
		writeErr(w, http.StatusTooManyRequests, fmt.Sprintf("尝试过于频繁，请 %d 秒后重试", int(d.Seconds())))
		return
	}
	if !s.store.CheckPassword(req.Old) {
		s.limit.Fail(clientIP(r, s.cfg.TrustProxy) + "|pwd")
		s.store.Audit(sess.User, clientIP(r, s.cfg.TrustProxy), "password_change_failed", "旧密码错误")
		go s.notify.Send("security_alert", "⚠ 修改密码失败", fmt.Sprintf(
			"用户 %s 从 %s 尝试修改密码但原密码错误。", sess.User, clientIP(r, s.cfg.TrustProxy)))
		writeErr(w, http.StatusForbidden, "原密码错误")
		return
	}
	if !strongPassword(req.New) {
		writeErr(w, http.StatusBadRequest, "新密码需至少 12 位，且同时包含大写字母、小写字母和数字")
		return
	}
	if err := s.store.SetPassword(req.New); err != nil {
		writeErr(w, http.StatusInternalServerError, "修改密码失败")
		return
	}
	// Web 修改后凭据以数据库为准，重启不再被 env 覆盖。
	_ = s.store.SetCredSource("web")
	n := s.sess.DeleteUserExcept(sess.User, sess.ID)
	s.store.Audit(sess.User, clientIP(r, s.cfg.TrustProxy), "password_change", fmt.Sprintf("其它会话已失效: %d", n))
	go s.notify.Send("security_alert", "✅ 登录密码已修改", fmt.Sprintf(
		"用户 %s 从 %s 修改了登录密码，其它 %d 个会话已失效。", sess.User, clientIP(r, s.cfg.TrustProxy), n))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "sessions_revoked": n})
}

// handleUsername 修改登录账号。需校验当前密码；成功后注销所有会话强制重新登录，
// 避免会话里缓存旧账号。修改结果持久保存，重启不会被 env 覆盖。
func (s *Server) handleUsername(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
		Username string `json:"username"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	sess := sess(r)
	ip := clientIP(r, s.cfg.TrustProxy)
	key := ip + "|userchg"
	if d := s.limit.Locked(key); d > 0 {
		writeErr(w, http.StatusTooManyRequests, fmt.Sprintf("尝试过于频繁，请 %d 秒后重试", int(d.Seconds())))
		return
	}
	if !s.store.CheckPassword(req.Password) {
		s.limit.Fail(key)
		s.store.Audit(sess.User, ip, "username_change_failed", "密码错误")
		go s.notify.Send("security_alert", "⚠ 修改账号失败", fmt.Sprintf(
			"用户 %s 从 %s 尝试修改账号但密码错误。", sess.User, ip))
		writeErr(w, http.StatusForbidden, "密码错误")
		return
	}
	username := strings.TrimSpace(req.Username)
	if !validUsername(username) {
		writeErr(w, http.StatusBadRequest, "账号需 3-32 位，字母开头，只能用字母、数字、下划线和短横线")
		return
	}
	if s.store.Username() == username {
		writeErr(w, http.StatusBadRequest, "新账号与当前账号相同")
		return
	}
	old := s.store.Username()
	if err := s.store.SetUsername(username); err != nil {
		writeErr(w, http.StatusInternalServerError, "修改账号失败")
		return
	}
	_ = s.store.SetCredSource("web")
	s.limit.Reset(key)
	// 注销全部会话（含当前），要求用新账号重新登录。
	n := s.sess.DeleteUserExcept(old, "")
	s.store.Audit(old, ip, "username_change", fmt.Sprintf("%s -> %s，会话已全部失效(%d)", old, username, n))
	go s.notify.Send("security_alert", "✅ 登录账号已修改", fmt.Sprintf(
		"账号 %s 从 %s 修改为 %s，%d 个会话已失效。修改已持久保存，重启后仍生效。", old, ip, username, n))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "sessions_revoked": n})
}

// ---------------- 证书同步 ----------------

func (s *Server) handleSyncCatalog(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":       s.sync.Enabled(),
		"dirs":          s.cfg.SyncDirs,
		"dir":           strings.Join(s.cfg.SyncDirs, ","),
		"modes":         syncModes,
		"presets":       syncPresets,
		"files":         s.sync.ListFiles(),
		"dir_status":    s.sync.CheckDirs(),
		"needs_restart": !s.sync.Enabled(),
	})
}

// splitSyncEvents 按 scope 分流同步记录：remote 只含推送到远程主机的结果，
// 旧记录没有 scope 时归入本地，避免远程区混入本地写入结果。
func splitSyncEvents(all []SyncEvent) (localEvents, remoteEvents []SyncEvent) {
	localEvents = []SyncEvent{}
	remoteEvents = []SyncEvent{}
	for _, ev := range all {
		if ev.Scope == "remote" {
			remoteEvents = append(remoteEvents, ev)
		} else {
			localEvents = append(localEvents, ev)
		}
	}
	return
}

func (s *Server) handleSyncRules(w http.ResponseWriter, r *http.Request) {
	localEvents, remoteEvents := splitSyncEvents(s.store.ListSyncEvents())
	writeJSON(w, http.StatusOK, map[string]any{
		"rules":             s.store.ListSyncRules(),
		"events":            localEvents,
		"remote_events":     remoteEvents,
		"seen_count":        s.store.SyncSeenCount(),
		"remote_seen_count": s.store.RemoteSeenCount(),
	})
}

func (s *Server) handleSyncSave(w http.ResponseWriter, r *http.Request) {
	var rule SyncRule
	if err := readJSONLimit(w, r, &rule, 8192); err != nil {
		writeErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	rule.ID = strings.TrimSpace(rule.ID)
	if rule.ID == "" {
		rule.ID = randToken(8)
	}
	rule.Name = strings.TrimSpace(rule.Name)
	if rule.Name == "" {
		rule.Name = "同步规则"
	}
	if !syncModeCodes[rule.Mode] {
		writeErr(w, http.StatusBadRequest, "未知匹配模式")
		return
	}
	if rule.Mode == syncFilename && strings.TrimSpace(rule.Pattern) == "" {
		writeErr(w, http.StatusBadRequest, "文件名模式必须填写匹配表达式")
		return
	}
	if rule.CertTmpl == "" {
		rule.CertTmpl = "{domain}_cert.pem"
	}
	if rule.KeyTmpl == "" {
		rule.KeyTmpl = "{domain}_key.pem"
	}
	// 注意：上面两个模板是历史兼容字段，实际同步不使用；保留仅为不破坏旧客户端提交。
	if !validCertName(rule.Source) && rule.Source != "" && rule.Source != "*" {
		writeErr(w, http.StatusBadRequest, "源证书名不合法")
		return
	}
	if err := s.store.PutSyncRule(rule); err != nil {
		writeErr(w, http.StatusInternalServerError, "保存失败")
		return
	}
	s.store.Audit(sess(r).User, clientIP(r, s.cfg.TrustProxy), "sync_rule_save", rule.Name)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "rule": rule})
}

func (s *Server) handleSyncDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.DeleteSyncRule(id); err != nil {
		writeErr(w, http.StatusInternalServerError, "删除失败")
		return
	}
	s.store.Audit(sess(r).User, clientIP(r, s.cfg.TrustProxy), "sync_rule_delete", id)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// filterSyncEvents 在内存里对本地 + 远程合并后的记录做多条件筛选。
// 记录上限只有 120 条，内存过滤比拼 SQL 更简单可靠，也避免注入。
func filterSyncEvents(all []SyncEvent, q, result, scope, from, to string) []SyncEvent {
	q = strings.ToLower(strings.TrimSpace(q))
	out := []SyncEvent{}
	for _, ev := range all {
		sc := ev.Scope
		if sc != "remote" {
			sc = "local" // 旧记录没有 scope，归入本地
		}
		if scope != "" && scope != "all" && scope != sc {
			continue
		}
		if result != "" && result != "all" && ev.Result != result {
			continue
		}
		day := ""
		if len(ev.Time) >= 10 {
			day = ev.Time[:10]
		}
		if from != "" && (day == "" || day < from) {
			continue
		}
		if to != "" && (day == "" || day > to) {
			continue
		}
		if q != "" {
			hay := strings.ToLower(strings.Join([]string{
				ev.Rule, ev.Source, ev.Target, ev.Detail, sc, ev.Result,
				strings.Join(ev.Files, " "),
			}, " "))
			if !strings.Contains(hay, q) {
				continue
			}
		}
		out = append(out, ev)
	}
	return out
}

// SyncEventGroup 是同一批次同步的合并展示项。一次同步通常会产生 cert/key、
// 多个域名的多条事件，逐条展示会把时间、规则、来源重复很多遍；合并后只展示
// 一条批次记录，文件用 chips 列出。原始记录仍通过 events 系列字段返回。
type SyncEventGroup struct {
	Time   string   `json:"time"`
	Scope  string   `json:"scope"`
	Rule   string   `json:"rule"`
	Source string   `json:"source"`
	Target string   `json:"target"`
	Result string   `json:"result"`
	Detail string   `json:"detail"`
	Count  int      `json:"count"`  // 文件数
	Files  []string `json:"files"`  // 文件名列表
	Merged int      `json:"merged"` // 合并了多少条原始记录

	key string `json:"-"`
}

// syncTargetDir 取「主机@用户:目录/文件」或「/目录/文件」的目录部分，
// 让同一次推送到同一目录的多个文件归为一批。
func syncTargetDir(target string) string {
	if i := strings.LastIndex(target, "/"); i > 0 {
		return target[:i]
	}
	return target
}

// groupSyncEvents 合并相邻且同范围、规则、来源、结果、目标目录、
// 同一分钟内的事件。记录本身按时间倒序，批次的事件天然相邻。
func groupSyncEvents(events []SyncEvent) []SyncEventGroup {
	out := []SyncEventGroup{}
	for _, ev := range events {
		scope := ev.Scope
		if scope != "remote" {
			scope = "local"
		}
		bucket := ev.Time
		if len(bucket) >= 16 {
			bucket = bucket[:16] // 精确到分钟，避免同批次事件跨秒后被拆开
		}
		key := strings.Join([]string{scope, ev.Rule, ev.Source, syncTargetDir(ev.Target), ev.Result, bucket}, "\x00")
		if len(out) > 0 && out[len(out)-1].key == key {
			g := &out[len(out)-1]
			g.Merged++
			if ev.Count > 0 {
				g.Count += ev.Count
			} else if len(ev.Files) > 0 {
				g.Count += len(ev.Files)
			}
			g.Files = append(g.Files, ev.Files...)
			// 失败详情最重要；成功批次保留第一条（文件名前缀相同）。
			if ev.Detail != "" && (g.Detail == "" || ev.Result == "fail") {
				g.Detail = ev.Detail
			}
			continue
		}
		out = append(out, SyncEventGroup{
			Time: ev.Time, Scope: scope, Rule: ev.Rule, Source: ev.Source,
			Target: syncTargetDir(ev.Target), Result: ev.Result, Detail: ev.Detail,
			Count: ev.Count, Files: append([]string(nil), ev.Files...), Merged: 1, key: key,
		})
	}
	return out
}

// handleSyncEvents 返回合并后的同步记录，支持关键词 / 结果 / 范围 / 日期筛选与分页。
// entries 为合并后的批次；events、remote_events、all_events 保留原始记录，兼容旧调用。
func (s *Server) handleSyncEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	all := s.store.AllSyncEvents()
	filtered := filterSyncEvents(all, q.Get("q"), q.Get("result"), q.Get("scope"), q.Get("from"), q.Get("to"))
	grouped := groupSyncEvents(filtered)
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}
	if offset > len(grouped) {
		offset = len(grouped)
	}
	end := offset + limit
	if end > len(grouped) {
		end = len(grouped)
	}
	entries := grouped[offset:end]
	if entries == nil {
		entries = []SyncEventGroup{}
	}
	localEvents, remoteEvents := splitSyncEvents(all)
	writeJSON(w, http.StatusOK, map[string]any{
		"entries":       entries,
		"total":         len(grouped),
		"limit":         limit,
		"offset":        offset,
		"results":       []string{"ok", "fail", "skip"},
		"scopes":        []string{"local", "remote"},
		"events":        localEvents,
		"remote_events": remoteEvents,
		"all_events":    all,
	})
}

func (s *Server) handleSyncClearEvents(w http.ResponseWriter, r *http.Request) {
	if err := s.store.ClearSyncEvents(); err != nil {
		writeErr(w, http.StatusInternalServerError, "清空失败")
		return
	}
	s.store.Audit(sess(r).User, clientIP(r, s.cfg.TrustProxy), "sync_clear_events", "")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleSyncRun(w http.ResponseWriter, r *http.Request) {
	if !s.sync.Enabled() {
		writeErr(w, http.StatusBadRequest, "未配置 ACME_PANEL_SYNC_DIR，无法同步")
		return
	}
	var req struct {
		Force bool `json:"force"`
	}
	// 允许空 body；解析不出内容时按普通同步处理。
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req)
	res := s.sync.run("手动触发", req.Force)
	detail := "普通同步"
	if req.Force {
		detail = "强制同步"
	}
	s.store.Audit(sess(r).User, clientIP(r, s.cfg.TrustProxy), "sync_run", detail)
	localEvents, remoteEvents := splitSyncEvents(res.Events)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "events": localEvents, "remote_events": remoteEvents,
		"all_events": res.Events, "skipped": res.Skipped, "force": req.Force,
	})
}

// handleSyncPreview 只计算规则会命中哪些文件，不写入任何内容。
func (s *Server) handleSyncPreview(w http.ResponseWriter, r *http.Request) {
	var rule SyncRule
	if err := readJSONLimit(w, r, &rule, 8192); err != nil {
		writeErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if !syncModeCodes[rule.Mode] {
		writeErr(w, http.StatusBadRequest, "未知匹配模式")
		return
	}
	matched := s.sync.Preview(rule)
	writeJSON(w, http.StatusOK, map[string]any{
		"matched": matched,
		"total":   len(matched),
	})
}

// ---------------- 远程主机证书同步 ----------------

func (s *Server) handleRemoteList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"hosts": s.store.ListRemoteHosts(),
	})
}

func (s *Server) handleRemoteSave(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Host         RemoteHost `json:"host"`
		KeepKey      bool       `json:"keep_key"`
		KeepPassword bool       `json:"keep_password"`
	}
	if err := readJSONLimit(w, r, &req, 128*1024); err != nil {
		writeErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	h := req.Host
	h.ID = strings.TrimSpace(h.ID)
	if h.ID == "" {
		h.ID = randToken(8)
	}
	h.Name = strings.TrimSpace(h.Name)
	h.Host = strings.TrimSpace(h.Host)
	h.User = strings.TrimSpace(h.User)
	h.RemoteDir = strings.TrimSpace(h.RemoteDir)
	h.Key = strings.TrimSpace(h.Key)
	if h.Port == 0 {
		h.Port = 22
	}
	// 只有显式 keep_* 才沿用旧凭证；空值本身表示「清空」，
	// 否则从密码认证切到私钥认证时旧密码会被无条件回填，导致两种凭证并存而保存失败。
	old, _ := s.store.GetRemoteHost(h.ID)
	if req.KeepKey {
		h.Key = old.Key
	}
	if req.KeepPassword {
		h.Password = old.Password
	}
	if h.Password != "" && !req.KeepKey && strings.TrimSpace(req.Host.Key) == "" {
		h.Key = ""
	}
	if h.Key != "" && !req.KeepPassword && strings.TrimSpace(req.Host.Password) == "" {
		h.Password = ""
	}
	if err := validateRemoteHost(h); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.PutRemoteHost(h); err != nil {
		writeErr(w, http.StatusInternalServerError, "保存失败: "+err.Error())
		return
	}
	s.store.Audit(sess(r).User, clientIP(r, s.cfg.TrustProxy), "remote_host_save", h.Name)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "host": s.store.ListRemoteHosts()})
}

func (s *Server) handleRemoteDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.DeleteRemoteHost(id); err != nil {
		writeErr(w, http.StatusInternalServerError, "删除失败")
		return
	}
	s.store.Audit(sess(r).User, clientIP(r, s.cfg.TrustProxy), "remote_host_delete", id)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleRemotePush 手动远程同步：与本地同步使用同一套规则匹配，
// 只推送规则命中且该规则选中的主机；不会把整个挂载目录一股脑推过去。
// 默认普通同步跳过内容未变化的文件；勾选 force 后忽略摘要全部重推。
func (s *Server) handleRemotePush(w http.ResponseWriter, r *http.Request) {
	var req struct {
		HostID    string `json:"host_id"`
		Force     bool   `json:"force"`
		ByContent bool   `json:"by_content"`
	}
	// 允许空 body；解析不出内容时按普通同步处理。
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req)
	// 按内容同步：读取目标机器上的证书文件，与面板已签名证书对比，
	// 命中的文件直接写入最新证书/私钥（写到目标机器上的对应文件名），
	// 不再把本地 /certs 里规则命中的文件整批推过去。
	if req.ByContent {
		s.handleRemotePushByContent(w, r, req.HostID, req.Force)
		return
	}
	if len(s.cfg.SyncDirs) == 0 {
		writeErr(w, http.StatusBadRequest, "未配置 ACME_PANEL_SYNC_DIR，没有可同步的本地证书目录")
		return
	}
	events := []SyncEvent{}
	skipped := 0
	matchedRules := 0
	for _, rule := range s.store.ListSyncRules() {
		// 规则没选远程主机 = 该规则不参与远程同步，避免推送到不相干的主机。
		if !rule.Enabled || len(rule.RemoteHosts) == 0 {
			continue
		}
		matched := s.sync.RuleMatchedFiles(rule)
		if len(matched) == 0 {
			continue
		}
		matchedRules++
		hosts := []string{}
		seenHost := map[string]bool{}
		for _, id := range rule.RemoteHosts {
			if seenHost[id] || (req.HostID != "" && req.HostID != id) {
				continue
			}
			seenHost[id] = true
			hosts = append(hosts, id)
		}
		for dir, names := range matched {
			for _, hostID := range hosts {
				// 路径只在 pushRemoteFiles 内拼接一次；这里传文件名，杜绝 /certs/certs。
				evs, skip := pushAllRemotesOnce(s.store, dir, names, req.Force, hostID)
				for i := range evs {
					evs[i].Rule = rule.Name + " → " + evs[i].Rule
				}
				events = append(events, evs...)
				skipped += skip
			}
		}
	}
	if len(events) > 0 {
		_ = s.store.AddSyncEvents(events)
	}
	detail := "普通远程同步（按规则）"
	if req.Force {
		detail = "强制远程同步（按规则）"
	}
	if req.HostID != "" {
		detail += " · " + req.HostID
	} else {
		detail += " · 规则选中的主机"
	}
	s.store.Audit(sess(r).User, clientIP(r, s.cfg.TrustProxy), "remote_push", detail)
	message := ""
	if matchedRules == 0 {
		message = "没有命中任何远程同步规则：请在同步规则的「远程主机」栏选择目标主机，并确认规则能匹配到本地证书"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "events": events, "remote_events": events,
		"force": req.Force, "skipped": skipped, "matched_rules": matchedRules, "message": message,
	})
}

// handleRemotePushByContent 按「目标机器现有证书内容」同步：
// 逐台主机列出远程证书目录，读取证书文件里的 CN/SAN 与面板已签名证书对比，
// 命中的文件用面板最新的证书/私钥覆盖（写到目标文件自己的名字上）。
// 主机配置了「负责的域名」时，同样按域名过滤，避免把 A 主机的证书写到 B 主机。
func (s *Server) handleRemotePushByContent(w http.ResponseWriter, r *http.Request, hostID string, force bool) {
	events := []SyncEvent{}
	skipped := 0
	matchedFiles := 0
	for _, view := range s.store.ListRemoteHosts() {
		if !view.Enabled || (hostID != "" && view.ID != hostID) {
			continue
		}
		h, err := s.store.GetRemoteHost(view.ID)
		if err != nil {
			continue
		}
		files, _, err := listRemoteFiles(s.store, h, h.RemoteDir)
		if err != nil {
			events = append(events, SyncEvent{
				Time: time.Now().Format(time.RFC3339), Scope: "remote",
				Rule: "按证书内容同步 · " + h.Name, Result: "fail", Detail: err.Error(),
			})
			continue
		}
		names := make([]string, 0, len(files))
		for _, f := range files {
			if !f.IsDir {
				names = append(names, f.Name)
			}
		}
		contents, err := readRemoteCertFiles(s.store, h, names)
		if err != nil {
			events = append(events, SyncEvent{
				Time: time.Now().Format(time.RFC3339), Scope: "remote",
				Rule: "按证书内容同步 · " + h.Name, Result: "fail", Detail: err.Error(),
			})
			continue
		}
		all, _ := s.sync.certs.Scan()
		matches := matchRemoteCerts(names, contents, all)
		// 按主机负责域名过滤：用「证书内容里的域名」判断归属，不用文件名——
		// 文件名只是目标机器上的存放名，不能代表它属于哪个域名。
		for name, m := range matches {
			if !hostWantsDomain(h, m.Domain) {
				delete(matches, name)
			}
		}
		if len(matches) == 0 {
			continue
		}
		matchedFiles += len(matches)
		evs, skip := pushMatchedToRemote(s.store, s.sync.certs, h, matches, force, names...)
		events = append(events, evs...)
		skipped += skip
	}
	if len(events) > 0 {
		_ = s.store.AddSyncEvents(events)
	}
	detail := "远程同步（按目标证书内容对比）"
	if force {
		detail = "强制远程同步（按目标证书内容对比）"
	}
	s.store.Audit(sess(r).User, clientIP(r, s.cfg.TrustProxy), "remote_push", detail)
	message := ""
	if matchedFiles == 0 && len(events) == 0 {
		message = "目标机器上没有找到与面板已签名证书内容匹配的证书文件：请确认主机配置、远程目录，以及目标证书确实由面板签发"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "events": events, "remote_events": events,
		"force": force, "by_content": true, "skipped": skipped,
		"matched_files": matchedFiles, "message": message,
	})
}

// handleRemoteFiles 列出指定远程主机目录里的文件，供页面展示。
// 目录一律取主机配置里的 remote_dir，不接受前端自定义目录（避免越权读取任意路径）。
func (s *Server) handleRemoteFiles(w http.ResponseWriter, r *http.Request) {
	var req struct {
		HostID string `json:"host_id"`
		Dir    string `json:"dir"` // 兼容旧客户端：字段保留但值被忽略
	}
	if err := readJSONLimit(w, r, &req, 8192); err != nil {
		writeErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	req.HostID = strings.TrimSpace(req.HostID)
	if req.HostID == "" {
		writeErr(w, http.StatusBadRequest, "请先选择远程主机")
		return
	}
	h, err := s.store.GetRemoteHost(req.HostID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "远程主机不存在")
		return
	}
	if strings.TrimSpace(h.RemoteDir) == "" {
		writeErr(w, http.StatusBadRequest, "这台主机还没有配置远程目录，请先编辑主机")
		return
	}
	_ = req.Dir // 只认主机配置，忽略请求里带的目录
	files, dir, err := listRemoteFiles(s.store, h, h.RemoteDir)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	names := make([]string, 0, len(files))
	for _, f := range files {
		if !f.IsDir {
			names = append(names, f.Name)
		}
	}
	// 类型标注与同步匹配是两件事，互不牵连：
	// ① 标注：读文件自身内容，是证书/私钥就标注，并给出它签的域名——
	//    面板没签发同名证书不影响标注（例如目标机上的第三方证书仍需看得见）。
	// ② 同步：只有内容与面板已签发证书对得上的文件才进入 contentMatches，
	//    绝不用同步规则或文件名推断，避免把无关文件写坏。
	kinds := map[string]string{}
	fileDomains := map[string][]string{}
	contentMatches := map[string]RemoteCertMatch{}
	if contents, err := readRemoteAllPEMFiles(s.store, h, names); err == nil {
		for name, data := range contents {
			kind, domains := detectRemoteFileInfo(data)
			if kind != "" {
				kinds[name] = kind
			}
			if len(domains) > 0 {
				fileDomains[name] = domains
			}
		}
		// 同步匹配用同一批内容（私钥读出来也没有证书块，不会误命中）。
		all, _ := s.sync.certs.Scan()
		contentMatches = matchRemoteCerts(names, contents, all)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "host": h.Name, "dir": dir, "files": files,
		"matched_kinds": kinds, "file_domains": fileDomains,
		"content_matches": contentMatches,
	})
}

func (s *Server) handleRemoteTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Host         RemoteHost `json:"host"`
		KeepKey      bool       `json:"keep_key"`
		KeepPassword bool       `json:"keep_password"`
	}
	if err := readJSONLimit(w, r, &req, 128*1024); err != nil {
		writeErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	h := req.Host
	if h.Port == 0 {
		h.Port = 22
	}
	// 与保存接口一致：空凭证就是清空，只有 keep_* 才沿用旧值。
	if req.KeepKey {
		if old, err := s.store.GetRemoteHost(h.ID); err == nil {
			h.Key = old.Key
		}
	}
	if req.KeepPassword {
		if old, err := s.store.GetRemoteHost(h.ID); err == nil {
			h.Password = old.Password
		}
	}
	if h.Password != "" && !req.KeepKey && strings.TrimSpace(req.Host.Key) == "" {
		h.Key = ""
	}
	if h.Key != "" && !req.KeepPassword && strings.TrimSpace(req.Host.Password) == "" {
		h.Password = ""
	}
	if err := testRemoteHost(s.store, h); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "msg": "连接成功"})
}
