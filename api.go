package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
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
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
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
			s.clearCookie(w)
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

func (s *Server) setCookie(w http.ResponseWriter, id string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.CookieSecure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(12 * time.Hour / time.Second),
	})
}

func (s *Server) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.CookieSecure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

// ---------------- 登录 ----------------

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
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
	sess := s.sess.Create(s.store.Username(), ip, r.UserAgent())
	s.setCookie(w, sess.ID)
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
	s.clearCookie(w)
	s.store.Audit(sess.User, clientIP(r, s.cfg.TrustProxy), "logout", "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	sess := sess(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"user":          sess.User,
		"csrf":          sess.CSRF,
		"acme_version":  s.acme.Version(r.Context()),
		"acme_home":     s.cfg.AcmeHome,
		"default_ca":    s.cfg.DefaultCA,
		"default_email": s.store.DefaultEmail(),
		"cookie_secure": s.cfg.CookieSecure,
		"tls":           s.cfg.TLSCert != "",
		"cron":          s.cfg.Cron,
		"server_time":   time.Now().UTC(),
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
	writeJSON(w, http.StatusOK, map[string]any{
		"total":      len(certs),
		"valid":      valid,
		"warning":    warning,
		"expired":    expired,
		"next":       next,
		"jobs":       s.jobs.List()[:minInt(5, len(s.jobs.List()))],
		"acme":       s.acme.Version(r.Context()),
		"version":    appVersion,
		"uptime_sec": int(time.Since(s.boot).Seconds()),
	})
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
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
	s.notify.Send("security_alert", "🔑 私钥被查看", fmt.Sprintf(
		"用户 %s 从 %s 查看了证书 %s 的私钥，已记录审计。", sess.User, ip, name))
	writeJSON(w, http.StatusOK, map[string]any{
		"name": name,
		"pem":  pemStr,
	})
}

// ---------------- 签发 / 续期 / 吊销 / 删除 ----------------

type issueReq struct {
	Domains    []string          `json:"domains"`
	Credential string            `json:"credential"` // 已保存凭证名
	Code       string            `json:"code"`       // 或直接指定 provider 类型
	Env        map[string]string `json:"env"`        // 临时凭证（不落盘）
	SaveAs     string            `json:"save_as"`    // 可选：同时保存为新凭证
	KeyLength  string            `json:"keylength"`
	CA         string            `json:"ca"`
	Force      bool              `json:"force"`
	Email      string            `json:"email"` // 该域名专用的 ACME 通知邮箱；留空用默认
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
	ca := req.CA
	if ca == "" {
		ca = s.cfg.DefaultCA
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
		if _, ok := providerByCode[code]; !ok {
			writeErr(w, http.StatusBadRequest, "已保存凭证类型不受支持")
			return
		}
	} else {
		code = req.Code
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

	args := []string{"--issue", "--dns", code}
	if email != "" {
		args = append(args, "--accountemail", email)
	}
	if req.KeyLength != "" {
		args = append(args, "--keylength", req.KeyLength)
	}
	if ca != "letsencrypt" {
		args = append(args, "--server", ca)
	}
	if req.Force {
		args = append(args, "--force")
	}
	for _, d := range domains {
		args = append(args, "-d", d)
	}

	preview := "acme.sh --issue --dns " + code
	for _, d := range domains {
		preview += " -d " + d
	}
	job := s.jobs.Start("issue", "签发 "+domains[0], domains[0], preview, env, args)
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
		go func(j *Job) {
			for i := 0; i < 300; i++ {
				if cur := s.jobs.Get(j.ID); cur != nil && (cur.Status == "success" || cur.Status == "failed" || cur.Status == "canceled") {
					break
				}
				time.Sleep(200 * time.Millisecond)
			}
			if err := s.certs.Purge(name); err == nil {
				s.jobs.push(j, "✓ 已删除目录 "+name)
			} else {
				s.jobs.push(j, "✗ 删除目录失败: "+err.Error())
			}
		}(job)
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
		Code string `json:"code"`
		Name string `json:"name"`
	}
	cas := []caItem{
		{"letsencrypt", "Let's Encrypt"},
		{"letsencrypt_test", "Let's Encrypt (测试环境)"},
		{"zerossl", "ZeroSSL"},
		{"buypass", "Buypass"},
		{"google", "Google Trust Services"},
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"providers":  providerCatalog,
		"cas":        cas,
		"default_ca": s.cfg.DefaultCA,
		"keylengths": []string{"ec-256", "ec-384", "2048", "4096"},
		"version":    appVersion,
		"cookie_sec": s.cfg.CookieSecure,
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
	env, err := filterEnv(req.Code, req.Env)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.PutProvider(req.Name, req.Code, env); err != nil {
		writeErr(w, http.StatusInternalServerError, "保存失败")
		return
	}
	s.store.Audit(sess(r).User, clientIP(r, s.cfg.TrustProxy), "provider_save", req.Name+" / "+req.Code)
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

func (s *Server) handleCancelJob(w http.ResponseWriter, r *http.Request) {
	if !s.jobs.Cancel(r.PathValue("id")) {
		writeErr(w, http.StatusBadRequest, "任务无法取消")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
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

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"entries": s.store.AuditTail(200)})
}

// ---------------- 通知渠道与邮箱 ----------------

func (s *Server) handleNotifyCatalog(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"events":        notifyEvents,
		"kinds":         notifierKinds,
		"default_email": s.store.DefaultEmail(),
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
	if !s.store.CheckPassword(req.Old) {
		s.limit.Fail(clientIP(r, s.cfg.TrustProxy) + "|pwd")
		s.store.Audit(sess.User, clientIP(r, s.cfg.TrustProxy), "password_change_failed", "旧密码错误")
		s.notify.Send("security_alert", "⚠ 修改密码失败", fmt.Sprintf(
			"用户 %s 从 %s 尝试修改密码但原密码错误。", sess.User, clientIP(r, s.cfg.TrustProxy)))
		writeErr(w, http.StatusForbidden, "原密码错误")
		return
	}
	if len(req.New) < 8 {
		writeErr(w, http.StatusBadRequest, "新密码至少 8 位")
		return
	}
	if err := s.store.SetPassword(req.New); err != nil {
		writeErr(w, http.StatusInternalServerError, "修改密码失败")
		return
	}
	n := s.sess.DeleteUserExcept(sess.User, sess.ID)
	s.store.Audit(sess.User, clientIP(r, s.cfg.TrustProxy), "password_change", fmt.Sprintf("其它会话已失效: %d", n))
	s.notify.Send("security_alert", "✅ 登录密码已修改", fmt.Sprintf(
		"用户 %s 从 %s 修改了登录密码，其它 %d 个会话已失效。", sess.User, clientIP(r, s.cfg.TrustProxy), n))
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
		"needs_restart": !s.sync.Enabled(),
	})
}

func (s *Server) handleSyncRules(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"rules":  s.store.ListSyncRules(),
		"events": s.store.ListSyncEvents(),
	})
}

func (s *Server) handleSyncSave(w http.ResponseWriter, r *http.Request) {
	var rule SyncRule
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&rule); err != nil {
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

func (s *Server) handleSyncEvents(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"events": s.store.ListSyncEvents()})
}

func (s *Server) handleSyncRun(w http.ResponseWriter, r *http.Request) {
	if !s.sync.Enabled() {
		writeErr(w, http.StatusBadRequest, "未配置 ACME_PANEL_SYNC_DIR，无法同步")
		return
	}
	events := s.sync.run("手动触发")
	s.store.Audit(sess(r).User, clientIP(r, s.cfg.TrustProxy), "sync_run", "")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "events": events})
}

// handleSyncPreview 只计算规则会命中哪些文件，不写入任何内容。
func (s *Server) handleSyncPreview(w http.ResponseWriter, r *http.Request) {
	var rule SyncRule
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&rule); err != nil {
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
