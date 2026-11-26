package main

// v0.1.71 新增能力：
//   - 到期看板批量续期（复用单证书续期的参数组装，避免逻辑分叉）
//   - ACME 账户管理增强（切换默认 CA、密码二次确认后导出账户密钥）
//   - 维护窗口 / 通知静默（按星期与时段暂停推送，关键安全事件可放行）
//
// 安全约束：
//   - 账户密钥导出必须校验当前登录密码，且路径严格限制在 ACME_HOME 内；
//   - 静默窗口只影响自动通知，手动「发送测试」不受影响；
//   - 所有配置变更写入审计与 Diff，导出行为单独记审计。

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ---------------- 数据模型 ----------------

// QuietHours 描述通知静默窗口。Days 为 0=周日 … 6=周六；空表示每天。
// StartHour > EndHour 表示跨午夜窗口（例如 22 点到次日 7 点）。
type QuietHours struct {
	Enabled       bool  `json:"enabled"`
	StartHour     int   `json:"start_hour"`     // 0-23
	EndHour       int   `json:"end_hour"`       // 0-23
	Days          []int `json:"days"`           // 空=每天
	AllowCritical bool  `json:"allow_critical"` // 静默期仍放行 security_alert
}

// ---------------- Store 新方法 ----------------

func (s *Store) SetQuietHours(q QuietHours) error {
	q.StartHour = clampInt(q.StartHour, 0, 23)
	q.EndHour = clampInt(q.EndHour, 0, 23)
	days := []int{}
	seen := map[int]bool{}
	for _, d := range q.Days {
		if d >= 0 && d <= 6 && !seen[d] {
			seen[d] = true
			days = append(days, d)
		}
	}
	sort.Ints(days)
	q.Days = days
	return s.mutateState(func(st *State) { st.QuietHours = q })
}

func (s *Store) SetDefaultCAOverride(ca string) error {
	return s.mutateState(func(st *State) { st.DefaultCAOverride = ca })
}

// ---------------- CA 解析 ----------------

// effectiveCA 返回面板当前实际使用的默认 CA。环境变量显式指定时优先级最高，
// 防止界面切换与运维侧配置互相覆盖。
func (s *Server) effectiveCA() string {
	if env("ACME_PANEL_CA", "") != "" {
		return s.cfg.DefaultCA
	}
	ca := s.store.Snapshot().DefaultCAOverride
	if ca != "" {
		if _, ok := allowedCA[ca]; ok {
			return ca
		}
	}
	return s.cfg.DefaultCA
}

// ---------------- 静默窗口判断 ----------------

// inQuietWindow 判断给定时间是否落在静默窗口内。窗口边界为 [start, end)，
// 跨午夜窗口按「>=start 或 <end」处理。Days 为空表示每天。
func inQuietWindow(q QuietHours, now time.Time) bool {
	if !q.Enabled {
		return false
	}
	h := now.Hour()
	if q.StartHour == q.EndHour {
		return false // 零长度窗口视为不启用，避免误伤全天
	}
	crossMidnight := q.StartHour > q.EndHour
	if len(q.Days) > 0 {
		// 跨午夜窗口的后半夜属于「起始日的次日」，按起始日匹配星期，
		// 否则只勾周五时，周六凌晨 02:00 会意外脱离静默期。
		wd := int(now.Weekday())
		if crossMidnight && h < q.EndHour {
			wd = (wd + 6) % 7
		}
		hit := false
		for _, d := range q.Days {
			if d == wd {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	if !crossMidnight {
		return h >= q.StartHour && h < q.EndHour
	}
	return h >= q.StartHour || h < q.EndHour
}

// quietAllows 决定某事件在静默期是否仍可发送。security_alert 默认放行，
// 除非用户显式关闭 AllowCritical。SendTest 不经过此方法。
func quietAllows(q QuietHours, event string) bool {
	if !q.AllowCritical {
		return false
	}
	return event == "security_alert" || event == "issue_failed" || event == "renew_failed"
}

// ---------------- 账户密钥路径 ----------------

var accountFileRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

// resolveAccountKeyPath 根据账户配置文件名推导账户私钥路径，并严格限制在
// ACME_HOME 内（含符号链接解析），防止通过账户 ID 越界读取任意文件。
func resolveAccountKeyPath(home, id string) (string, error) {
	if !accountFileRe.MatchString(id) || strings.Contains(id, "..") || !strings.HasSuffix(id, "account.conf") {
		return "", fmt.Errorf("非法账户 ID")
	}
	root, err := filepath.Abs(home)
	if err != nil {
		return "", err
	}
	if resolved, e := filepath.EvalSymlinks(root); e == nil {
		root = resolved
	}
	prefix := strings.TrimSuffix(id, "account.conf") // "letsencrypt_" 或 ""
	base := strings.Trim(prefix, "_")
	candidates := []string{
		prefix + "account.key",
		filepath.Join(base, "account.key"),
		filepath.Join("ca", base, "account.key"),
	}
	for _, rel := range candidates {
		p := filepath.Join(root, rel)
		resolved, err := filepath.EvalSymlinks(p)
		if err != nil {
			continue
		}
		rel2, err := filepath.Rel(root, resolved)
		if err != nil || strings.HasPrefix(rel2, "..") || filepath.IsAbs(rel2) {
			continue
		}
		st, err := os.Stat(resolved)
		if err != nil || st.IsDir() || st.Size() > 1<<20 {
			continue
		}
		return resolved, nil
	}
	return "", fmt.Errorf("未找到该账户的私钥文件（已检查 %d 个常见路径）", len(candidates))
}

// ---------------- 批量续期请求 ----------------

type renewBatchReq struct {
	Names []string `json:"names"`
	Force bool     `json:"force"`
}

func normalizeRenewNames(names []string) ([]string, error) {
	out := []string{}
	seen := map[string]bool{}
	for _, raw := range names {
		// acme.sh 证书目录名恒为小写；统一大小写后再去重与查表，
		// 避免 "A.com" 与 "a.com" 被当成两张证书。
		n := strings.ToLower(strings.TrimSpace(raw))
		if n == "" {
			continue
		}
		if !validCertName(n) {
			return nil, fmt.Errorf("非法证书名：%s", n)
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("请至少选择一张证书")
	}
	if len(out) > 50 {
		return nil, fmt.Errorf("单批最多续期 50 张证书")
	}
	return out, nil
}

// renewArgsFor 复用与单证书续期完全一致的参数顺序，避免两处逻辑漂移。
func renewArgsFor(domain string, isECC, force bool) []string {
	args := []string{"--renew", "-d", domain}
	if isECC {
		args = append(args, "--ecc")
	}
	if force {
		args = append(args, "--force")
	}
	return args
}

// ---------------- 请求处理器 ----------------

// handleExpiryRenewBatch 从到期看板批量排队续期；不存在的证书会被跳过并在响应中列出。
func (s *Server) handleExpiryRenewBatch(w http.ResponseWriter, r *http.Request) {
	var req renewBatchReq
	if err := readJSON(w, r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	names, err := normalizeRenewNames(req.Names)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	type item struct {
		ID     string `json:"id"`
		Domain string `json:"domain"`
		Name   string `json:"name"`
	}
	jobs := []item{}
	skipped := []string{}
	for _, name := range names {
		ci, err := s.certs.Get(name)
		if err != nil {
			skipped = append(skipped, name)
			continue
		}
		args := renewArgsFor(ci.Domain, ci.IsECC, req.Force)
		preview := "acme.sh --renew -d " + ci.Domain
		if ci.IsECC {
			preview += " --ecc"
		}
		if req.Force {
			preview += " --force"
		}
		j := s.jobs.Start("renew", "批量续期 "+ci.Domain, ci.Domain, preview, nil, args)
		jobs = append(jobs, item{ID: j.ID, Domain: ci.Domain, Name: name})
	}
	s.store.Audit(sess(r).User, clientIP(r, s.cfg.TrustProxy), "renew_batch",
		fmt.Sprintf("queued=%d skipped=%d force=%t", len(jobs), len(skipped), req.Force))
	writeJSON(w, http.StatusAccepted, map[string]any{
		"jobs": jobs, "queued": len(jobs), "skipped": skipped, "force": req.Force,
	})
}

// handleQuietHours 返回静默窗口配置与当前是否处于窗口内。
func (s *Server) handleQuietHours(w http.ResponseWriter, r *http.Request) {
	q := s.store.Snapshot().QuietHours
	now := time.Now()
	writeJSON(w, http.StatusOK, map[string]any{
		"quiet_hours": q,
		"active":      inQuietWindow(q, now),
		"now":         now,
	})
}

func (s *Server) handleQuietHoursSave(w http.ResponseWriter, r *http.Request) {
	var req QuietHours
	if err := readJSON(w, r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	before := jsonSnapshot(s.store.Snapshot().QuietHours)
	if err := s.store.SetQuietHours(req); err != nil {
		writeErr(w, http.StatusInternalServerError, "保存失败: "+err.Error())
		return
	}
	// 记录实际落盘的规范化值（小时已 clamp、星期已去重排序），避免审计失真。
	stored := s.store.Snapshot().QuietHours
	s.recordDiff(r, "quiet_hours_save", "notification", before, jsonSnapshot(stored))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "quiet_hours": stored})
}

// handleDefaultCASet 切换面板默认 CA；环境变量锁定时拒绝。
func (s *Server) handleDefaultCASet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CA string `json:"ca"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	ca := strings.TrimSpace(req.CA)
	if _, ok := allowedCA[ca]; !ok {
		writeErr(w, http.StatusBadRequest, "不支持的 CA")
		return
	}
	if env("ACME_PANEL_CA", "") != "" {
		writeErr(w, http.StatusConflict, "默认 CA 已由环境变量 ACME_PANEL_CA 锁定，请在部署配置中修改")
		return
	}
	before := s.effectiveCA()
	if err := s.store.SetDefaultCAOverride(ca); err != nil {
		writeErr(w, http.StatusInternalServerError, "保存失败: "+err.Error())
		return
	}
	s.recordDiff(r, "default_ca_set", "acme", before, ca)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "default_ca": ca})
}

// handleACMEAccountKey 导出账户私钥：必须提供当前登录密码，导出行为单独审计。
func (s *Server) handleACMEAccountKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID       string `json:"id"`
		Password string `json:"password"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if !s.store.CheckPassword(req.Password) {
		s.store.Audit(sess(r).User, clientIP(r, s.cfg.TrustProxy), "account_key_denied", req.ID)
		writeErr(w, http.StatusForbidden, "密码校验失败")
		return
	}
	path, err := resolveAccountKeyPath(s.cfg.AcmeHome, strings.TrimSpace(req.ID))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取账户私钥失败: "+err.Error())
		return
	}
	s.store.Audit(sess(r).User, clientIP(r, s.cfg.TrustProxy), "account_key_export", req.ID)
	w.Header().Set("Content-Type", "application/x-pem-file; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", `attachment; filename="`+strings.TrimSuffix(req.ID, ".conf")+`.key"`)
	_, _ = w.Write(b)
}

// caOptions 给前端返回可切换的 CA 列表（字母序）。
func caOptions() []map[string]string {
	keys := make([]string, 0, len(allowedCA))
	for k := range allowedCA {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]map[string]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, map[string]string{"value": k, "label": k})
	}
	return out
}
