package main

// v0.1.70 新增 API handler。按功能分组，所有写操作统一记录配置 Diff 与审计。

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"
)

// ---------------- 会话管理 ----------------

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	cur := sess(r)
	list := s.sess.List()
	out := make([]map[string]any, 0, len(list))
	for _, v := range list {
		out = append(out, map[string]any{
			"id":         v.ID,
			"user":       v.User,
			"ip":         v.IP,
			"ua":         v.UA,
			"created":    v.Created,
			"last_seen":  v.LastSeen,
			"long_lived": v.LongLived,
			"current":    v.ID == cur.ID,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sessions":      out,
		"idle_minutes":  int(s.sess.idle.Minutes()),
		"life_hours":    int(s.sess.life.Hours()),
		"remember_idle": 30 * 24 * 60,
		"remember_life": 90 * 24,
		"total":         len(out),
	})
}

func (s *Server) handleSessionRevoke(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	cur := sess(r)
	if id == cur.ID {
		writeErr(w, http.StatusBadRequest, "不能下线当前会话，请使用「退出登录」")
		return
	}
	if !s.sess.Exists(id) {
		writeErr(w, http.StatusNotFound, "会话不存在或已过期")
		return
	}
	s.sess.Delete(id)
	s.store.Audit(cur.User, clientIP(r, s.cfg.TrustProxy), "session_revoke", id[:minLen(id, 12)])
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleSessionsRevokeOthers(w http.ResponseWriter, r *http.Request) {
	cur := sess(r)
	n := s.sess.DeleteUserExcept(cur.User, cur.ID)
	s.store.Audit(cur.User, clientIP(r, s.cfg.TrustProxy), "session_revoke_all", fmt.Sprintf("kicked=%d", n))
	writeJSON(w, http.StatusOK, map[string]any{"kicked": n})
}

func minLen(s string, n int) int {
	if len(s) < n {
		return len(s)
	}
	return n
}

// ---------------- IP / CIDR 白名单 ----------------

func (s *Server) handleIPAllowlist(w http.ResponseWriter, r *http.Request) {
	st := s.store.Snapshot()
	_, err := parseCIDRList(st.IPAllowlist)
	invalidMsg := ""
	if err != nil {
		// 错误详情只给已登录用户看，不暴露给入口中间件的拒绝响应。
		invalidMsg = err.Error()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"entries":     st.IPAllowlist,
		"allow_local": st.AllowLocalBypass,
		"current_ip":  clientIP(r, s.cfg.TrustProxy),
		"trust_proxy": s.cfg.TrustProxy,
		"trust_hops":  s.cfg.TrustHops,
		"configured":  len(st.IPAllowlist) > 0,
		"valid":       err == nil,
		"invalid_msg": invalidMsg,
	})
}

func (s *Server) handleIPAllowlistSave(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Entries    []string `json:"entries"`
		AllowLocal *bool    `json:"allow_local"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	clean := []string{}
	for _, raw := range req.Entries {
		v := strings.TrimSpace(raw)
		if v != "" {
			clean = append(clean, v)
		}
	}
	if len(clean) > 200 {
		writeErr(w, http.StatusBadRequest, "最多允许 200 条 CIDR 条目")
		return
	}
	if _, err := parseCIDRList(clean); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	beforeSt := s.store.Snapshot()
	if req.AllowLocal != nil {
		if err := s.store.SetAllowLocalBypass(*req.AllowLocal); err != nil {
			writeErr(w, http.StatusInternalServerError, "保存失败")
			return
		}
	}
	if err := s.store.SetIPAllowlist(clean); err != nil {
		writeErr(w, http.StatusInternalServerError, "保存失败")
		return
	}
	afterSt := s.store.Snapshot()
	s.recordDiff(r, "ip_allowlist_save", "安全",
		jsonSnapshot(map[string]any{"entries": beforeSt.IPAllowlist, "allow_local": beforeSt.AllowLocalBypass}),
		jsonSnapshot(map[string]any{"entries": afterSt.IPAllowlist, "allow_local": afterSt.AllowLocalBypass}))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "entries": clean})
}

func (s *Server) handleIPAllowlistTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP string `json:"ip"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	st := s.store.Snapshot()
	ip := strings.TrimSpace(req.IP)
	if ip == "" {
		ip = clientIP(r, s.cfg.TrustProxy)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ip":      ip,
		"allowed": ipAllowed(ip, st.IPAllowlist, st.AllowLocalBypass),
	})
}

// ---------------- 一键健康自检 ----------------

var caDirectoryURL = map[string]string{
	"letsencrypt":      "https://acme-v02.api.letsencrypt.org/directory",
	"letsencrypt_test": "https://acme-staging-v02.api.letsencrypt.org/directory",
	"zerossl":          "https://acme.zerossl.com/v2/DV90/directory",
	"buypass":          "https://api.buypass.com/acme/directory",
	"google":           "https://dv.acme-v02.api.pki.goog/directory",
}

func (s *Server) runHealthCheck() HealthReport {
	rep := HealthReport{TS: time.Now(), Checks: []HealthCheck{}}
	add := func(name, status, detail string) {
		rep.Checks = append(rep.Checks, HealthCheck{Name: name, Status: status, Detail: detail})
	}

	// 1. acme.sh 可执行
	if st, err := os.Stat(s.cfg.AcmeBin); err != nil {
		add("acme.sh", "fail", "未找到 acme.sh："+err.Error())
	} else if st.IsDir() || st.Mode()&0o111 == 0 {
		add("acme.sh", "fail", "acme.sh 不可执行，请检查挂载与权限")
	} else {
		add("acme.sh", "ok", "可执行文件正常")
	}

	// 2. 数据目录可写
	probe := filepath.Join(s.cfg.DataDir, ".health-probe")
	if err := os.WriteFile(probe, []byte("ok"), 0o600); err != nil {
		add("数据目录", "fail", "不可写："+err.Error())
	} else {
		_ = os.Remove(probe)
		add("数据目录", "ok", "可读写")
	}

	// 3. 同步目录
	if len(s.cfg.SyncDirs) == 0 {
		add("同步目录", "warn", "未配置 ACME_PANEL_SYNC_DIR，本地同步不可用")
	} else {
		bad := []string{}
		for _, dir := range s.cfg.SyncDirs {
			p := filepath.Join(dir, ".health-probe")
			if err := os.WriteFile(p, []byte("ok"), 0o600); err != nil {
				bad = append(bad, dir+": "+err.Error())
			} else {
				_ = os.Remove(p)
			}
		}
		if len(bad) > 0 {
			add("同步目录", "fail", strings.Join(bad, "；"))
		} else {
			add("同步目录", "ok", fmt.Sprintf("%d 个目录均可写", len(s.cfg.SyncDirs)))
		}
	}

	// 4. CA 连通性与系统时间偏差
	url := caDirectoryURL[s.effectiveCA()]
	if url == "" {
		add("CA 连通", "warn", "未识别的 CA："+s.effectiveCA())
	} else {
		client := &http.Client{Timeout: 6 * time.Second}
		resp, err := client.Get(url)
		if err != nil {
			add("CA 连通", "fail", "无法连接 "+url+"："+err.Error())
		} else {
			_ = resp.Body.Close()
			add("CA 连通", "ok", fmt.Sprintf("%s 返回 %d", s.effectiveCA(), resp.StatusCode))
			if ds := resp.Header.Get("Date"); ds != "" {
				if t, e := http.ParseTime(ds); e == nil {
					delta := time.Since(t)
					if delta < 0 {
						delta = -delta
					}
					if delta > 5*time.Minute {
						add("系统时间", "fail", fmt.Sprintf("与 CA 服务器时间相差 %.1f 分钟，会导致签发失败", delta.Minutes()))
					} else if delta > 2*time.Minute {
						add("系统时间", "warn", fmt.Sprintf("与 CA 服务器时间相差 %.1f 分钟", delta.Minutes()))
					} else {
						add("系统时间", "ok", "与 CA 服务器时间同步")
					}
				}
			}
		}
	}

	// 5. DNS 凭证可解密
	providers := s.store.ListProviders()
	if len(providers) == 0 {
		add("DNS 凭证", "warn", "尚未保存任何 DNS 凭证")
	} else {
		okCount := 0
		for _, p := range providers {
			if _, _, err := s.store.GetProvider(p.Name); err == nil {
				okCount++
			}
		}
		if okCount == 0 {
			add("DNS 凭证", "fail", "凭证存在但无法解密，请检查 secret.key 是否一致")
		} else {
			add("DNS 凭证", "ok", fmt.Sprintf("%d/%d 个凭证可用", okCount, len(providers)))
		}
	}

	// 6. 证书目录可读性
	certs, err := s.certs.Scan()
	if err != nil {
		add("证书目录", "fail", "读取失败："+err.Error())
	} else {
		add("证书目录", "ok", fmt.Sprintf("识别到 %d 张证书", len(certs)))
	}

	rep.Overall = "ok"
	for _, c := range rep.Checks {
		if c.Status == "fail" {
			rep.Overall = "fail"
		} else if c.Status == "warn" && rep.Overall == "ok" {
			rep.Overall = "warn"
		}
	}
	s.store.AddHealthReport(rep)
	return rep
}

func (s *Server) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	rep := s.runHealthCheck()
	s.store.Audit(sess(r).User, clientIP(r, s.cfg.TrustProxy), "health_check", rep.Overall)
	writeJSON(w, http.StatusOK, rep)
}

func (s *Server) handleHealthHistory(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"history": s.store.RecentHealthReports(20),
	})
}

// ---------------- 证书到期风险看板 ----------------

func (s *Server) handleExpiry(w http.ResponseWriter, r *http.Request) {
	certs, err := s.certs.Scan()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取证书失败: "+err.Error())
		return
	}
	sort.Slice(certs, func(i, j int) bool { return certs[i].DaysLeft < certs[j].DaysLeft })
	groups := map[string][]CertInfo{
		"expired":  {},
		"critical": {},
		"warning":  {},
		"valid":    {},
	}
	counts := map[string]int{"expired": 0, "critical": 0, "warning": 0, "valid": 0}
	for _, c := range certs {
		key := "valid"
		if c.DaysLeft < 0 {
			key = "expired"
		} else if c.DaysLeft <= 7 {
			key = "critical"
		} else if c.DaysLeft <= 30 {
			key = "warning"
		}
		groups[key] = append(groups[key], c)
		counts[key]++
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"total":  len(certs),
		"counts": counts,
		"groups": groups,
		"now":    time.Now(),
	})
}

// ---------------- 自动备份：配置、列表、手动执行、读取、删除 ----------------

func (s *Server) handleBackupSettings(w http.ResponseWriter, r *http.Request) {
	st := s.store.Snapshot()
	writeJSON(w, http.StatusOK, st.AutoBackup)
}

func (s *Server) handleBackupSettingsSave(w http.ResponseWriter, r *http.Request) {
	var req AutoBackupConfig
	if err := readJSON(w, r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if !validInterval(req.Interval) {
		writeErr(w, http.StatusBadRequest, "间隔只能是 daily 或 weekly")
		return
	}
	before := s.store.Snapshot().AutoBackup
	req.Hour = clampInt(req.Hour, 0, 23)
	req.Keep = clampInt(req.Keep, 1, 50)
	if err := s.store.SetAutoBackup(req); err != nil {
		writeErr(w, http.StatusInternalServerError, "保存失败")
		return
	}
	s.recordDiff(r, "auto_backup_save", "备份", jsonSnapshot(before), jsonSnapshot(req))
	writeJSON(w, http.StatusOK, req)
}

func (s *Server) handleBackupList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"records": s.store.ListBackups(50),
		"config":  s.store.Snapshot().AutoBackup,
	})
}

// createBackup 生成一份配置备份文件（不含登录凭据与 secret.key），并写入记录表。
// includeCerts=true 时把证书目录一并打包进 tar.gz。
func (s *Server) createBackup(kind string, includeCerts bool) (BackupRecord, error) {
	st := s.store.Snapshot()
	st.Username = ""
	st.Salt = ""
	st.Hash = ""
	st.Iter = 0
	st.CredSource = ""
	st.APITokens = nil // 令牌哈希不随备份外带，避免离线撞库

	payload := BackupFile{
		Format:     backupFormat,
		Version:    backupVersion,
		AppVersion: appVersion,
		ExportedAt: time.Now(),
		State:      st,
	}
	b, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return BackupRecord{}, err
	}
	name := "backup-" + time.Now().UTC().Format("20060102T150405") + "-" + randToken(6) + ".json"
	path, err := s.backupPath(name)
	if err != nil {
		return BackupRecord{}, err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return BackupRecord{}, err
	}
	var archiveErr error
	if includeCerts {
		tgzName := strings.TrimSuffix(name, ".json") + "-certs.tar.gz"
		var tgzPath string
		tgzPath, archiveErr = s.backupPath(tgzName)
		if archiveErr == nil {
			var f *os.File
			f, archiveErr = os.Create(tgzPath)
			if archiveErr == nil {
				gz := gzip.NewWriter(f)
				tw := tar.NewWriter(gz)
				walkErr := filepath.Walk(s.cfg.AcmeHome, func(p string, info os.FileInfo, err error) error {
					if err != nil {
						return err
					}
					if info.IsDir() {
						return nil
					}
					rel, e := filepath.Rel(s.cfg.AcmeHome, p)
					if e != nil || strings.HasPrefix(rel, ".") {
						return nil
					}
					hdr := &tar.Header{Name: filepath.ToSlash(rel), Mode: 0o600, Size: info.Size(), ModTime: info.ModTime()}
					if e := tw.WriteHeader(hdr); e != nil {
						return e
					}
					src, e := os.Open(p)
					if e != nil {
						return e
					}
					_, copyErr := io.Copy(tw, src)
					closeErr := src.Close()
					if copyErr != nil {
						return copyErr
					}
					return closeErr
				})
				// Close 错误只在没有更早的根因时记录，避免掩盖真正的失败原因。
				if e := tw.Close(); e != nil && walkErr == nil {
					walkErr = e
				}
				if e := gz.Close(); e != nil && walkErr == nil {
					walkErr = e
				}
				if e := f.Close(); e != nil && walkErr == nil {
					walkErr = e
				}
				archiveErr = walkErr
			}
		}
		if archiveErr != nil && tgzPath != "" {
			// 归档已损坏，立即删除半成品，防止灾难恢复时误用。
			_ = os.Remove(tgzPath)
		}
	}
	rec := BackupRecord{
		TS: time.Now(), Name: name, Size: int64(len(b)),
		Kind: kind, Status: "ok", Detail: "配置备份",
	}
	if archiveErr != nil {
		// 配置 JSON 仍然有效，但必须如实标记证书归档失败。
		rec.Status = "fail"
		rec.Detail = "证书归档失败: " + archiveErr.Error()
	} else if includeCerts {
		rec.Detail += " + 证书归档"
	}
	rec.ID = s.store.AddBackupRecord(rec)
	return rec, nil
}

func (s *Server) handleBackupRun(w http.ResponseWriter, r *http.Request) {
	rec, err := s.createBackup("manual", false)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "备份失败: "+err.Error())
		return
	}
	if rec.Status != "ok" {
		writeErr(w, http.StatusInternalServerError, "备份失败: "+rec.Detail)
		return
	}
	s.store.Audit(sess(r).User, clientIP(r, s.cfg.TrustProxy), "backup_create", rec.Name)
	writeJSON(w, http.StatusOK, rec)
}

func (s *Server) handleBackupContent(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "非法备份 ID")
		return
	}
	var name, status string
	if s.store.db != nil {
		_ = s.store.db.QueryRow(`SELECT name,status FROM backups WHERE id=?`, id).Scan(&name, &status)
	}
	if name == "" {
		writeErr(w, http.StatusNotFound, "备份记录不存在")
		return
	}
	path, err := s.backupPath(name)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		writeErr(w, http.StatusNotFound, "备份文件已丢失")
		return
	}
	var raw map[string]any
	if json.Unmarshal(b, &raw) != nil {
		writeErr(w, http.StatusBadRequest, "备份文件格式错误")
		return
	}
	// 只返回摘要与统计，不把完整凭证密文回显到浏览器。
	summary := map[string]any{
		"id":          id,
		"name":        name,
		"status":      status,
		"format":      raw["format"],
		"version":     raw["version"],
		"app_version": raw["appVersion"],
		"exported_at": raw["exportedAt"],
		"bytes":       len(b),
	}
	if st, ok := raw["state"].(map[string]any); ok {
		summary["providers"] = len(mapKeys(st["providers"]))
		summary["notifiers"] = len(mapKeys(st["notifiers"]))
		summary["sync_rules"] = len(sliceLen(st["sync_rules"]))
		summary["remote_hosts"] = len(mapKeys(st["remote_hosts"]))
	}
	writeJSON(w, http.StatusOK, summary)
}

func mapKeys(v any) []string {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func sliceLen(v any) []any {
	s, _ := v.([]any)
	return s
}

func (s *Server) handleBackupDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "非法备份 ID")
		return
	}
	var name string
	if s.store.db != nil {
		_ = s.store.db.QueryRow(`SELECT name FROM backups WHERE id=?`, id).Scan(&name)
	}
	if name == "" {
		writeErr(w, http.StatusNotFound, "备份记录不存在")
		return
	}
	path, _ := s.backupPath(name)
	_ = os.Remove(path)
	// 同时删除配套证书归档。
	certPath, _ := s.backupPath(strings.TrimSuffix(name, ".json") + "-certs.tar.gz")
	_ = os.Remove(certPath)
	s.store.DeleteBackupRecord(id)
	s.store.Audit(sess(r).User, clientIP(r, s.cfg.TrustProxy), "backup_delete", name)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---------------- 失败任务指数退避自动重试 ----------------

func (s *Server) handleRetryPolicy(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.store.Snapshot().RetryPolicy)
}

func (s *Server) handleRetryPolicySave(w http.ResponseWriter, r *http.Request) {
	var req RetryPolicy
	if err := readJSON(w, r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	before := s.store.Snapshot().RetryPolicy
	req.MaxAttempts = clampInt(req.MaxAttempts, 2, 10)
	req.BaseDelay = clampInt(req.BaseDelay, 5, 3600)
	req.MaxDelay = clampInt(req.MaxDelay, req.BaseDelay, 86400)
	if err := s.store.SetRetryPolicy(req); err != nil {
		writeErr(w, http.StatusInternalServerError, "保存失败")
		return
	}
	s.recordDiff(r, "retry_policy_save", "任务", jsonSnapshot(before), jsonSnapshot(req))
	writeJSON(w, http.StatusOK, req)
}

func (s *Server) handleRetryQueue(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"queue": s.jobs.RetryQueue(),
	})
}

// ---------------- 配置变更 Diff ----------------

func (s *Server) handleConfigDiffs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := parseIntDefault(q.Get("limit"), 50)
	offset := parseIntDefault(q.Get("offset"), 0)
	list, total, err := s.store.QueryConfigDiffs(q.Get("action"), q.Get("category"), limit, offset)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "查询失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":      list,
		"total":      total,
		"limit":      limit,
		"offset":     offset,
		"actions":    s.store.ConfigDiffActions(),
		"categories": s.store.ConfigDiffCategories(),
	})
}

// ---------------- 证书链/私钥一致性校验与 OCSP ----------------

func (s *Server) handleCertVerify(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	ci, err := s.certs.Get(name)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	detail, err := s.certs.ReadKey(name)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "读取私钥失败: "+err.Error())
		return
	}
	fullchain, err := s.certs.ReadPEM(name, "fullchain")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "读取证书链失败: "+err.Error())
		return
	}
	checks := []HealthCheck{}
	add := func(n, st, d string) { checks = append(checks, HealthCheck{Name: n, Status: st, Detail: d}) }

	leaf, err := parseFirstCert([]byte(fullchain))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "解析 leaf 证书失败: "+err.Error())
		return
	}
	// 私钥与证书公钥匹配
	if err := certKeyMatch(leaf, []byte(detail)); err != nil {
		add("私钥匹配", "fail", err.Error())
	} else {
		add("私钥匹配", "ok", "私钥与 leaf 证书公钥一致")
	}
	// 证书链完整性：逐张检查 Issuer 是否由后续证书签发
	chain, badCerts, err := parseAllCerts([]byte(fullchain))
	if err != nil || len(chain) == 0 {
		add("证书链", "fail", "无法解析证书链")
	} else {
		if badCerts > 0 {
			add("证书链解析", "fail", fmt.Sprintf("有 %d 张证书 DER 解码失败，以下链校验结果可能不完整", badCerts))
		}
		if len(chain) == 1 {
			add("证书链", "warn", "链中只有 leaf 证书，建议部署 fullchain")
		} else {
			broken := []string{}
			for i := 0; i < len(chain)-1; i++ {
				if chain[i].CheckSignatureFrom(chain[i+1]) != nil {
					broken = append(broken, fmt.Sprintf("第 %d 张证书的签发者不是第 %d 张", i+1, i+2))
				}
			}
			if len(broken) > 0 {
				add("证书链", "fail", strings.Join(broken, "；"))
			} else if badCerts == 0 {
				add("证书链", "ok", fmt.Sprintf("链完整，共 %d 张", len(chain)))
			} else {
				add("证书链", "warn", "已解析部分签名链一致，但存在损坏证书，结果不完整")
			}
		}
	}
	// 有效期
	days := int(time.Until(leaf.NotAfter).Hours() / 24)
	if days < 0 {
		add("有效期", "fail", fmt.Sprintf("已过期 %d 天", -days))
	} else if days <= 7 {
		add("有效期", "warn", fmt.Sprintf("仅剩 %d 天", days))
	} else {
		add("有效期", "ok", fmt.Sprintf("剩余 %d 天", days))
	}
	// OCSP（可选，网络失败只记 warn）
	ocspURL := ""
	if len(leaf.OCSPServer) > 0 {
		ocspURL = leaf.OCSPServer[0]
	}
	if ocspURL == "" {
		add("OCSP", "warn", "证书未提供 OCSP 地址")
	} else {
		issuer := leaf // 缺省用 leaf 作为 issuer，至少能构造合法请求
		if len(chain) > 1 && chain[len(chain)-1] != leaf {
			issuer = chain[1]
		}
		reqBody, e := ocsp.CreateRequest(leaf, issuer, nil)
		if e != nil {
			add("OCSP", "warn", "构造请求失败："+e.Error())
		} else {
			client := &http.Client{Timeout: 6 * time.Second}
			resp, e := client.Post(ocspURL, "application/ocsp-request", bytes.NewReader(reqBody))
			if e != nil {
				add("OCSP", "warn", "查询失败："+e.Error())
			} else {
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
				_ = resp.Body.Close()
				oresp, e := ocsp.ParseResponseForCert(body, leaf, issuer)
				if e != nil {
					add("OCSP", "warn", "解析响应失败："+e.Error())
				} else {
					switch oresp.Status {
					case ocsp.Good:
						add("OCSP", "ok", "证书状态正常")
					case ocsp.Revoked:
						add("OCSP", "fail", "证书已被吊销")
					default:
						add("OCSP", "warn", "状态未知")
					}
				}
			}
		}
	}
	overall := "ok"
	for _, c := range checks {
		if c.Status == "fail" {
			overall = "fail"
		} else if c.Status == "warn" && overall == "ok" {
			overall = "warn"
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name": name, "domain": ci.Domain, "overall": overall, "checks": checks,
	})
}

func parseFirstCert(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("PEM 解码失败")
	}
	return x509.ParseCertificate(block.Bytes)
}

// parseAllCerts 返回成功解析的证书，以及 DER 损坏的证书块数。
// 只统计类型为 CERTIFICATE 的块，避免把同文件里的私钥/注释误判为坏证书。
func parseAllCerts(pemBytes []byte) ([]*x509.Certificate, int, error) {
	out := []*x509.Certificate{}
	bad := 0
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			bad++
			continue
		}
		out = append(out, c)
	}
	return out, bad, nil
}

func certKeyMatch(cert *x509.Certificate, keyPEM []byte) error {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return fmt.Errorf("私钥 PEM 解码失败")
	}
	switch k := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			if p8, e := x509.ParsePKCS8PrivateKey(block.Bytes); e == nil {
				priv, _ = p8.(*rsa.PrivateKey)
			}
		}
		if priv == nil {
			return fmt.Errorf("私钥解析失败")
		}
		if priv.PublicKey.N.Cmp(k.N) != 0 || priv.PublicKey.E != k.E {
			return fmt.Errorf("私钥与证书公钥不匹配")
		}
	case *ecdsa.PublicKey:
		priv, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			if p8, e := x509.ParsePKCS8PrivateKey(block.Bytes); e == nil {
				priv, _ = p8.(*ecdsa.PrivateKey)
			}
		}
		if priv == nil {
			return fmt.Errorf("私钥解析失败")
		}
		if priv.PublicKey.X.Cmp(k.X) != 0 || priv.PublicKey.Y.Cmp(k.Y) != 0 {
			return fmt.Errorf("私钥与证书公钥不匹配")
		}
	default:
		return fmt.Errorf("不支持的公钥类型")
	}
	return nil
}

// ---------------- 批量签发向导 ----------------

// handleIssueBatch 把一次文本域里的多个域名拆成独立任务排队。
// 每个域名单独签发，避免一个域名失败拖累整批；公共参数（凭证/CA/密钥/邮箱）只校验一次。
func (s *Server) handleIssueBatch(w http.ResponseWriter, r *http.Request) {
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
	if len(domains) > 50 {
		writeErr(w, http.StatusBadRequest, "单批最多 50 个域名")
		return
	}
	if !validKeyLength(req.KeyLength) {
		writeErr(w, http.StatusBadRequest, "不支持的密钥类型")
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
	email := strings.TrimSpace(req.Email)
	if email == "" {
		email = s.store.DefaultEmail()
	}
	if email != "" && !emailRe.MatchString(email) {
		writeErr(w, http.StatusBadRequest, "ACME 邮箱格式不合法")
		return
	}

	jobs := make([]map[string]any, 0, len(domains))
	for _, d := range domains {
		key := d
		if strings.HasPrefix(req.KeyLength, "ec-") {
			key += "_ecc"
		}
		args := []string{"--issue", "--dns", code}
		if req.DNSSleep > 0 {
			args = append(args, "--dnssleep", strconv.Itoa(req.DNSSleep))
		}
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
		args = append(args, "-d", d)
		preview := "acme.sh --issue --dns " + code + " -d " + d
		j := s.jobs.Start("issue", "批量签发 "+d, d, preview, env, args)
		jobs = append(jobs, map[string]any{"id": j.ID, "domain": d, "cert_name": key})
	}
	s.store.Audit(sess(r).User, clientIP(r, s.cfg.TrustProxy), "issue_batch",
		fmt.Sprintf("count=%d via %s", len(domains), code))
	writeJSON(w, http.StatusAccepted, map[string]any{
		"jobs": jobs, "count": len(jobs), "queued": true,
	})
}

// ---------------- ACME 账户管理 ----------------

// handleACMEAccounts 从 acme.sh 目录解析账户摘要；不返回账户私钥内容。
func (s *Server) handleACMEAccounts(w http.ResponseWriter, r *http.Request) {
	accounts := scanACMEAccounts(s.cfg.AcmeHome, s.effectiveCA())
	st := s.store.Snapshot()
	if len(accounts) > 0 {
		_ = s.store.SetACMEAccounts(accounts)
	} else {
		accounts = st.ACMEAccounts // 目录暂不可读时沿用缓存
	}
	if accounts == nil {
		accounts = []ACMEAccount{} // 始终返回数组，避免前端拿到 null
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"accounts":   accounts,
		"default_ca": s.effectiveCA(),
		"acme_home":  s.cfg.AcmeHome,
		"env_pinned": os.Getenv("ACME_PANEL_CA") != "",
	})
}

func scanACMEAccounts(home, defaultCA string) []ACMEAccount {
	out := []ACMEAccount{}
	entries, err := os.ReadDir(home)
	if err != nil {
		return out
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, "account.conf") || e.IsDir() {
			continue
		}
		path := filepath.Join(home, name)
		b, err := os.ReadFile(path)
		if err != nil || len(b) > 1<<20 {
			continue
		}
		email := ""
		server := ""
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "ACME_EMAIL=") {
				email = strings.Trim(strings.TrimPrefix(line, "ACME_EMAIL="), `"'`)
			}
			if strings.HasPrefix(line, "DEFAULT_ACME_SERVER=") {
				server = strings.Trim(strings.TrimPrefix(line, "DEFAULT_ACME_SERVER="), `"'`)
			}
		}
		ca := strings.TrimSuffix(name, "account.conf")
		if ca == "" {
			ca = "default"
		}
		sum := sha256Bytes(b)
		out = append(out, ACMEAccount{
			ID:             name,
			CA:             serverOrDefault(ca, server),
			Email:          email,
			AccountDir:     name,
			KeyFingerprint: sum,
			Default:        ca == defaultCA || strings.Contains(server, defaultCA),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func serverOrDefault(ca, server string) string {
	if server != "" {
		return server
	}
	if v, ok := caDirectoryURL[ca]; ok {
		return v
	}
	return ca
}

// ---------------- 只读 API Token ----------------

func (s *Server) handleTokens(w http.ResponseWriter, r *http.Request) {
	out := []map[string]any{}
	for _, t := range s.store.Snapshot().APITokens {
		out = append(out, map[string]any{
			"id": t.ID, "name": t.Name, "prefix": t.Prefix, "scopes": t.Scopes,
			"created": t.Created, "last_used": t.LastUsed, "enabled": t.Enabled,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": out})
}

func (s *Server) handleTokenCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name   string   `json:"name"`
		Scopes []string `json:"scopes"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > 40 {
		writeErr(w, http.StatusBadRequest, "令牌名称需为 1～40 个字符")
		return
	}
	for _, sc := range req.Scopes {
		if !validTokenScope(sc) {
			writeErr(w, http.StatusBadRequest, "不支持的权限范围："+sc)
			return
		}
	}
	tokens := s.store.Snapshot().APITokens
	if len(tokens) >= 100 {
		writeErr(w, http.StatusBadRequest, "最多创建 100 个令牌")
		return
	}
	token, plain := newAPIToken(name, req.Scopes)
	tokens = append(tokens, token)
	if err := s.store.SetAPITokens(tokens); err != nil {
		writeErr(w, http.StatusInternalServerError, "保存失败")
		return
	}
	s.recordDiff(r, "token_create", "安全", "", jsonSnapshot(map[string]any{
		"name": token.Name, "scopes": token.Scopes, "prefix": token.Prefix,
	}))
	writeJSON(w, http.StatusCreated, map[string]any{
		"token": token, "plain": plain,
		"warning": "明文令牌仅显示这一次，请立即保存；刷新后无法再次查看。",
	})
}

func (s *Server) handleTokenDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	tokens := s.store.Snapshot().APITokens
	found := false
	kept := []APIToken{}
	for _, t := range tokens {
		if t.ID == id {
			found = true
			continue
		}
		kept = append(kept, t)
	}
	if !found {
		writeErr(w, http.StatusNotFound, "令牌不存在")
		return
	}
	if err := s.store.SetAPITokens(kept); err != nil {
		writeErr(w, http.StatusInternalServerError, "删除失败")
		return
	}
	s.recordDiff(r, "token_delete", "安全", id, "")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleTokenUsage(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"header": apiTokenHeader,
		"scopes": []string{"certs", "jobs", "sync", "audit", "overview"},
		"rules": []string{
			"令牌仅允许 GET 请求，写操作仍需会话 Cookie 与 CSRF 令牌",
			"Header 名为 X-API-Token，值为创建时返回的完整明文（含 acmp_ 前缀）",
			"Token 只存 SHA-256 哈希，明文创建后不可再次查看",
			"白名单、HTTPS-only 策略对令牌同样生效",
		},
		"examples": []map[string]string{
			{"name": "查看证书列表", "cmd": "curl -H 'X-API-Token: acmp_你的令牌' https://acme.example.com/api/certs"},
			{"name": "查看任务状态", "cmd": "curl -H 'X-API-Token: acmp_你的令牌' https://acme.example.com/api/jobs"},
			{"name": "查询到期看板", "cmd": "curl -H 'X-API-Token: acmp_你的令牌' https://acme.example.com/api/expiry"},
		},
	})
}

// ---------------- 统一计划任务 ----------------

func nextRunAt(enabled bool, hour, weekday int, interval string) string {
	if !enabled {
		return "已停用"
	}
	now := time.Now()
	base := time.Date(now.Year(), now.Month(), now.Day(), hour, 0, 0, 0, now.Location())
	if !base.After(now) {
		base = base.AddDate(0, 0, 1)
	}
	if interval == "weekly" {
		for base.Weekday() != time.Weekday(weekday) {
			base = base.AddDate(0, 0, 1)
		}
	}
	return base.Format("2006-01-02 15:04")
}

func (s *Server) handleSchedules(w http.ResponseWriter, r *http.Request) {
	st := s.store.Snapshot()
	items := []ScheduleInfo{
		{
			Key: "cron", Name: "自动续期检查", Category: "证书",
			Description: "每天按设定的小时调用 acme.sh --cron",
			Enabled:     s.cfg.Cron, Detail: fmt.Sprintf("每天 %02d:00", st.CronHour),
			NextRun: nextRunAt(s.cfg.Cron, st.CronHour, 0, "daily"),
		},
		{
			Key: "update", Name: "面板版本检测", Category: "系统",
			Description: "按配置周期查询 GitHub Release",
			Enabled:     st.Update.AutoCheck && st.Update.Interval != updateIntervalOff,
			Detail:      "周期 " + st.Update.Interval,
			NextRun: nextRunAt(st.Update.AutoCheck && st.Update.Interval != updateIntervalOff, 4, 0,
				map[string]string{"daily": "daily", "weekly": "weekly", "6h": "daily"}[st.Update.Interval]),
		},
		{
			Key: "backup", Name: "自动备份", Category: "备份",
			Description: "定时导出配置备份并按保留份数清理",
			Enabled:     st.AutoBackup.Enabled,
			Detail:      fmt.Sprintf("%s %02d:00，保留 %d 份", st.AutoBackup.Interval, st.AutoBackup.Hour, st.AutoBackup.Keep),
			NextRun:     nextRunAt(st.AutoBackup.Enabled, st.AutoBackup.Hour, 0, st.AutoBackup.Interval),
		},
		{
			Key: "expiry", Name: "临期证书提醒", Category: "证书",
			Description: "30 天内到期的证书每天推送一次通知",
			Enabled:     true, Detail: "每天随自动续期检查执行",
			NextRun: nextRunAt(true, st.CronHour, 0, "daily"),
		},
		{
			Key: "retention", Name: "记录清理", Category: "系统",
			Description: "按保留天数清理任务、审计与同步记录",
			Enabled:     st.RetentionDays > 0,
			Detail:      fmt.Sprintf("保留 %d 天", st.RetentionDays),
			NextRun:     nextRunAt(st.RetentionDays > 0, 3, 0, "daily"),
		},
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": items, "server_time": time.Now(),
	})
}

// ---------------- CSV 导出 ----------------

func (s *Server) handleCSVExport(w http.ResponseWriter, r *http.Request) {
	kind := r.URL.Query().Get("kind")
	var header []string
	rows := [][]string{}
	switch kind {
	case "audit":
		header = []string{"时间", "用户", "IP", "动作", "详情"}
		list, _ := s.store.AuditQuery(AuditFilter{Limit: 10000})
		for _, a := range list {
			rows = append(rows, []string{
				mapStr(a, "ts"), mapStr(a, "user"), mapStr(a, "ip"),
				mapStr(a, "action"), mapStr(a, "detail"),
			})
		}
	case "jobs":
		header = []string{"任务ID", "类型", "标题", "状态", "创建", "结束", "错误"}
		for _, j := range s.jobs.List() {
			rows = append(rows, []string{j.ID, j.Kind, j.Title, j.Status,
				formatTimeCSV(j.Created), formatTimeCSV(j.Ended), j.Error})
		}
	case "sync":
		header = []string{"时间", "范围", "规则", "来源", "目标", "结果", "详情"}
		for _, e := range s.store.AllSyncEvents() {
			rows = append(rows, []string{e.Time, e.Scope, e.Rule, e.Source, e.Target, e.Result, e.Detail})
		}
	case "diff":
		header = []string{"时间", "用户", "IP", "动作", "分类", "变更前", "变更后"}
		list, _, err := s.store.QueryConfigDiffs("", "", 10000, 0)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "查询失败")
			return
		}
		for _, d := range list {
			rows = append(rows, []string{d.TS.Format(time.RFC3339), d.User, d.IP, d.Action, d.Category, d.Before, d.After})
		}
	default:
		writeErr(w, http.StatusBadRequest, "不支持的导出类型")
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-%s.csv"`, kind, time.Now().Format("20060102")))
	_, _ = w.Write([]byte("\xef\xbb\xbf")) // BOM，Excel 直接打开不乱码
	writeCSV(w, header, rows)
}

func formatTimeCSV(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

// ---------------- 界面语言 ----------------

func (s *Server) handleLocaleSave(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Locale string `json:"locale"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if req.Locale != "zh" && req.Locale != "en" && req.Locale != "ja" {
		writeErr(w, http.StatusBadRequest, "不支持的语言")
		return
	}
	before := s.store.Snapshot().Locale
	if err := s.store.SetLocale(req.Locale); err != nil {
		writeErr(w, http.StatusInternalServerError, "保存失败")
		return
	}
	s.recordDiff(r, "locale_save", "系统", before, req.Locale)
	writeJSON(w, http.StatusOK, map[string]any{"locale": req.Locale})
}
