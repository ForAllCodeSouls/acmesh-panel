package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// BackupFile 是配置备份的单文件格式。State 里的凭证都是 AES-GCM 密文，
// 不含 secret.key 主密钥；登录密码哈希在导出时被剔除，恢复时始终沿用当前 env 凭据。
type BackupFile struct {
	Format     string    `json:"format"`
	Version    int       `json:"version"`
	AppVersion string    `json:"app_version"`
	ExportedAt time.Time `json:"exported_at"`
	State      State     `json:"state"`
}

const (
	backupFormat  = "acmesh-panel-backup"
	backupVersion = 1
	backupMaxBody = 8 << 20 // 8 MiB，足够容纳全部配置与最近记录
)

// backupCounts 供页面在导入前预览「这份备份里有什么」。
func backupCounts(st State) map[string]int {
	return map[string]int{
		"providers":    len(st.Providers),
		"notifiers":    len(st.Notifiers),
		"remote_hosts": len(st.RemoteHosts),
		"sync_rules":   len(st.SyncRules),
		"sync_events":  len(st.SyncEvents),
		"cert_emails":  len(st.CertEmails),
		"notify_sent":  len(st.NotifySent),
		"sync_seen":    len(st.SyncSeen),
		"remote_seen":  len(st.RemoteSeen),
	}
}

// handleBackupExport 把当前配置导出成一个 JSON 文件下载。
func (s *Server) handleBackupExport(w http.ResponseWriter, r *http.Request) {
	st := s.store.Snapshot()
	// 登录凭据不随备份导出：备份文件里不携带账号名、盐、密码哈希与来源标记。
	st.Username = ""
	st.Salt = ""
	st.Hash = ""
	st.Iter = 0
	st.CredSource = ""
	bf := BackupFile{
		Format:     backupFormat,
		Version:    backupVersion,
		AppVersion: appVersion,
		ExportedAt: time.Now(),
		State:      st,
	}
	name := fmt.Sprintf("acmesh-panel-backup-%s.json", time.Now().Format("20060102-150405"))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(bf)
	s.store.Audit(sess(r).User, clientIP(r, s.cfg.TrustProxy), "backup_export", name)
}

// handleBackupImport 校验并恢复一份配置备份。登录凭据不覆盖，会话保持有效。
func (s *Server) handleBackupImport(w http.ResponseWriter, r *http.Request) {
	var bf BackupFile
	dec := json.NewDecoder(io.LimitReader(r.Body, backupMaxBody))
	if err := dec.Decode(&bf); err != nil {
		writeErr(w, http.StatusBadRequest, "备份文件不是有效的 JSON（或超过 8 MiB）")
		return
	}
	if bf.Format != backupFormat {
		writeErr(w, http.StatusBadRequest, "不是 acmesh-panel 的配置备份文件")
		return
	}
	if bf.Version != backupVersion {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("备份版本 %d 不受支持（当前支持 %d）", bf.Version, backupVersion))
		return
	}
	st := bf.State
	// 空备份（没有任何配置）也允许恢复为空配置，但必须能看出是完整结构：
	// UpdatedAt / 各类 map 都不应全是零值，至少要有导出时写入的时间戳。
	if bf.ExportedAt.IsZero() {
		writeErr(w, http.StatusBadRequest, "备份文件缺少导出时间，可能已损坏")
		return
	}
	if st.Providers == nil && st.Notifiers == nil && st.RemoteHosts == nil &&
		st.SyncRules == nil && st.SyncEvents == nil && st.DefaultEmail == "" &&
		st.CronHour == 0 && st.RetentionDays == 0 {
		writeErr(w, http.StatusBadRequest, "备份内容为空或已损坏，已拒绝恢复")
		return
	}
	counts := backupCounts(st)
	if err := s.store.Restore(st); err != nil {
		writeErr(w, http.StatusInternalServerError, "恢复失败："+err.Error())
		return
	}
	detail := fmt.Sprintf("来源版本 %s · 导出于 %s", bf.AppVersion, bf.ExportedAt.Format(time.RFC3339))
	s.store.Audit(sess(r).User, clientIP(r, s.cfg.TrustProxy), "backup_restore", detail)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "restored": counts, "app_version": bf.AppVersion,
		"message": "配置已恢复；备份不含登录账号与密码哈希，当前凭据未被覆盖。",
	})
}
