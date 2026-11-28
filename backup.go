package main

import (
	"encoding/base64"
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
		"eab_creds":    len(st.EABCreds),
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

// ValidateRestore 在恢复前验证备份里的加密凭证能否被当前 secret.key 解开。
// 备份本身不含主密钥；跨机器重建时若只复制了备份 JSON 而没有复制 secret.key，
// 直接恢复会让所有凭证变成无法读取的密文，界面却显示"恢复成功"。
func (s *Store) ValidateRestore(st State) error {
	ns := s.aead.NonceSize()
	openable := func(blob, aad, label string) error {
		raw, err := base64.StdEncoding.DecodeString(blob)
		if err != nil || len(raw) < ns {
			return fmt.Errorf("%s 数据损坏", label)
		}
		if _, err := s.aead.Open(nil, raw[:ns], raw[ns:], []byte(aad)); err != nil {
			return fmt.Errorf("%s 无法用当前 secret.key 解密（请在同一实例恢复，或一并迁移 secret.key）", label)
		}
		return nil
	}
	for name, enc := range st.Providers {
		if err := openable(enc.Blob, name+"|"+enc.Code, "DNS 凭证 "+name); err != nil {
			return err
		}
	}
	for id := range st.Notifiers {
		enc := st.Notifiers[id]
		if err := openable(enc.Blob, id, "通知渠道 "+id); err != nil {
			return err
		}
	}
	for id := range st.RemoteHosts {
		enc := st.RemoteHosts[id]
		if err := openable(enc.Blob, id, "远程主机 "+id); err != nil {
			return err
		}
	}
	// EAB 凭证的 AAD 与 DNS 凭证隔离，必须单独验证，否则跨实例恢复后
	// 界面显示成功但所有 EAB 凭证实际无法解密，直到签发时才暴露。
	for name, enc := range st.EABCreds {
		if err := openable(enc.Blob, eabAADPrefix+name+"|"+enc.Code, "EAB 凭证 "+name); err != nil {
			return err
		}
	}
	return nil
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
		st.EABCreds == nil && st.SyncRules == nil && st.SyncEvents == nil && st.DefaultEmail == "" &&
		st.CronHour == 0 && st.RetentionDays == 0 {
		writeErr(w, http.StatusBadRequest, "备份内容为空或已损坏，已拒绝恢复")
		return
	}
	if err := s.store.ValidateRestore(st); err != nil {
		writeErr(w, http.StatusBadRequest, "备份与当前存储密钥不匹配："+err.Error())
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
		"message": "配置已恢复；备份不含登录账号与密码哈希，当前凭据未被覆盖。跨实例恢复请一并迁移 secret.key，否则加密凭证无法解开。",
	})
}
