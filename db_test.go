package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestImportLegacyFiles 验证旧 JSON/JSONL 数据能一次性导入 SQLite，
// 且导入后旧文件保留为 *.imported 备份，不直接删除。
func TestImportLegacyFiles(t *testing.T) {
	dir := t.TempDir()
	stateJSON := `{"username":"admin","default_email":"old@example.com","cron_hour":5,"sync_rules":[]}`
	jobsJSON := `[{"id":"job-old","kind":"issue","title":"旧任务","status":"success","created":"2026-01-01T00:00:00Z"}]`
	auditJSON := `{"ts":"2026-01-01T00:00:00+08:00","user":"admin","ip":"127.0.0.1","action":"login","detail":""}` + "\n"
	for name, data := range map[string]string{
		"state.json": stateJSON, "jobs.json": jobsJSON, "audit.log": auditJSON,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	db, err := openDB(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var raw string
	if err := db.QueryRow(`SELECT value FROM state WHERE key='main'`).Scan(&raw); err != nil {
		t.Fatalf("state 未导入: %v", err)
	}
	if !strings.Contains(raw, "old@example.com") || !strings.Contains(raw, `"cron_hour":5`) {
		t.Fatalf("state 内容不符: %s", raw)
	}
	var jobs, audits int
	if err := db.QueryRow(`SELECT COUNT(*) FROM jobs`).Scan(&jobs); err != nil || jobs != 1 {
		t.Fatalf("jobs 导入失败: count=%d err=%v", jobs, err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit`).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("audit 导入失败: count=%d err=%v", audits, err)
	}
	for _, name := range []string{"state.json", "jobs.json", "audit.log"} {
		if _, err := os.Stat(filepath.Join(dir, name+".imported")); err != nil {
			t.Fatalf("旧文件备份缺失: %s: %v", name, err)
		}
	}

	// 再打开一次不应重复导入
	db2, err := openDB(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	if err := db2.QueryRow(`SELECT COUNT(*) FROM audit`).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("重复导入: count=%d err=%v", audits, err)
	}
}

// TestCleanup 验证超过保留天数的审计记录被删除，新的保留。
func TestCleanup(t *testing.T) {
	dir := t.TempDir()
	db, err := openDB(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := &Store{dir: dir, db: db}
	old := time.Now().AddDate(0, 0, -40).Format(time.RFC3339)
	fresh := time.Now().AddDate(0, 0, -1).Format(time.RFC3339)
	for _, ts := range []string{old, fresh} {
		if _, err := db.Exec(`INSERT INTO audit(ts,user,ip,action,detail) VALUES(?,?,?,?,?)`,
			ts, "admin", "127.0.0.1", "login", ""); err != nil {
			t.Fatal(err)
		}
	}
	removed, err := store.Cleanup(30)
	if err != nil {
		t.Fatal(err)
	}
	if removed["audit"] != 1 {
		t.Fatalf("应清理 1 条旧审计，实际 %v", removed)
	}
	var left int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit`).Scan(&left); err != nil || left != 1 {
		t.Fatalf("清理后应剩 1 条，实际 %d err=%v", left, err)
	}
	if got := store.RetentionDays(); got != 0 {
		t.Fatalf("零值 Store 的保留天数应为 0，实际 %d", got)
	}
}
