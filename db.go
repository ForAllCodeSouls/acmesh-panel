package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// 持久化统一走 SQLite：state（配置/凭证密文/规则/记录）、jobs（任务）、audit（审计）。
// WAL + synchronous=FULL + 单连接：每次写入都是事务提交，不会再出现 JSON 写一半丢数据。

// openDB 打开数据目录下的 panel.db，建表并检查旧 JSON 导入。
func openDB(dir string) (*sql.DB, error) {
	path := filepath.Join(dir, "panel.db")
	p := filepath.ToSlash(path)
	// Windows 绝对路径（C:/...）必须以 / 开头，否则 file://C:/... 会被解析成
	// host="C:"，modernc/sqlite 报 invalid uri authority。容器 Linux 路径本来就是 /...。
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	u := (&url.URL{Scheme: "file", Path: p}).String()
	dsn := u + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite 只有一个写者，串行化避免锁竞争
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	// 数据文件只给面板自己读（fuse / 某些文件系统可能不支持，忽略即可）
	_ = os.Chmod(path, 0o600)
	for _, suffix := range []string{"-wal", "-shm"} {
		_ = os.Chmod(path+suffix, 0o600)
	}
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, created TEXT NOT NULL, data TEXT NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS idx_jobs_created ON jobs(created)`,
		`CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL,
		 user TEXT NOT NULL, ip TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts)`,
		// v0.1.70：配置变更对比、健康自检快照、备份记录。
		`CREATE TABLE IF NOT EXISTS config_diffs (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL,
		 user TEXT NOT NULL, ip TEXT NOT NULL, action TEXT NOT NULL, category TEXT NOT NULL,
		 before TEXT NOT NULL, after TEXT NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS idx_config_diffs_ts ON config_diffs(ts)`,
		`CREATE TABLE IF NOT EXISTS health_snapshots (id INTEGER PRIMARY KEY AUTOINCREMENT,
		 ts TEXT NOT NULL, result TEXT NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS idx_health_ts ON health_snapshots(ts)`,
		`CREATE TABLE IF NOT EXISTS backups (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL,
		 name TEXT NOT NULL, size INTEGER NOT NULL, kind TEXT NOT NULL, status TEXT NOT NULL, detail TEXT NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS idx_backups_ts ON backups(ts)`,
	}
	for _, q := range stmts {
		if _, err := db.Exec(q); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	if err := importLegacyFiles(dir, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

// importLegacyFiles 把旧版 JSON/JSONL 数据一次性导入 SQLite。
// 导入成功后旧文件改名为 *.imported 留作备份，绝不直接删除。
func importLegacyFiles(dir string, db *sql.DB) error {
	var n int
	// ---- state.json ----
	if err := db.QueryRow(`SELECT COUNT(*) FROM state WHERE key='main'`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		path := filepath.Join(dir, "state.json")
		if b, err := os.ReadFile(path); err == nil && json.Valid(b) {
			if _, err := db.Exec(`INSERT INTO state(key,value) VALUES('main',?)`, string(b)); err != nil {
				return err
			}
			backupLegacyFile(path)
		}
	}
	// ---- jobs.json ----
	if err := db.QueryRow(`SELECT COUNT(*) FROM jobs`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		path := filepath.Join(dir, "jobs.json")
		if b, err := os.ReadFile(path); err == nil {
			var jobs []persistedJob
			if json.Unmarshal(b, &jobs) == nil {
				tx, err := db.Begin()
				if err != nil {
					return err
				}
				ok := true
				for _, p := range jobs {
					data, _ := json.Marshal(p)
					created := p.Created.Format(time.RFC3339Nano)
					if p.Created.IsZero() {
						created = time.Now().Format(time.RFC3339Nano)
					}
					if _, err := tx.Exec(`INSERT OR REPLACE INTO jobs(id,created,data) VALUES(?,?,?)`,
						p.ID, created, string(data)); err != nil {
						ok = false
						break
					}
				}
				if ok {
					ok = tx.Commit() == nil
				} else {
					_ = tx.Rollback()
				}
				if ok {
					backupLegacyFile(path)
				}
			}
		}
	}
	// ---- audit.log / audit.log.1 ----
	var ac int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit`).Scan(&ac); err != nil {
		return err
	}
	if ac == 0 {
		for _, name := range []string{"audit.log", "audit.log.1"} {
			path := filepath.Join(dir, name)
			b, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			tx, err := db.Begin()
			if err != nil {
				return err
			}
			ok := true
			for _, line := range splitLines(string(b)) {
				var rec struct {
					TS     string `json:"ts"`
					User   string `json:"user"`
					IP     string `json:"ip"`
					Action string `json:"action"`
					Detail string `json:"detail"`
				}
				if json.Unmarshal([]byte(line), &rec) != nil {
					continue
				}
				if _, err := tx.Exec(`INSERT INTO audit(ts,user,ip,action,detail) VALUES(?,?,?,?,?)`,
					rec.TS, rec.User, rec.IP, rec.Action, rec.Detail); err != nil {
					ok = false
					break
				}
			}
			if ok {
				ok = tx.Commit() == nil
			} else {
				_ = tx.Rollback()
			}
			if ok {
				backupLegacyFile(path)
			}
		}
	}
	return nil
}

func backupLegacyFile(path string) {
	if _, err := os.Stat(path); err != nil {
		return
	}
	bak := path + ".imported"
	if _, err := os.Stat(bak); err == nil {
		bak = fmt.Sprintf("%s.imported.%d", path, time.Now().Unix())
	}
	_ = os.Rename(path, bak)
}

// Cleanup 删除超过保留天数的任务、审计与同步记录。days<=0 表示不清理。
func (s *Store) Cleanup(days int) (map[string]int, error) {
	out := map[string]int{}
	if days <= 0 || s.db == nil {
		return out, nil
	}
	cutoffTime := time.Now().AddDate(0, 0, -days)
	// jobs.created 存的是 RFC3339Nano（acme.go），cutoff 若只到秒会把同秒晚几毫秒的
	// 任务误判为过期（字典序 '.' < 'Z'）；两边都用 Nano 才能按时间正确比较。
	cutoff := cutoffTime.Format(time.RFC3339Nano)
	// audit.ts 存的是秒精度 RFC3339：'Z'(0x5A) > '.'(0x2E)，用 Nano cutoff
	// 会让 cutoff 所在整秒的记录逃过清理。审计单独用秒精度保持一致。
	auditCutoff := cutoffTime.Format(time.RFC3339)

	// 先过滤 state 里的同步记录并落盘。若这一步失败，SQL 行完全不动，
	// 避免出现「jobs/audit 已永久删除、却向用户报告清理失败」的部分生效。
	s.mu.Lock()
	before := len(s.state.SyncEvents)
	kept := make([]SyncEvent, 0, before)
	for _, ev := range s.state.SyncEvents {
		t, err := time.Parse(time.RFC3339, ev.Time)
		if err == nil && t.Before(cutoffTime) {
			continue
		}
		kept = append(kept, ev)
	}
	if len(kept) != before {
		s.state.SyncEvents = kept
		if err := s.saveLocked(); err != nil {
			s.mu.Unlock()
			return out, err
		}
		out["sync_events"] = before - len(kept)
	}
	s.mu.Unlock()

	// state 已成功落盘，再删除 jobs/audit。即使这里失败，重试也是幂等的：
	// 同步记录已被过滤掉，不会重复计数。
	tx, err := s.db.Begin()
	if err != nil {
		return out, err
	}
	defer func() { _ = tx.Rollback() }()
	if res, err := tx.Exec(`DELETE FROM jobs WHERE created < ?`, cutoff); err == nil {
		n, _ := res.RowsAffected()
		out["jobs"] = int(n)
	}
	if res, err := tx.Exec(`DELETE FROM audit WHERE ts < ?`, auditCutoff); err == nil {
		n, _ := res.RowsAffected()
		out["audit"] = int(n)
	}
	if err := tx.Commit(); err != nil {
		return out, err
	}
	return out, nil
}

// DB 返回底层数据库连接，供任务管理器写入任务记录。
func (s *Store) DB() *sql.DB { return s.db }

var errNoDB = errors.New("数据库未初始化")
