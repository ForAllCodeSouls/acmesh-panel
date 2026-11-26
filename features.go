package main

// 本文件承载 v0.1.70 新增能力的数据模型与存储方法：
// 会话管理、IP/CIDR 白名单、只读 API Token、自动备份、失败任务退避重试、
// 配置变更 Diff、健康自检、ACME 账户、批量签发与统一计划任务。
//
// 设计约束：
//   - 配置类数据放 State（单条 JSON in SQLite），加字段无需 DDL 迁移；
//   - 记录类数据（Diff/自检/备份）放独立 SQLite 表，带上限裁剪，便于分页查询；
//   - 所有凭证类字段仍经 Store 的 AEAD 加密，明文只存在于请求生命周期内。

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---------------- 新增配置类型 ----------------

// APIToken 是只读访问令牌。Hash 为 SHA-256(token)，明文只在创建响应里出现一次。
type APIToken struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Prefix   string    `json:"prefix"` // 展示用前缀，如 acmp_3f9a
	Hash     string    `json:"hash"`   // 64 位 hex SHA-256
	Scopes   []string  `json:"scopes"` // 允许的 API 路径前缀，空表示全部只读端点
	Created  time.Time `json:"created"`
	LastUsed time.Time `json:"last_used"`
	Enabled  bool      `json:"enabled"`
}

// AutoBackupConfig 是自动备份配置。备份文件保存在 DataDir/backups/。
type AutoBackupConfig struct {
	Enabled      bool      `json:"enabled"`
	Interval     string    `json:"interval"`      // daily | weekly
	Hour         int       `json:"hour"`          // 0-23，本地时间
	Keep         int       `json:"keep"`          // 保留份数，1-50
	IncludeCerts bool      `json:"include_certs"` // 是否把证书目录一并打包
	LastRun      time.Time `json:"last_run"`
	LastResult   string    `json:"last_result"`
}

// RetryPolicy 是失败任务指数退避自动重试策略。
type RetryPolicy struct {
	Enabled     bool `json:"enabled"`
	MaxAttempts int  `json:"max_attempts"` // 含首次执行，2-10
	BaseDelay   int  `json:"base_delay"`   // 秒，5-3600
	MaxDelay    int  `json:"max_delay"`    // 秒，>= BaseDelay
}

// ACMEAccount 是从 acme.sh 账户目录解析出的账户摘要。
type ACMEAccount struct {
	ID             string `json:"id"`
	CA             string `json:"ca"`
	Email          string `json:"email"`
	AccountDir     string `json:"account_dir"`     // 相对 ACME_HOME 的路径，避免暴露宿主机绝对路径
	KeyFingerprint string `json:"key_fingerprint"` // 账户密钥 SHA-256 前 16 位
	Default        bool   `json:"default"`         // 是否为当前默认 CA
}

// ConfigDiff 是一条配置变更对比记录。
type ConfigDiff struct {
	ID       int64     `json:"id"`
	TS       time.Time `json:"ts"`
	User     string    `json:"user"`
	IP       string    `json:"ip"`
	Action   string    `json:"action"`
	Category string    `json:"category"`
	Before   string    `json:"before"`
	After    string    `json:"after"`
}

// HealthReport 是一次健康自检的完整结果。
type HealthReport struct {
	TS      time.Time     `json:"ts"`
	Overall string        `json:"overall"` // ok | warn | fail
	Checks  []HealthCheck `json:"checks"`
}

type HealthCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"` // ok | warn | fail
	Detail string `json:"detail"`
}

// BackupRecord 是一次备份的元数据（实际文件在 DataDir/backups/）。
type BackupRecord struct {
	ID     int64     `json:"id"`
	TS     time.Time `json:"ts"`
	Name   string    `json:"name"`
	Size   int64     `json:"size"`
	Kind   string    `json:"kind"` // auto | manual
	Status string    `json:"status"`
	Detail string    `json:"detail"`
}

// ScheduleInfo 是统一计划任务页的一项。
type ScheduleInfo struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
	Detail      string `json:"detail"`
	NextRun     string `json:"next_run"`
	Category    string `json:"category"`
}

func validInterval(v string) bool { return v == "daily" || v == "weekly" }

func validTokenScope(v string) bool {
	return v == "certs" || v == "jobs" || v == "sync" || v == "audit" || v == "overview"
}

// ---------------- State 字段扩展 ----------------

// extendState 给 State 追加新字段。单独文件声明避免动 store.go 的大段结构定义时出错。
// Go 不允许跨文件扩展 struct，因此这里用方法包装：实际字段直接加在 State 定义中（见 store.go）。

// ---------------- Store 新方法 ----------------

func (s *Store) mutateState(fn func(*State)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.state)
	return s.saveLocked()
}

func (s *Store) SetIPAllowlist(list []string) error {
	return s.mutateState(func(st *State) { st.IPAllowlist = append([]string(nil), list...) })
}

func (s *Store) SetAllowLocalBypass(v bool) error {
	return s.mutateState(func(st *State) { st.AllowLocalBypass = v })
}

func (s *Store) SetAPITokens(tokens []APIToken) error {
	return s.mutateState(func(st *State) { st.APITokens = append([]APIToken(nil), tokens...) })
}

func (s *Store) SetAutoBackup(cfg AutoBackupConfig) error {
	return s.mutateState(func(st *State) { st.AutoBackup = cfg })
}

func (s *Store) SetRetryPolicy(p RetryPolicy) error {
	return s.mutateState(func(st *State) { st.RetryPolicy = p })
}

func (s *Store) SetLocale(v string) error {
	return s.mutateState(func(st *State) { st.Locale = v })
}

func (s *Store) SetACMEAccounts(accounts []ACMEAccount) error {
	return s.mutateState(func(st *State) { st.ACMEAccounts = append([]ACMEAccount(nil), accounts...) })
}

func (s *Store) MarkTokenUsed(id string) {
	_ = s.mutateState(func(st *State) {
		for i := range st.APITokens {
			if st.APITokens[i].ID == id {
				st.APITokens[i].LastUsed = time.Now()
			}
		}
	})
}

// ---------------- 记录表（Diff / 自检 / 备份）----------------

const (
	maxConfigDiffs     = 300
	maxHealthSnapshots = 100
	maxBackupRecords   = 100
)

func (s *Store) AddConfigDiff(user, ip, action, category, before, after string) {
	if s.db == nil {
		return
	}
	_, _ = s.db.Exec(`INSERT INTO config_diffs(ts,user,ip,action,category,before,after) VALUES(?,?,?,?,?,?,?)`,
		time.Now().Format(time.RFC3339Nano), user, ip, action, category, before, after)
	s.trimTable("config_diffs", maxConfigDiffs)
}

func (s *Store) QueryConfigDiffs(action, category string, limit, offset int) ([]ConfigDiff, int, error) {
	if s.db == nil {
		return nil, 0, errNoDB
	}
	if limit < 1 || limit > 100 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	where, args := []string{"1=1"}, []any{}
	if action != "" {
		where = append(where, "action=?")
		args = append(args, action)
	}
	if category != "" {
		where = append(where, "category=?")
		args = append(args, category)
	}
	w := strings.Join(where, " AND ")
	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM config_diffs WHERE `+w, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(`SELECT id,ts,user,ip,action,category,before,after FROM config_diffs WHERE `+w+
		` ORDER BY id DESC LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []ConfigDiff{}
	for rows.Next() {
		var d ConfigDiff
		var ts string
		if err := rows.Scan(&d.ID, &ts, &d.User, &d.IP, &d.Action, &d.Category, &d.Before, &d.After); err != nil {
			continue
		}
		d.TS, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, d)
	}
	return out, total, nil
}

func (s *Store) ConfigDiffActions() []string {
	return s.distinctColumn("config_diffs", "action")
}

func (s *Store) ConfigDiffCategories() []string {
	return s.distinctColumn("config_diffs", "category")
}

func (s *Store) distinctColumn(table, col string) []string {
	out := []string{}
	if s.db == nil {
		return out
	}
	// 白名单：只允许本项目固定表名与列名，杜绝拼接注入。
	allowed := map[string]bool{"config_diffs|action": true, "config_diffs|category": true}
	if !allowed[table+"|"+col] {
		return out
	}
	rows, err := s.db.Query(`SELECT DISTINCT ` + col + ` FROM ` + table + ` ORDER BY ` + col)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var v string
		if rows.Scan(&v) == nil && v != "" {
			out = append(out, v)
		}
	}
	return out
}

func (s *Store) AddHealthReport(r HealthReport) {
	if s.db == nil {
		return
	}
	b, _ := json.Marshal(r)
	_, _ = s.db.Exec(`INSERT INTO health_snapshots(ts,result) VALUES(?,?)`,
		r.TS.Format(time.RFC3339Nano), string(b))
	s.trimTable("health_snapshots", maxHealthSnapshots)
}

func (s *Store) RecentHealthReports(limit int) []HealthReport {
	out := []HealthReport{}
	if s.db == nil {
		return out
	}
	if limit < 1 || limit > maxHealthSnapshots {
		limit = 20
	}
	rows, err := s.db.Query(`SELECT result FROM health_snapshots ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		if rows.Scan(&raw) != nil {
			continue
		}
		var r HealthReport
		if json.Unmarshal([]byte(raw), &r) == nil {
			out = append(out, r)
		}
	}
	return out
}

func (s *Store) AddBackupRecord(rec BackupRecord) int64 {
	if s.db == nil {
		return 0
	}
	res, err := s.db.Exec(`INSERT INTO backups(ts,name,size,kind,status,detail) VALUES(?,?,?,?,?,?)`,
		rec.TS.Format(time.RFC3339Nano), rec.Name, rec.Size, rec.Kind, rec.Status, rec.Detail)
	if err == nil {
		s.trimTable("backups", maxBackupRecords)
		if id, e := res.LastInsertId(); e == nil {
			return id
		}
	}
	return 0
}

func (s *Store) ListBackups(limit int) []BackupRecord {
	out := []BackupRecord{}
	if s.db == nil {
		return out
	}
	if limit < 1 || limit > maxBackupRecords {
		limit = 50
	}
	rows, err := s.db.Query(`SELECT id,ts,name,size,kind,status,detail FROM backups ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var r BackupRecord
		var ts string
		if rows.Scan(&r.ID, &ts, &r.Name, &r.Size, &r.Kind, &r.Status, &r.Detail) != nil {
			continue
		}
		r.TS, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, r)
	}
	return out
}

func (s *Store) DeleteBackupRecord(id int64) bool {
	if s.db == nil {
		return false
	}
	res, err := s.db.Exec(`DELETE FROM backups WHERE id=?`, id)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}

func (s *Store) trimTable(table string, keep int) {
	if s.db == nil || keep < 1 {
		return
	}
	allowed := map[string]bool{"config_diffs": true, "health_snapshots": true, "backups": true}
	if !allowed[table] {
		return
	}
	_, _ = s.db.Exec(`DELETE FROM `+table+` WHERE id IN (SELECT id FROM `+table+
		` ORDER BY id DESC LIMIT -1 OFFSET ?)`, keep)
}

// ---------------- IP / CIDR 白名单 ----------------

func parseCIDRList(list []string) ([]*net.IPNet, error) {
	out := []*net.IPNet{}
	for _, raw := range list {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if !strings.Contains(s, "/") {
			ip := net.ParseIP(s)
			if ip == nil {
				return nil, fmt.Errorf("无效 IP：%s", s)
			}
			bits := 128
			if ip.To4() != nil {
				bits = 32
			}
			s = fmt.Sprintf("%s/%d", s, bits)
		}
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("无效 CIDR：%s", s)
		}
		out = append(out, n)
	}
	return out, nil
}

// ipAllowed 返回 false 表示该来源应被拒绝。空白名单 = 不限制。
// 本地回环豁免由 allowLocal 控制（默认开），避免误配后连 localhost 都进不来。
func ipAllowed(ipStr string, allowlist []string, allowLocal bool) bool {
	if len(allowlist) == 0 {
		return true
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if allowLocal && ip.IsLoopback() {
		return true
	}
	nets, err := parseCIDRList(allowlist)
	if err != nil {
		return false // 配置非法时保守拒绝，回环仍可进入修正
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ---------------- 只读 API Token ----------------

const apiTokenHeader = "X-API-Token"
const apiTokenPrefix = "acmp_"

func newAPIToken(name string, scopes []string) (APIToken, string) {
	raw := apiTokenPrefix + randToken(32)
	sum := sha256.Sum256([]byte(raw))
	sorted := append([]string(nil), scopes...)
	sort.Strings(sorted)
	return APIToken{
		ID:      randToken(12),
		Name:    name,
		Prefix:  raw[:len(apiTokenPrefix)+6],
		Hash:    hex.EncodeToString(sum[:]),
		Scopes:  sorted,
		Created: time.Now(),
		Enabled: true,
	}, raw
}

func tokenHash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func tokenMatches(t APIToken, raw string) bool {
	if !t.Enabled {
		return false
	}
	h := tokenHash(raw)
	return subtle.ConstantTimeCompare([]byte(h), []byte(t.Hash)) == 1
}

// tokenScopeAllowed 检查路径是否落在 token 允许的只读端点内。
func tokenScopeAllowed(scopes []string, path string) bool {
	if len(scopes) == 0 {
		return true
	}
	for _, sc := range scopes {
		if sc == "certs" && strings.HasPrefix(path, "/api/certs") {
			return true
		}
		if sc == "jobs" && strings.HasPrefix(path, "/api/jobs") {
			return true
		}
		if sc == "sync" && (strings.HasPrefix(path, "/api/sync") || strings.HasPrefix(path, "/api/remote")) {
			return true
		}
		if sc == "audit" && strings.HasPrefix(path, "/api/audit") {
			return true
		}
		if sc == "overview" && (path == "/api/overview" || path == "/api/storage" || path == "/api/health/report") {
			return true
		}
	}
	return false
}

// ---------------- 配置 Diff 辅助 ----------------

var diffSecretRe = regexp.MustCompile(`(?i)("(?:password|secret|token|key|target|api_key|private_key)"\s*:\s*)"[^"]*"`)

// redactDiff 对配置对比里的敏感字段打码。Diff 用于审计追溯，绝不保留明文凭证。
func redactDiff(s string) string {
	if s == "" {
		return s
	}
	s = diffSecretRe.ReplaceAllString(s, `${1}"***"`)
	if len(s) > 8000 {
		s = s[:8000] + "…(truncated)"
	}
	return s
}

func (s *Server) recordDiff(r *http.Request, action, category, before, after string) {
	u, ip := "", ""
	if ss := sess(r); ss != nil {
		u, ip = ss.User, ss.IP
	} else {
		ip = clientIP(r, s.cfg.TrustProxy)
	}
	s.store.AddConfigDiff(u, ip, action, category, redactDiff(before), redactDiff(after))
	if u != "" {
		s.store.Audit(u, ip, "config_change", category+": "+action)
	}
}

func jsonSnapshot(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}

// ---------------- 备份文件辅助 ----------------

func (s *Server) backupDir() string { return filepath.Join(s.cfg.DataDir, "backups") }

func (s *Server) backupPath(name string) (string, error) {
	dir := s.backupDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	// name 由本模块生成（时间戳+随机），仍做一次 basename 校验防路径穿越。
	if filepath.Base(name) != name || strings.ContainsAny(name, `/\\`) {
		return "", fmt.Errorf("非法备份文件名")
	}
	return filepath.Join(dir, name), nil
}

// ---------------- 工具 ----------------

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func parseIntDefault(s string, def int) int {
	if v, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return v
	}
	return def
}

// ---------------- 入口中间件 ----------------

// requireIPAllowlist 在所有入口最外层生效：白名单命中前不暴露面板是否存在。
// /api/health 始终放行，避免容器健康检查因 IP 策略被判为不健康。
func (s *Server) requireIPAllowlist(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/health" {
			next.ServeHTTP(w, r)
			return
		}
		st := s.store.Snapshot()
		ip := clientIP(r, s.cfg.TrustProxy)
		if !ipAllowed(ip, st.IPAllowlist, st.AllowLocalBypass) {
			s.store.Audit("", ip, "ip_blocked", r.URL.Path)
			writeErr(w, http.StatusForbidden, "访问来源不在允许列表内")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireRead 允许会话 Cookie 或只读 API Token 访问 GET 端点。
// Token 只允许 GET/HEAD，写操作必须走完整会话 + CSRF。
func (s *Server) requireRead(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			if raw := r.Header.Get(apiTokenHeader); raw != "" {
				for _, t := range s.store.Snapshot().APITokens {
					if tokenMatches(t, raw) && tokenScopeAllowed(t.Scopes, r.URL.Path) {
						s.store.MarkTokenUsed(t.ID)
						h(w, r)
						return
					}
				}
				writeErr(w, http.StatusUnauthorized, "只读令牌无效或无权访问该端点")
				return
			}
		}
		s.requireAuth(h)(w, r)
	}
}
