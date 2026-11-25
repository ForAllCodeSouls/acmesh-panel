package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// pbkdf2Iter 是密码哈希的迭代次数。600k 次在常规 CPU 上约 100~200ms，
// 足以让离线爆破成本高昂，同时不影响交互体验。
const pbkdf2Iter = 600000

// EncEnv 是加密后的 DNS 服务商凭证。明文永不落盘，也不出现在日志/API 里。
type EncEnv struct {
	Code string `json:"code"`
	Blob string `json:"blob"` // base64(nonce || ciphertext)
}

// EncNotifier 是整体加密后的通知渠道配置（URL 里常带 token，因此连同 Secret 一起加密）。
type EncNotifier struct {
	Blob string `json:"blob"`
}

// EncRemote 是整体加密后的远程主机配置（含 SSH 私钥）。
type EncRemote struct {
	Blob string `json:"blob"`
}

// RemoteHost 是一台远程证书同步目标（SSH 私钥或账号密码认证）。
type RemoteHost struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	User      string `json:"user"`
	RemoteDir string `json:"remote_dir"`
	Key       string `json:"key"`       // SSH 私钥内容（加密存储，接口只回掩码）
	Password  string `json:"password"`  // SSH 登录密码（加密存储，接口只回掩码）
	AutoPush  bool   `json:"auto_push"` // 本地同步成功后自动推送；关闭时只能手动强制推送
	Enabled   bool   `json:"enabled"`
}

// RemoteHostView 是返回给前端的安全视图（不含私钥/密码明文）。
type RemoteHostView struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Host           string `json:"host"`
	Port           int    `json:"port"`
	User           string `json:"user"`
	RemoteDir      string `json:"remote_dir"`
	KeyMasked      string `json:"key_masked"`
	HasKey         bool   `json:"has_key"`
	PasswordMasked string `json:"password_masked"`
	HasPassword    bool   `json:"has_password"`
	AuthMode       string `json:"auth_mode"` // key | password
	AutoPush       bool   `json:"auto_push"`
	Enabled        bool   `json:"enabled"`
}

// Notifier 是一个通知渠道。Target 是 base URL 或完整 webhook URL，Secret 是 token。
type Notifier struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Kind    string   `json:"kind"`
	Target  string   `json:"target"`
	Secret  string   `json:"secret"`
	Events  []string `json:"events"`
	Enabled bool     `json:"enabled"`
}

// State 是面板的持久化状态，存于 /data/state.json（0600）。
type State struct {
	Username      string                 `json:"username"`
	Salt          string                 `json:"salt"`
	Hash          string                 `json:"hash"`
	Iter          int                    `json:"iter"`
	UpdatedAt     time.Time              `json:"updated_at"`
	Providers     map[string]EncEnv      `json:"providers"`
	Notifiers     map[string]EncNotifier `json:"notifiers"`
	DefaultEmail  string                 `json:"default_email"`
	CertEmails    map[string]string      `json:"cert_emails"`    // 证书目录名 -> 该域名自定义 ACME 邮箱
	NotifySent    map[string]string      `json:"notify_sent"`    // 证书目录名 -> 最近一次临期提醒日期
	SyncRules     []SyncRule             `json:"sync_rules"`     // 证书同步规则
	SyncEvents    []SyncEvent            `json:"sync_events"`    // 最近同步记录
	SyncSeen      map[string]string      `json:"sync_seen"`      // 同步目标 -> 上次写入的源证书指纹（仅证书内容摘要，非凭证）
	RemoteSeen    map[string]string      `json:"remote_seen"`    // 主机|目录|文件名 -> 上次成功推送的文件内容摘要（仅摘要，非凭证）
	RemoteHosts   map[string]EncRemote   `json:"remote_hosts"`   // 远程主机（整体加密，含 SSH 私钥）
	CronHour      int                    `json:"cron_hour"`      // 每日自动检测时间（0-23 点），未设置默认 3 点
	CronLastDay   string                 `json:"cron_last_day"`  // 上次自动检测的本地日期 YYYY-MM-DD
	RetentionDays int                    `json:"retention_days"` // 任务/审计/同步记录保留天数，0 表示不清理
}

// Store 负责状态持久化、凭证加解密、密码校验与审计日志。
type Store struct {
	dir string
	db  *sql.DB

	mu    sync.RWMutex
	state State
	aead  cipher.AEAD

	auditMu sync.Mutex
}

func loadOrCreateKey(path string) ([]byte, error) {
	if b, err := os.ReadFile(path); err == nil {
		if len(b) != 32 {
			return nil, fmt.Errorf("secret.key 长度异常 (%d 字节)，应为 32", len(b))
		}
		return b, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	db, err := openDB(dir)
	if err != nil {
		return nil, err
	}
	key, err := loadOrCreateKey(filepath.Join(dir, "secret.key"))
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	s := &Store{dir: dir, db: db, aead: gcm}
	s.state.Providers = map[string]EncEnv{}
	s.state.Notifiers = map[string]EncNotifier{}
	s.state.CertEmails = map[string]string{}
	s.state.NotifySent = map[string]string{}
	s.state.SyncSeen = map[string]string{}
	s.state.RemoteSeen = map[string]string{}
	s.state.CronHour = 3 // 默认每天 3 点检测
	s.state.RetentionDays = 30
	s.load()
	return s, nil
}

func (s *Store) load() {
	var raw string
	if err := s.db.QueryRow(`SELECT value FROM state WHERE key='main'`).Scan(&raw); err != nil {
		return // 全新安装：保留 NewStore 里的默认值
	}
	var st State
	if json.Unmarshal([]byte(raw), &st) != nil {
		return
	}
	if st.Providers == nil {
		st.Providers = map[string]EncEnv{}
	}
	if st.Notifiers == nil {
		st.Notifiers = map[string]EncNotifier{}
	}
	if st.CertEmails == nil {
		st.CertEmails = map[string]string{}
	}
	if st.NotifySent == nil {
		st.NotifySent = map[string]string{}
	}
	if st.SyncSeen == nil {
		st.SyncSeen = map[string]string{}
	}
	if st.RemoteSeen == nil {
		st.RemoteSeen = map[string]string{}
	}
	// 兼容旧数据：没有这些字段时给出默认值
	var rawFields map[string]json.RawMessage
	if json.Unmarshal([]byte(raw), &rawFields) == nil {
		if _, ok := rawFields["cron_hour"]; !ok {
			st.CronHour = 3
		}
		if _, ok := rawFields["retention_days"]; !ok {
			st.RetentionDays = 30
		}
	}
	if st.CronHour < 0 || st.CronHour > 23 {
		st.CronHour = 3
	}
	if st.RetentionDays < 0 {
		st.RetentionDays = 0
	}
	s.state = st
}

func (s *Store) saveLocked() error {
	b, err := json.Marshal(s.state)
	if err != nil {
		return err
	}
	if s.db == nil {
		return errNoDB
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	_, err = tx.Exec(`INSERT INTO state(key,value) VALUES('main',?) `+
		`ON CONFLICT(key) DO UPDATE SET value=excluded.value`, string(b))
	if err != nil {
		return err
	}
	return tx.Commit()
}

// Close 关闭状态数据库；测试与进程退出时使用。
func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

func (s *Store) Snapshot() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st := s.state
	st.Providers = make(map[string]EncEnv, len(s.state.Providers))
	for k, v := range s.state.Providers {
		st.Providers[k] = v
	}
	st.Notifiers = make(map[string]EncNotifier, len(s.state.Notifiers))
	for k, v := range s.state.Notifiers {
		st.Notifiers[k] = v
	}
	st.CertEmails = make(map[string]string, len(s.state.CertEmails))
	for k, v := range s.state.CertEmails {
		st.CertEmails[k] = v
	}
	st.NotifySent = make(map[string]string, len(s.state.NotifySent))
	for k, v := range s.state.NotifySent {
		st.NotifySent[k] = v
	}
	st.SyncRules = append([]SyncRule(nil), s.state.SyncRules...)
	st.SyncEvents = append([]SyncEvent(nil), s.state.SyncEvents...)
	st.SyncSeen = make(map[string]string, len(s.state.SyncSeen))
	for k, v := range s.state.SyncSeen {
		st.SyncSeen[k] = v
	}
	st.RemoteSeen = make(map[string]string, len(s.state.RemoteSeen))
	for k, v := range s.state.RemoteSeen {
		st.RemoteSeen[k] = v
	}
	return st
}

func (s *Store) Username() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.Username
}

// SetPassword 设置（或重置）密码。使用 PBKDF2-HMAC-SHA256 + 随机盐。
func (s *Store) SetPassword(password string) error {
	if len(password) < 8 {
		return errors.New("密码至少 8 位")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	dk, err := pbkdf2.Key(sha256.New, password, salt, pbkdf2Iter, 32)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Salt = base64.StdEncoding.EncodeToString(salt)
	s.state.Hash = base64.StdEncoding.EncodeToString(dk)
	s.state.Iter = pbkdf2Iter
	s.state.UpdatedAt = time.Now().UTC()
	if s.state.Providers == nil {
		s.state.Providers = map[string]EncEnv{}
	}
	return s.saveLocked()
}

// SetupInitialCredentials 仅在尚无密码时原子写入账号与密码，防止并发重复注册覆盖。
func (s *Store) SetupInitialCredentials(user, password string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Hash != "" {
		return errors.New("账号已初始化")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	dk, err := pbkdf2.Key(sha256.New, password, salt, pbkdf2Iter, 32)
	if err != nil {
		return err
	}
	s.state.Username = user
	s.state.Salt = base64.StdEncoding.EncodeToString(salt)
	s.state.Hash = base64.StdEncoding.EncodeToString(dk)
	s.state.Iter = pbkdf2Iter
	s.state.UpdatedAt = time.Now().UTC()
	return s.saveLocked()
}

func (s *Store) HasPassword() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.Hash != ""
}

func (s *Store) SetUsername(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Username = name
	return s.saveLocked()
}

// CheckPassword 用恒定时间比较校验密码。
func (s *Store) CheckPassword(password string) bool {
	s.mu.RLock()
	saltB64, hashB64, iter, user := s.state.Salt, s.state.Hash, s.state.Iter, s.state.Username
	s.mu.RUnlock()
	if hashB64 == "" || saltB64 == "" {
		return false
	}
	if iter <= 0 {
		iter = pbkdf2Iter
	}
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return false
	}
	want, err := base64.StdEncoding.DecodeString(hashB64)
	if err != nil {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iter, len(want))
	if err != nil {
		return false
	}
	_ = user
	return subtle.ConstantTimeCompare(got, want) == 1
}

// CheckUsername 恒定时间比较用户名，避免通过响应时间枚举。
func (s *Store) CheckUsername(name string) bool {
	s.mu.RLock()
	want := s.state.Username
	s.mu.RUnlock()
	// 先各自哈希成定长摘要再比较，不因长度差异提前返回。
	a := sha256.Sum256([]byte(want))
	b := sha256.Sum256([]byte(name))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

func (s *Store) PutProvider(name, code string, env map[string]string) error {
	if name == "" || code == "" {
		return errors.New("provider 名称与类型不能为空")
	}
	plain, err := json.Marshal(env)
	if err != nil {
		return err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	ct := s.aead.Seal(nil, nonce, plain, []byte(name+"|"+code))
	blob := base64.StdEncoding.EncodeToString(append(nonce, ct...))

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Providers == nil {
		s.state.Providers = map[string]EncEnv{}
	}
	s.state.Providers[name] = EncEnv{Code: code, Blob: blob}
	return s.saveLocked()
}

func (s *Store) GetProvider(name string) (string, map[string]string, error) {
	s.mu.RLock()
	enc, ok := s.state.Providers[name]
	s.mu.RUnlock()
	if !ok {
		return "", nil, errors.New("凭证不存在")
	}
	raw, err := base64.StdEncoding.DecodeString(enc.Blob)
	if err != nil {
		return "", nil, err
	}
	ns := s.aead.NonceSize()
	if len(raw) < ns {
		return "", nil, errors.New("凭证数据损坏")
	}
	plain, err := s.aead.Open(nil, raw[:ns], raw[ns:], []byte(name+"|"+enc.Code))
	if err != nil {
		return "", nil, errors.New("凭证解密失败（secret.key 可能已更换）")
	}
	var env map[string]string
	if err := json.Unmarshal(plain, &env); err != nil {
		return "", nil, err
	}
	return enc.Code, env, nil
}

func (s *Store) DeleteProvider(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.state.Providers, name)
	return s.saveLocked()
}

type ProviderView struct {
	Name   string            `json:"name"`
	Code   string            `json:"code"`
	Masked map[string]string `json:"masked"`
}

func (s *Store) ListProviders() []ProviderView {
	st := s.Snapshot()
	out := make([]ProviderView, 0, len(st.Providers))
	for name, enc := range st.Providers {
		v := ProviderView{Name: name, Code: enc.Code, Masked: map[string]string{}}
		if _, env, err := s.GetProvider(name); err == nil {
			for k, val := range env {
				v.Masked[k] = mask(val)
			}
		}
		out = append(out, v)
	}
	return out
}

// mask 只保留末 4 位，其余打码。
func mask(v string) string {
	if v == "" {
		return ""
	}
	r := []rune(v)
	if len(r) < 16 {
		return "••••••••"
	}
	return "••••••••" + string(r[len(r)-4:])
}

// ---------------- 通知渠道（整体加密存储） ----------------

func (s *Store) PutNotifier(n Notifier) error {
	if n.ID == "" || n.Name == "" || n.Kind == "" {
		return errors.New("渠道 ID / 名称 / 类型不能为空")
	}
	plain, err := json.Marshal(n)
	if err != nil {
		return err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	// AAD 只绑定 ID：读取时无需先解密即可得到它，同时防止密文被挪到别的渠道下。
	ct := s.aead.Seal(nil, nonce, plain, []byte(n.ID))
	blob := base64.StdEncoding.EncodeToString(append(nonce, ct...))

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Notifiers == nil {
		s.state.Notifiers = map[string]EncNotifier{}
	}
	s.state.Notifiers[n.ID] = EncNotifier{Blob: blob}
	return s.saveLocked()
}

func (s *Store) GetNotifier(id string) (Notifier, error) {
	s.mu.RLock()
	enc, ok := s.state.Notifiers[id]
	s.mu.RUnlock()
	if !ok {
		return Notifier{}, errors.New("通知渠道不存在")
	}
	raw, err := base64.StdEncoding.DecodeString(enc.Blob)
	if err != nil {
		return Notifier{}, err
	}
	ns := s.aead.NonceSize()
	if len(raw) < ns {
		return Notifier{}, errors.New("通知渠道数据损坏")
	}
	plain, err := s.aead.Open(nil, raw[:ns], raw[ns:], []byte(id))
	if err != nil {
		return Notifier{}, errors.New("通知渠道解密失败（secret.key 可能已更换）")
	}
	var n Notifier
	if err := json.Unmarshal(plain, &n); err != nil {
		return Notifier{}, err
	}
	return n, nil
}

func (s *Store) DeleteNotifier(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.state.Notifiers, id)
	return s.saveLocked()
}

type NotifierView struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Kind         string   `json:"kind"`
	TargetMasked string   `json:"target_masked"`
	SecretMasked string   `json:"secret_masked"`
	Events       []string `json:"events"`
	Enabled      bool     `json:"enabled"`
}

func (s *Store) ListNotifiers() []NotifierView {
	st := s.Snapshot()
	out := make([]NotifierView, 0, len(st.Notifiers))
	for id := range st.Notifiers {
		n, err := s.GetNotifier(id)
		if err != nil {
			continue
		}
		out = append(out, NotifierView{
			ID:           n.ID,
			Name:         n.Name,
			Kind:         n.Kind,
			TargetMasked: mask(n.Target),
			SecretMasked: mask(n.Secret),
			Events:       n.Events,
			Enabled:      n.Enabled,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ---------------- 默认邮箱 / 按域名邮箱 ----------------

func (s *Store) SetDefaultEmail(email string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.DefaultEmail = strings.TrimSpace(email)
	return s.saveLocked()
}

func (s *Store) DefaultEmail() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.DefaultEmail
}

// SetCertEmail 设置某个域名的专用 ACME 邮箱；传空字符串表示恢复使用默认邮箱。
func (s *Store) SetCertEmail(name, email string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.CertEmails == nil {
		s.state.CertEmails = map[string]string{}
	}
	email = strings.TrimSpace(email)
	if email == "" {
		delete(s.state.CertEmails, name)
	} else {
		s.state.CertEmails[name] = email
	}
	return s.saveLocked()
}

func (s *Store) CertEmail(name string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.CertEmails[name]
}

func (s *Store) AllCertEmails() map[string]string {
	st := s.Snapshot()
	return st.CertEmails
}

// MarkNotified / NotifiedToday 用于临期提醒按天去重，避免每 12 小时重复轰炸。
func (s *Store) MarkNotified(name, day string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.NotifySent == nil {
		s.state.NotifySent = map[string]string{}
	}
	s.state.NotifySent[name] = day
	return s.saveLocked()
}

func (s *Store) NotifiedToday(name, day string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.NotifySent[name] == day
}

// Audit 追加一条审计记录到 SQLite（单条事务写入，不会写半行）。
func (s *Store) Audit(user, ip, action, detail string) {
	if s.db == nil {
		return
	}
	_, _ = s.db.Exec(`INSERT INTO audit(ts,user,ip,action,detail) VALUES(?,?,?,?,?)`,
		time.Now().Format(time.RFC3339), user, ip, action, detail)
}

// AuditTail 返回最近 n 条审计记录（新的在前）。
func (s *Store) AuditTail(n int) []map[string]any {
	if s.db == nil || n <= 0 {
		return nil
	}
	rows, err := s.db.Query(`SELECT ts,user,ip,action,detail FROM audit ORDER BY id DESC LIMIT ?`, n)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var ts, user, ip, action, detail string
		if err := rows.Scan(&ts, &user, &ip, &action, &detail); err != nil {
			continue
		}
		out = append(out, map[string]any{
			"ts": ts, "user": user, "ip": ip, "action": action, "detail": detail,
		})
	}
	return out
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// ---------------- 数据保留 ----------------

// RetentionDays 返回任务/审计/同步记录保留天数，0 表示不清理。
func (s *Store) RetentionDays() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.RetentionDays
}

// SetRetentionDays 设置保留天数（0 表示永不清理，最长 3650 天）。
func (s *Store) SetRetentionDays(days int) error {
	if days < 0 || days > 3650 {
		return errors.New("保留天数必须在 0-3650 之间")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.RetentionDays = days
	return s.saveLocked()
}

// ---------------- 自动检测调度 ----------------

// CronSchedule 返回配置的小时与上次检测日期。
func (s *Store) CronSchedule() (hour int, lastDay string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	h := s.state.CronHour
	if h < 0 || h > 23 {
		h = 3
	}
	return h, s.state.CronLastDay
}

func (s *Store) SetCronHour(hour int) error {
	if hour < 0 || hour > 23 {
		return errors.New("小时必须在 0-23 之间")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.CronHour = hour
	return s.saveLocked()
}

// MarkCronRun 标记某天已执行过自动检测，避免重启后重复执行。
func (s *Store) MarkCronRun(day string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.CronLastDay = day
	return s.saveLocked()
}

// ---------------- 证书同步规则 ----------------

func (s *Store) ListSyncRules() []SyncRule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]SyncRule(nil), s.state.SyncRules...)
}

func (s *Store) PutSyncRule(r SyncRule) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	found := false
	for i := range s.state.SyncRules {
		if s.state.SyncRules[i].ID == r.ID {
			old := s.state.SyncRules[i]
			if r.LastSync == "" {
				r.LastSync = old.LastSync
				r.LastInfo = old.LastInfo
			}
			s.state.SyncRules[i] = r
			found = true
			break
		}
	}
	if !found {
		s.state.SyncRules = append(s.state.SyncRules, r)
	}
	return s.saveLocked()
}

func (s *Store) DeleteSyncRule(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.state.SyncRules[:0]
	for _, r := range s.state.SyncRules {
		if r.ID != id {
			out = append(out, r)
		}
	}
	s.state.SyncRules = out
	return s.saveLocked()
}

func (s *Store) TouchSyncRule(id, info string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.state.SyncRules {
		if s.state.SyncRules[i].ID == id {
			s.state.SyncRules[i].LastSync = time.Now().Format(time.RFC3339)
			if len(info) > 240 {
				info = info[:240]
			}
			s.state.SyncRules[i].LastInfo = info
			break
		}
	}
	return s.saveLocked()
}

func (s *Store) AddSyncEvents(evs []SyncEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.SyncEvents = append(s.state.SyncEvents, evs...)
	if len(s.state.SyncEvents) > 120 {
		s.state.SyncEvents = append([]SyncEvent(nil), s.state.SyncEvents[len(s.state.SyncEvents)-120:]...)
	}
	return s.saveLocked()
}

func (s *Store) ClearSyncEvents() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.SyncEvents = nil
	return s.saveLocked()
}

// SyncSeens 返回同步指纹表的副本，供同步引擎判断证书是否变化。
func (s *Store) SyncSeens() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]string, len(s.state.SyncSeen))
	for k, v := range s.state.SyncSeen {
		out[k] = v
	}
	return out
}

// MarkSyncSeen 批量记录目标文件本次写入所用的证书指纹，一次落盘。
func (s *Store) MarkSyncSeen(entries map[string]string) error {
	if len(entries) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.SyncSeen == nil {
		s.state.SyncSeen = map[string]string{}
	}
	for k, v := range entries {
		s.state.SyncSeen[k] = v
	}
	return s.saveLocked()
}

// SyncSeenCount 返回已记录指纹的目标文件数量，供 Web 显示。
func (s *Store) SyncSeenCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.state.SyncSeen)
}

// RemoteSeens 返回远程推送指纹表的副本，用于跳过内容未变化的文件。
func (s *Store) RemoteSeens() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]string, len(s.state.RemoteSeen))
	for k, v := range s.state.RemoteSeen {
		out[k] = v
	}
	return out
}

// MarkRemoteSeen 批量记录远程主机已成功推送的文件内容摘要，一次落盘。
func (s *Store) MarkRemoteSeen(entries map[string]string) error {
	if len(entries) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.RemoteSeen == nil {
		s.state.RemoteSeen = map[string]string{}
	}
	for k, v := range entries {
		s.state.RemoteSeen[k] = v
	}
	return s.saveLocked()
}

// RemoteSeenCount 返回已记录远程推送摘要的文件数量。
func (s *Store) RemoteSeenCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.state.RemoteSeen)
}

func (s *Store) ListSyncEvents() []SyncEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := append([]SyncEvent(nil), s.state.SyncEvents...)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	if len(out) > 40 {
		out = out[:40]
	}
	return out
}
