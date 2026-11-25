package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---------- DNS 服务商目录（只收录经过验证的 acme.sh dnsapi 实现）----------

type EnvField struct {
	Name     string `json:"name"`
	Label    string `json:"label"`
	Hint     string `json:"hint"`
	Optional bool   `json:"optional"`
	Secret   bool   `json:"secret"`
}

type ProviderDef struct {
	Code   string     `json:"code"`
	Name   string     `json:"name"`
	Fields []EnvField `json:"fields"`
}

var providerCatalog = []ProviderDef{
	{"dns_ali", "阿里云 DNS", []EnvField{
		{Name: "Ali_Key", Label: "AccessKey ID", Secret: true},
		{Name: "Ali_Secret", Label: "AccessKey Secret", Secret: true},
	}},
	{"dns_cf", "Cloudflare", []EnvField{
		{Name: "CF_Token", Label: "API Token", Hint: "Zone.DNS 编辑权限", Secret: true},
		{Name: "CF_Account_ID", Label: "Account ID", Optional: true},
		{Name: "CF_Zone_ID", Label: "Zone ID", Optional: true},
	}},
	{"dns_dp", "DNSPod (dnspod.cn)", []EnvField{
		{Name: "DP_Id", Label: "API ID"},
		{Name: "DP_Key", Label: "API Token", Secret: true},
	}},
	{"dns_tencent", "腾讯云 DNSPod", []EnvField{
		{Name: "Tencent_SecretId", Label: "SecretId", Secret: true},
		{Name: "Tencent_SecretKey", Label: "SecretKey", Secret: true},
	}},
	{"dns_gd", "GoDaddy", []EnvField{
		{Name: "GD_Key", Label: "API Key", Secret: true},
		{Name: "GD_Secret", Label: "API Secret", Secret: true},
	}},
	{"dns_huaweicloud", "华为云 DNS", []EnvField{
		{Name: "HUAWEICLOUD_Username", Label: "用户名"},
		{Name: "HUAWEICLOUD_Password", Label: "密码", Secret: true},
		{Name: "HUAWEICLOUD_ProjectID", Label: "Project ID", Optional: true},
	}},
	{"dns_aws", "AWS Route 53", []EnvField{
		{Name: "AWS_ACCESS_KEY_ID", Label: "Access Key ID", Secret: true},
		{Name: "AWS_SECRET_ACCESS_KEY", Label: "Secret Access Key", Secret: true},
		{Name: "AWS_REGION", Label: "Region", Optional: true, Hint: "默认 us-east-1"},
	}},
	{"dns_namecheap", "Namecheap", []EnvField{
		{Name: "NAMECHEAP_USERNAME", Label: "用户名"},
		{Name: "NAMECHEAP_API_KEY", Label: "API Key", Secret: true},
		{Name: "NAMECHEAP_SOURCEIP", Label: "白名单 IP", Optional: true},
	}},
	{"dns_dynu", "Dynu DNS", []EnvField{
		{Name: "Dynu_ClientId", Label: "Client ID", Hint: "Dynu 控制面板 → API Credentials 里的 OAuth2 Client ID，不是 API Key", Secret: true},
		{Name: "Dynu_Secret", Label: "Secret", Hint: "同一页面显示的 Secret", Secret: true},
	}},
	{"dns_he", "Hurricane Electric", []EnvField{
		{Name: "HE_Username", Label: "用户名"},
		{Name: "HE_Password", Label: "密码", Secret: true},
	}},
	{"dns_freedns", "FreeDNS", []EnvField{
		{Name: "FREEDNS_User", Label: "用户名"},
		{Name: "FREEDNS_Password", Label: "密码", Secret: true},
	}},
	{"dns_gandi", "Gandi LiveDNS", []EnvField{
		{Name: "GANDI_LIVEDNS_TOKEN", Label: "API Token", Secret: true},
	}},
	{"dns_do", "DigitalOcean", []EnvField{
		{Name: "DO_API_KEY", Label: "API Token", Secret: true},
	}},
	{"dns_linode", "Linode", []EnvField{
		{Name: "LINODE_V4_API_KEY", Label: "API Token", Secret: true},
	}},
	{"dns_vultr", "Vultr", []EnvField{
		{Name: "VULTR_API_KEY", Label: "API Key", Secret: true},
	}},
	{"dns_bunny", "Bunny.net", []EnvField{
		{Name: "BUNNY_API_KEY", Label: "API Key", Secret: true},
	}},
	{"dns_porkbun", "Porkbun", []EnvField{
		{Name: "PORKBUN_API_KEY", Label: "API Key", Secret: true},
		{Name: "PORKBUN_SECRET_API_KEY", Label: "Secret API Key", Secret: true},
	}},
	{"dns_desec", "deSEC", []EnvField{
		{Name: "DEDYN_TOKEN", Label: "API Token", Secret: true},
	}},
}

var providerByCode = func() map[string]ProviderDef {
	m := map[string]ProviderDef{}
	for _, p := range providerCatalog {
		m[p.Code] = p
	}
	return m
}()

// ---------- 参数校验 ----------

var (
	domainRe   = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	certNameRe = regexp.MustCompile(`^[A-Za-z0-9._*-]{1,253}$`)
	emailRe    = regexp.MustCompile(`^[^@\s]{1,64}@[^@\s]{1,190}$`)

	// acme.sh 未到续期时间时的输出：
	// [Tue Nov 24 19:41:26 UTC 2026] Skipping. Next renewal time is: 2027-02-09T19:04:24Z
	skipRe = regexp.MustCompile(`(?i)Skipping\.?\s*Next renewal time is:\s*([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]+Z)`)
)

func validDomain(d string) bool {
	d = strings.ToLower(strings.TrimSpace(d))
	if len(d) > 253 {
		return false
	}
	return domainRe.MatchString(d)
}

func validKeyLength(k string) bool {
	switch k {
	case "", "2048", "3072", "4096", "ec-256", "ec-384":
		return true
	}
	return false
}

var allowedCA = map[string]string{
	"letsencrypt":      "letsencrypt",
	"letsencrypt_test": "letsencrypt_test",
	"zerossl":          "zerossl",
	"buypass":          "buypass",
	"google":           "google",
}

// certName 校验证书域名/目录名，拒绝一切路径穿越与 shell 元字符。
func validCertName(name string) bool {
	if name == "" || strings.Contains(name, "..") || strings.ContainsAny(name, "/\\ \t\n\r\x00") {
		return false
	}
	return certNameRe.MatchString(name)
}

// ---------- acme.sh 调用（argv-only，绝不经过 shell）----------

type ACME struct {
	Home string
	Bin  string
	Log  string
}

var errAcmeMissing = errors.New("未找到 acme.sh，请检查镜像或 ACME_HOME 挂载")

func (a *ACME) cmd(ctx context.Context, env map[string]string, args ...string) *exec.Cmd {
	full := append([]string{"--home", a.Home, "--log", a.Log}, args...)
	c := exec.CommandContext(ctx, a.Bin, full...)
	c.Env = append(os.Environ(), "HOME="+a.Home, "LE_WORKING_DIR="+a.Home)
	for k, v := range env {
		c.Env = append(c.Env, k+"="+v)
	}
	return c
}

func (a *ACME) Version(ctx context.Context) string {
	if _, err := os.Stat(a.Bin); err != nil {
		return ""
	}
	c, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := a.cmd(c, nil, "--version").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// ---------- 任务队列 + 实时日志 ----------

type Job struct {
	ID      string    `json:"id"`
	Kind    string    `json:"kind"`
	Title   string    `json:"title"`
	Domain  string    `json:"domain"`
	Status  string    `json:"status"` // queued|running|success|failed|canceled
	Preview string    `json:"preview"`
	Error   string    `json:"error"`
	Created time.Time `json:"created"`
	Started time.Time `json:"started"`
	Ended   time.Time `json:"ended"`

	logs   []string
	Manual bool `json:"manual"` // 手动触发的任务才会展示"未到续签时间"提示
}

type JobManager struct {
	mu     sync.Mutex
	jobs   map[string]*Job
	order  []string
	subs   map[string]map[chan string]struct{}
	sem    chan struct{}
	canc   map[string]context.CancelFunc
	acme   *ACME
	store  *Store
	certs  *CertScanner
	onDone func(*Job) // 任务结束后异步触发通知（由 Server 注入）
}

// persistedJob 是落盘的任务记录（含日志），重启后可恢复。
type persistedJob struct {
	ID      string    `json:"id"`
	Kind    string    `json:"kind"`
	Title   string    `json:"title"`
	Domain  string    `json:"domain"`
	Status  string    `json:"status"`
	Preview string    `json:"preview"`
	Error   string    `json:"error"`
	Created time.Time `json:"created"`
	Started time.Time `json:"started"`
	Ended   time.Time `json:"ended"`
	Manual  bool      `json:"manual"`
	Logs    []string  `json:"logs"`
}

// loadPersisted 从 SQLite 恢复历史任务（只保留已完成/取消的）。
func (m *JobManager) loadPersisted() {
	if m.store == nil || m.store.DB() == nil {
		return
	}
	rows, err := m.store.DB().Query(`SELECT data FROM jobs ORDER BY created, id`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			continue
		}
		var p persistedJob
		if json.Unmarshal([]byte(raw), &p) != nil {
			continue
		}
		if p.Status == "running" || p.Status == "queued" {
			p.Status = "failed"
			p.Error = "面板重启导致任务中断"
		}
		j := &Job{
			ID: p.ID, Kind: p.Kind, Title: p.Title, Domain: p.Domain,
			Status: p.Status, Preview: p.Preview, Error: p.Error,
			Created: p.Created, Started: p.Started, Ended: p.Ended,
			Manual: p.Manual, logs: p.Logs,
		}
		m.jobs[j.ID] = j
		m.order = append(m.order, j.ID)
	}
	if len(m.order) > 200 {
		m.order = m.order[len(m.order)-200:]
	}
}

// savePersisted 把任务记录写入 SQLite（事务整体替换，不产生半写文件）。
func (m *JobManager) savePersisted() {
	if m.store == nil || m.store.DB() == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock() // 快照与事务提交必须同一把锁，否则旧快照可能后写覆盖新状态
	list := make([]persistedJob, 0, len(m.order))
	for _, id := range m.order {
		j, ok := m.jobs[id]
		if !ok {
			continue
		}
		list = append(list, persistedJob{
			ID: j.ID, Kind: j.Kind, Title: j.Title, Domain: j.Domain,
			Status: j.Status, Preview: j.Preview, Error: j.Error,
			Created: j.Created, Started: j.Started, Ended: j.Ended,
			Manual: j.Manual, Logs: append([]string(nil), j.logs...),
		})
	}

	tx, err := m.store.DB().Begin()
	if err != nil {
		return
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`DELETE FROM jobs`); err != nil {
		return
	}
	for _, p := range list {
		data, err := json.Marshal(p)
		if err != nil {
			return
		}
		created := p.Created.Format(time.RFC3339Nano)
		if p.Created.IsZero() {
			created = time.Now().Format(time.RFC3339Nano)
		}
		if _, err := tx.Exec(`INSERT INTO jobs(id,created,data) VALUES(?,?,?)`,
			p.ID, created, string(data)); err != nil {
			return
		}
	}
	_ = tx.Commit()
}

func NewJobManager(acme *ACME, store *Store, parallel int) *JobManager {
	if parallel < 1 {
		parallel = 1
	}
	m := &JobManager{
		jobs:  map[string]*Job{},
		subs:  map[string]map[chan string]struct{}{},
		sem:   make(chan struct{}, parallel),
		canc:  map[string]context.CancelFunc{},
		acme:  acme,
		store: store,
	}
	m.loadPersisted()
	return m
}

func (m *JobManager) push(j *Job, line string) {
	m.mu.Lock()
	j.logs = append(j.logs, line)
	if len(j.logs) > 2000 {
		j.logs = j.logs[len(j.logs)-2000:]
	}
	chans := make([]chan string, 0, len(m.subs[j.ID]))
	for ch := range m.subs[j.ID] {
		chans = append(chans, ch)
	}
	m.mu.Unlock()
	for _, ch := range chans {
		select {
		case ch <- line:
		default: // 慢消费者直接丢帧，避免阻塞任务
		}
	}
}

func (m *JobManager) Subscribe(jobID string) ([]string, chan string, func()) {
	ch := make(chan string, 256)
	m.mu.Lock()
	j, ok := m.jobs[jobID]
	var hist []string
	if ok {
		hist = append(hist, j.logs...)
	}
	if m.subs[jobID] == nil {
		m.subs[jobID] = map[chan string]struct{}{}
	}
	m.subs[jobID][ch] = struct{}{}
	m.mu.Unlock()
	cancel := func() {
		m.mu.Lock()
		delete(m.subs[jobID], ch)
		m.mu.Unlock()
	}
	return hist, ch, cancel
}

func (m *JobManager) Get(id string) *Job {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[id]
	if !ok {
		return nil
	}
	cp := *j
	cp.logs = append([]string(nil), j.logs...)
	return &cp
}

func (m *JobManager) List() []*Job {
	m.mu.Lock()
	out := make([]*Job, 0, len(m.order))
	for i := len(m.order) - 1; i >= 0; i-- {
		if j, ok := m.jobs[m.order[i]]; ok {
			cp := *j
			cp.logs = nil
			out = append(out, &cp)
		}
	}
	m.mu.Unlock()
	return out
}

func (m *JobManager) Cancel(id string) bool {
	m.mu.Lock()
	c := m.canc[id]
	j, ok := m.jobs[id]
	m.mu.Unlock()
	if !ok || c == nil {
		return false
	}
	c()
	m.push(j, "⚠ 已请求取消任务")
	return true
}

func (m *JobManager) Start(kind, title, domain, preview string, env map[string]string, args []string) *Job {
	return m.start(kind, title, domain, preview, env, args, true)
}

// StartAuto 用于内置调度触发的任务：不展示"未到续签时间"提示。
func (m *JobManager) StartAuto(kind, title, domain, preview string, env map[string]string, args []string) *Job {
	return m.start(kind, title, domain, preview, env, args, false)
}

func (m *JobManager) start(kind, title, domain, preview string, env map[string]string, args []string, manual bool) *Job {
	j := &Job{
		ID:      randToken(9),
		Kind:    kind,
		Title:   title,
		Domain:  domain,
		Status:  "queued",
		Preview: preview,
		Created: time.Now(),
		Manual:  manual,
	}
	m.mu.Lock()
	m.jobs[j.ID] = j
	m.order = append(m.order, j.ID)
	if len(m.order) > 200 {
		old := m.order[0]
		m.order = m.order[1:]
		delete(m.jobs, old)
		delete(m.subs, old)
	}
	m.mu.Unlock()

	go m.run(j, env, args)
	m.savePersisted()
	return j
}

func (m *JobManager) run(j *Job, env map[string]string, args []string) {
	m.sem <- struct{}{}
	defer func() { <-m.sem }()

	if _, err := os.Stat(m.acme.Bin); err != nil {
		m.mu.Lock()
		j.Status = "failed"
		j.Error = errAcmeMissing.Error()
		j.Started, j.Ended = time.Now(), time.Now()
		m.mu.Unlock()
		m.push(j, "✗ "+errAcmeMissing.Error())
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	m.mu.Lock()
	j.Status = "running"
	j.Started = time.Now()
	m.canc[j.ID] = cancel
	m.mu.Unlock()

	m.push(j, "$ acme.sh "+redactArgs(args))
	cmd := m.acme.cmd(ctx, env, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		m.finish(j, "failed", err.Error())
		return
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		m.finish(j, "failed", err.Error())
		return
	}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	rawLines := make([]string, 0, 32)
	var skipAt time.Time
	for sc.Scan() {
		line := sc.Text()
		if len(rawLines) < 256 {
			rawLines = append(rawLines, line)
		}
		if t, ok := parseSkipping(line); ok {
			skipAt = t
		}
		m.push(j, redactLine(line, env))
	}
	err = cmd.Wait()
	m.mu.Lock()
	delete(m.canc, j.ID)
	m.mu.Unlock()
	if err == nil {
		m.push(j, "✓ 完成")
		m.finish(j, "success", "")
	} else if !skipAt.IsZero() {
		// acme.sh 返回非零但明确说明"未到续期时间"：这不是失败。
		m.handleNotDue(j, skipAt, rawLines)
	} else if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		m.push(j, "✗ 超时（15 分钟）")
		m.finish(j, "failed", "执行超时")
	} else if ctx.Err() == context.Canceled {
		m.push(j, "✗ 已取消")
		m.finish(j, "canceled", "已取消")
	} else {
		m.push(j, "✗ "+err.Error())
		m.finish(j, "failed", err.Error())
	}
}

// parseSkipping 识别 acme.sh "未到续期时间" 输出，提取下次可续签时间。
func parseSkipping(line string) (time.Time, bool) {
	m := skipRe.FindStringSubmatch(line)
	if len(m) < 2 {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, m[1])
	return t, err == nil
}

// handleNotDue 处理"证书未到续期时间"：任务标记为 skipped 而非 failed，不发失败通知。
// 手动触发时在日志里追加距过期、距可续签的友好提示；自动调度则完全静默。
func (m *JobManager) handleNotDue(j *Job, nextRenew time.Time, rawLines []string) {
	if j.Manual {
		m.push(j, "ℹ 证书尚未到续期时间，已跳过（非失败）")
		expiry := m.expiryFor(j, rawLines)
		if !expiry.IsZero() {
			m.push(j, fmt.Sprintf("  证书到期：%s（还有 %s）",
				expiry.Format("2006-01-02"), humanDuration(time.Until(expiry))))
		}
		m.push(j, fmt.Sprintf("  下次可续签：%s（还有 %s）",
			nextRenew.Format("2006-01-02"), humanDuration(time.Until(nextRenew))))
		m.push(j, "  如需强制续签，请在续期时勾选「强制续签」")
	}
	m.finish(j, "skipped", "")
}

// expiryFor 从证书目录解析到期时间（优先按任务域名，再从输出路径兜底）。
func (m *JobManager) expiryFor(j *Job, rawLines []string) time.Time {
	if m.certs == nil || j.Domain == "" {
		return time.Time{}
	}
	all, err := m.certs.Scan()
	if err == nil {
		for _, ci := range all {
			if ci.Domain == j.Domain {
				return ci.NotAfter
			}
		}
	}
	return time.Time{}
}

// humanDuration 把时长转成"X 天 Y 小时"的中文表述。
func humanDuration(d time.Duration) string {
	if d < 0 {
		return "0 天"
	}
	days := int(d.Hours() / 24)
	hours := int(d.Hours()) % 24
	if days > 0 {
		return fmt.Sprintf("%d 天 %d 小时", days, hours)
	}
	if hours > 0 {
		return fmt.Sprintf("%d 小时", hours)
	}
	return fmt.Sprintf("%d 分钟", int(d.Minutes()))
}

func (m *JobManager) finish(j *Job, status, errMsg string) {
	m.mu.Lock()
	j.Status = status
	j.Error = errMsg
	j.Ended = time.Now()
	chans := make([]chan string, 0, len(m.subs[j.ID]))
	for ch := range m.subs[j.ID] {
		chans = append(chans, ch)
	}
	m.mu.Unlock()
	msg := "__done__:" + status
	for _, ch := range chans {
		select {
		case ch <- msg:
		default:
		}
	}
	if m.onDone != nil {
		// 传副本，避免通知 goroutine 与后续日志写入竞争。
		cp := *j
		m.mu.Lock()
		cp.logs = append([]string(nil), j.logs...)
		m.mu.Unlock()
		go m.onDone(&cp)
	}
	m.savePersisted()
}

// redactArgs / redactLine 保证凭证不会出现在任务预览和实时日志里。
func redactArgs(args []string) string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if strings.HasPrefix(a, "-") || !strings.Contains(a, "=") {
			out = append(out, shellQuote(a))
			continue
		}
		out = append(out, shellQuote(a))
	}
	return strings.Join(out, " ")
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("@%_+=:,./-", r))
	}) >= 0 {
		return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
	}
	return s
}

func redactLine(line string, env map[string]string) string {
	for _, v := range env {
		if v != "" {
			line = strings.ReplaceAll(line, v, "••••")
		}
	}
	return line
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

var _ = fmt.Sprintf
