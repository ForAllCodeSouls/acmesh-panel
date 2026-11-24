package main

import (
	"bufio"
	"context"
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

	logs []string
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
	onDone func(*Job) // 任务结束后异步触发通知（由 Server 注入）
}

func NewJobManager(acme *ACME, store *Store, parallel int) *JobManager {
	if parallel < 1 {
		parallel = 1
	}
	return &JobManager{
		jobs:  map[string]*Job{},
		subs:  map[string]map[chan string]struct{}{},
		sem:   make(chan struct{}, parallel),
		canc:  map[string]context.CancelFunc{},
		acme:  acme,
		store: store,
	}
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
	j := &Job{
		ID:      randToken(9),
		Kind:    kind,
		Title:   title,
		Domain:  domain,
		Status:  "queued",
		Preview: preview,
		Created: time.Now(),
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
	for sc.Scan() {
		m.push(j, redactLine(sc.Text(), env))
	}
	err = cmd.Wait()
	m.mu.Lock()
	delete(m.canc, j.ID)
	m.mu.Unlock()
	if err == nil {
		m.push(j, "✓ 完成")
		m.finish(j, "success", "")
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
		if len(v) >= 4 {
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
