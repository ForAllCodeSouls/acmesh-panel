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
	"strconv"
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
	Code    string     `json:"code"`
	Name    string     `json:"name"`
	Website string     `json:"website"` // 服务商官网，面板里给出直达链接方便取凭证
	Fields  []EnvField `json:"fields"`
}

var providerCatalog = []ProviderDef{
	{"dns_acmedns", "ACME-DNS", "https://acme-dns.io/", []EnvField{
		{Name: "ACMEDNS_SUBDOMAIN", Label: "Subdomain"},
		{Name: "ACMEDNS_USERNAME", Label: "Username", Secret: true},
		{Name: "ACMEDNS_PASSWORD", Label: "Password", Secret: true},
		{Name: "ACMEDNS_UPDATE_URL", Label: "Update URL", Optional: true, Hint: "自建服务时填写"},
	}},
	{"dns_ali", "阿里云 DNS", "https://www.aliyun.com/product/dns", []EnvField{
		{Name: "Ali_Key", Label: "AccessKey ID", Secret: true},
		{Name: "Ali_Secret", Label: "AccessKey Secret", Secret: true},
	}},
	{"dns_arvan", "ArvanCloud", "https://panel.arvancloud.ir/", []EnvField{
		{Name: "Arvan_Token", Label: "API Token", Secret: true},
	}},
	{"dns_aws", "AWS Route 53", "https://console.aws.amazon.com/iamv2/home#/users", []EnvField{
		{Name: "AWS_ACCESS_KEY_ID", Label: "Access Key ID", Secret: true},
		{Name: "AWS_SECRET_ACCESS_KEY", Label: "Secret Access Key", Secret: true},
		{Name: "AWS_REGION", Label: "Region", Optional: true, Hint: "默认 us-east-1"},
	}},
	{"dns_azure", "Azure DNS", "https://portal.azure.com/", []EnvField{
		{Name: "AZUREDNS_SUBSCRIPTIONID", Label: "Subscription ID", Secret: true},
		{Name: "AZUREDNS_TENANTID", Label: "Tenant ID", Secret: true},
		{Name: "AZUREDNS_APPID", Label: "Application (client) ID", Secret: true},
		{Name: "AZUREDNS_CLIENTSECRET", Label: "Client Secret", Secret: true},
	}},
	{"dns_baidu", "百度云 DNS", "https://console.bce.baidu.com/iam/", []EnvField{
		{Name: "Baidu_AK", Label: "Access Key ID", Secret: true},
		{Name: "Baidu_SK", Label: "Secret Access Key", Secret: true},
	}},
	{"dns_bunny", "Bunny.net", "https://bunny.net/account/settings/api", []EnvField{
		{Name: "BUNNY_API_KEY", Label: "API Key", Secret: true},
	}},
	{"dns_cf", "Cloudflare", "https://dash.cloudflare.com/profile/api-tokens", []EnvField{
		{Name: "CF_Token", Label: "API Token", Hint: "Zone.DNS 编辑权限", Secret: true},
		{Name: "CF_Account_ID", Label: "Account ID", Optional: true},
		{Name: "CF_Zone_ID", Label: "Zone ID", Optional: true},
	}},
	{"dns_conoha", "ConoHa", "https://www.conoha.jp/", []EnvField{
		{Name: "CONOHA_Username", Label: "用户名"},
		{Name: "CONOHA_Password", Label: "密码", Secret: true},
		{Name: "CONOHA_TenantId", Label: "Tenant ID"},
		{Name: "CONOHA_IdentityServiceApi", Label: "Identity Service API", Hint: "例如 https://identity.tyo1.conoha.io/v2.0"},
	}},
	{"dns_constellix", "Constellix", "https://constellix.com/", []EnvField{
		{Name: "CONSTELLIX_Key", Label: "API Key", Secret: true},
		{Name: "CONSTELLIX_Secret", Label: "API Secret", Secret: true},
	}},
	{"dns_desec", "deSEC", "https://desec.io/login", []EnvField{
		{Name: "DEDYN_TOKEN", Label: "API Token", Secret: true},
	}},
	{"dns_df", "dyndnsfree.de", "https://www.dyndnsfree.de/", []EnvField{
		{Name: "DF_user", Label: "用户名"},
		{Name: "DF_password", Label: "密码", Secret: true},
	}},
	{"dns_dgon", "DigitalOcean", "https://cloud.digitalocean.com/account/api/tokens", []EnvField{
		{Name: "DO_API_KEY", Label: "API Token", Secret: true},
	}},
	{"dns_dnsimple", "DNSimple", "https://dnsimple.com/user/authorizations", []EnvField{
		{Name: "DNSimple_OAUTH_TOKEN", Label: "OAuth Token", Secret: true},
	}},
	{"dns_dp", "DNSPod (dnspod.cn)", "https://www.dnspod.cn/", []EnvField{
		{Name: "DP_Id", Label: "API ID"},
		{Name: "DP_Key", Label: "API Token", Secret: true},
	}},
	{"dns_dpi", "DNSPod 国际站", "https://www.dnspod.com/", []EnvField{
		{Name: "DPI_Id", Label: "API ID"},
		{Name: "DPI_Key", Label: "API Token", Secret: true},
	}},
	{"dns_duckdns", "DuckDNS", "https://www.duckdns.org/", []EnvField{
		{Name: "DuckDNS_Token", Label: "API Token", Hint: "打开官网登录后，首页显示的 Token（不是域名）", Secret: true},
	}},
	{"dns_dynu", "Dynu DNS", "https://www.dynu.com/en-US/ControlPanel/APICredentials", []EnvField{
		{Name: "Dynu_ClientId", Label: "Client ID", Hint: "Dynu 控制面板 → API Credentials 里的 OAuth2 Client ID，不是 API Key", Secret: true},
		{Name: "Dynu_Secret", Label: "Secret", Hint: "同一页面显示的 Secret", Secret: true},
	}},
	{"dns_dynv6", "dynv6", "https://dynv6.com/keys", []EnvField{
		{Name: "DYNV6_TOKEN", Label: "HTTP API Token", Hint: "dynv6 → Keys 页面获取", Secret: true},
	}},
	{"dns_easydns", "easyDNS", "https://my.easydns.com/", []EnvField{
		{Name: "EASYDNS_Key", Label: "API Key", Secret: true},
		{Name: "EASYDNS_Token", Label: "API Token", Secret: true},
	}},
	{"dns_freedns", "FreeDNS", "https://freedns.afraid.org/", []EnvField{
		{Name: "FREEDNS_User", Label: "用户名"},
		{Name: "FREEDNS_Password", Label: "密码", Secret: true},
	}},
	{"dns_gandi_livedns", "Gandi LiveDNS", "https://www.gandi.net/en/my-account/credentials", []EnvField{
		{Name: "GANDI_LIVEDNS_TOKEN", Label: "API Token", Hint: "新版 Token；旧版 API Key 已弃用", Secret: true},
	}},
	{"dns_gd", "GoDaddy", "https://developer.godaddy.com/keys", []EnvField{
		{Name: "GD_Key", Label: "API Key", Secret: true},
		{Name: "GD_Secret", Label: "API Secret", Secret: true},
	}},
	{"dns_he", "Hurricane Electric", "https://dns.he.net/", []EnvField{
		{Name: "HE_Username", Label: "用户名"},
		{Name: "HE_Password", Label: "密码", Secret: true},
	}},
	{"dns_huaweicloud", "华为云 DNS", "https://console.huaweicloud.com/dns/", []EnvField{
		{Name: "HUAWEICLOUD_Username", Label: "用户名"},
		{Name: "HUAWEICLOUD_Password", Label: "密码", Secret: true},
		{Name: "HUAWEICLOUD_ProjectID", Label: "Project ID", Optional: true},
	}},
	{"dns_inwx", "INWX", "https://www.inwx.de/", []EnvField{
		{Name: "INWX_User", Label: "用户名"},
		{Name: "INWX_Password", Label: "密码", Secret: true},
		{Name: "INWX_Shared_Secret", Label: "Shared Secret", Optional: true, Hint: "开启 2FA 时必填", Secret: true},
	}},
	{"dns_jd", "京东云 DNS", "https://docs.jdcloud.com/cn/jd-cloud-dns/api", []EnvField{
		{Name: "JD_ACCESS_KEY_ID", Label: "Access Key ID", Secret: true},
		{Name: "JD_ACCESS_KEY_SECRET", Label: "Access Key Secret", Secret: true},
		{Name: "JD_REGION", Label: "Region", Optional: true, Hint: "默认 cn-north-1"},
	}},
	{"dns_linode_v4", "Linode", "https://cloud.linode.com/profile/tokens", []EnvField{
		{Name: "LINODE_V4_API_KEY", Label: "API Token", Secret: true},
	}},
	{"dns_mydnsjp", "MyDNS.JP", "https://www.mydns.jp/", []EnvField{
		{Name: "MYDNSJP_MasterID", Label: "Master ID"},
		{Name: "MYDNSJP_Password", Label: "密码", Secret: true},
	}},
	{"dns_namecheap", "Namecheap", "https://www.namecheap.com/security/api-manager/", []EnvField{
		{Name: "NAMECHEAP_USERNAME", Label: "用户名"},
		{Name: "NAMECHEAP_API_KEY", Label: "API Key", Secret: true},
		{Name: "NAMECHEAP_SOURCEIP", Label: "白名单 IP", Optional: true},
	}},
	{"dns_namesilo", "NameSilo", "https://www.namesilo.com/account/api-manager", []EnvField{
		{Name: "Namesilo_Key", Label: "API Key", Secret: true},
	}},
	{"dns_netcup", "netcup", "https://www.netcup.de/", []EnvField{
		{Name: "NC_CID", Label: "客户编号 (CID)"},
		{Name: "NC_Apikey", Label: "API Key", Secret: true},
		{Name: "NC_Apipw", Label: "API Password", Secret: true},
	}},
	{"dns_netlify", "Netlify", "https://app.netlify.com/user/applications", []EnvField{
		{Name: "NETLIFY_ACCESS_TOKEN", Label: "Personal Access Token", Secret: true},
	}},
	{"dns_njalla", "Njalla", "https://njal.la/", []EnvField{
		{Name: "NJALLA_Token", Label: "API Token", Secret: true},
	}},
	{"dns_nsupdate", "RFC2136 / nsupdate", "https://www.isc.org/bind/", []EnvField{
		{Name: "NSUPDATE_SERVER", Label: "DNS 服务器地址"},
		{Name: "NSUPDATE_SERVER_PORT", Label: "端口", Optional: true, Hint: "默认 53"},
		{Name: "NSUPDATE_KEY", Label: "TSIG Key", Optional: true, Hint: "格式 keyname:base64；动态更新已开放时可留空", Secret: true},
		{Name: "NSUPDATE_ZONE", Label: "Zone", Optional: true, Hint: "留空则自动推断"},
		{Name: "NSUPDATE_OPT", Label: "额外参数", Optional: true},
	}},
	{"dns_openprovider", "OpenProvider", "https://cp.openprovider.eu/", []EnvField{
		{Name: "OPENPROVIDER_USER", Label: "用户名"},
		{Name: "OPENPROVIDER_PASSWORDHASH", Label: "Password Hash", Secret: true},
	}},
	{"dns_ovh", "OVHcloud", "https://api.ovh.com/createToken/", []EnvField{
		{Name: "OVH_AK", Label: "Application Key", Secret: true},
		{Name: "OVH_AS", Label: "Application Secret", Secret: true},
		{Name: "OVH_CK", Label: "Consumer Key", Secret: true},
		{Name: "OVH_END_POINT", Label: "API 端点", Hint: "ovh-eu / ovh-us / ovh-ca / soyoustart-eu 等"},
	}},
	{"dns_pdns", "PowerDNS", "https://doc.powerdns.com/", []EnvField{
		{Name: "PDNS_Url", Label: "API 地址", Hint: "例如 http://127.0.0.1:8081"},
		{Name: "PDNS_ServerId", Label: "Server ID", Hint: "通常是 localhost"},
		{Name: "PDNS_Token", Label: "API Key", Secret: true},
		{Name: "PDNS_Ttl", Label: "TTL", Optional: true, Hint: "默认 60"},
	}},
	{"dns_porkbun", "Porkbun", "https://porkbun.com/account/api", []EnvField{
		{Name: "PORKBUN_API_KEY", Label: "API Key", Secret: true},
		{Name: "PORKBUN_SECRET_API_KEY", Label: "Secret API Key", Secret: true},
	}},
	{"dns_tencent", "腾讯云 DNSPod", "https://console.cloud.tencent.com/cam/capi", []EnvField{
		{Name: "Tencent_SecretId", Label: "SecretId", Secret: true},
		{Name: "Tencent_SecretKey", Label: "SecretKey", Secret: true},
	}},
	{"dns_ultra", "UltraDNS", "https://www.ultradns.com/", []EnvField{
		{Name: "ULTRA_USR", Label: "用户名"},
		{Name: "ULTRA_PWD", Label: "密码", Secret: true},
	}},
	{"dns_vercel", "Vercel", "https://vercel.com/account/tokens", []EnvField{
		{Name: "VERCEL_TOKEN", Label: "Access Token", Secret: true},
	}},
	{"dns_vultr", "Vultr", "https://my.vultr.com/settings/#settingsapi", []EnvField{
		{Name: "VULTR_API_KEY", Label: "API Key", Secret: true},
	}},
}

// 旧版本面板用过的 code 与实际 acme.sh 脚本名不一致；保存过的凭证继续可用。
var legacyProviderCodes = map[string]string{
	"dns_do":     "dns_dgon",
	"dns_gandi":  "dns_gandi_livedns",
	"dns_linode": "dns_linode_v4",
}

// normalizeProviderCode 把历史 code 归一到 acme.sh 实际支持的脚本名。
func normalizeProviderCode(code string) string {
	if real, ok := legacyProviderCodes[code]; ok {
		return real
	}
	return code
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

	// 重试所需的原始执行参数。env 含凭证，绝不序列化给前端；args 也不直接暴露。
	retryArgs []string
	retryEnv  map[string]string
	attempt   int  // 自动重试累计次数（不含首次执行），仅用于退避策略
	retried   bool // 该任务是否已被认领重试（手动或自动），防止同一任务重复执行
}

type JobManager struct {
	mu             sync.Mutex
	jobs           map[string]*Job
	order          []string
	subs           map[string]map[chan string]struct{}
	sem            chan struct{}
	canc           map[string]context.CancelFunc
	acme           *ACME
	store          *Store
	certs          *CertScanner
	onDone         func(*Job)      // 任务结束后异步触发通知（由 Server 注入）
	retryScheduler *RetryScheduler // 失败任务指数退避自动重试（由 Server 注入）

	// purgeHooks 按任务 ID 注册的一次性"完成后清理"钩子（如删除证书目录）。
	// 任务结束时在 finish 内直接触发，不再用固定 60s 轮询等待，避免任务超时 15min 时漏清理。
	purgeHooks map[string]func()
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
	Attempt int       `json:"attempt,omitempty"`
	Logs    []string  `json:"logs"`

	// 重试参数：args 不含凭证可明文；env 含凭证，经 store 的 AEAD 加密后存 EnvBlob。
	Args    []string `json:"args,omitempty"`
	EnvBlob string   `json:"env_blob,omitempty"` // base64(nonce||ciphertext)
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
			Manual: p.Manual, logs: p.Logs, attempt: p.Attempt,
			retryArgs: p.Args,
		}
		// 重试凭证以密文落盘，恢复时用同一把密钥与任务 ID 作为 AAD 解封；
		// 解不开（换过 secret.key）就当作不可重试，不让它阻断历史任务展示。
		if p.EnvBlob != "" && m.store != nil {
			if plain, e := m.store.OpenForRetry(p.EnvBlob, p.ID); e == nil {
				var env map[string]string
				if json.Unmarshal(plain, &env) == nil {
					j.retryEnv = env
				}
			}
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
		p := persistedJob{
			ID: j.ID, Kind: j.Kind, Title: j.Title, Domain: j.Domain,
			Status: j.Status, Preview: j.Preview, Error: j.Error,
			Created: j.Created, Started: j.Started, Ended: j.Ended,
			Manual: j.Manual, Logs: append([]string(nil), j.logs...), Attempt: j.attempt,
			Args: append([]string(nil), j.retryArgs...),
		}
		// env 含 DNS API 凭证：加密后才落盘，AAD 绑定任务 ID。
		if len(j.retryEnv) > 0 && m.store != nil {
			if plain, e := json.Marshal(j.retryEnv); e == nil {
				if blob, e := m.store.SealForRetry(plain, j.ID); e == nil {
					p.EnvBlob = blob
				}
			}
		}
		list = append(list, p)
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
		jobs:       map[string]*Job{},
		subs:       map[string]map[chan string]struct{}{},
		sem:        make(chan struct{}, parallel),
		canc:       map[string]context.CancelFunc{},
		purgeHooks: map[string]func(){},
		acme:       acme,
		store:      store,
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

// Retry 以原任务的凭证与命令参数重新提交一个新任务。
// 仅允许终态任务重试；运行中的任务重试无意义且可能造成并发冲突。
func (m *JobManager) Retry(id string) (*Job, error) {
	m.mu.Lock()
	old, ok := m.jobs[id]
	if !ok {
		m.mu.Unlock()
		return nil, errors.New("任务不存在")
	}
	if old.Status != "failed" && old.Status != "canceled" && old.Status != "skipped" {
		m.mu.Unlock()
		return nil, errors.New("只有失败、已取消或未到期的任务可以重试")
	}
	// 同一失败任务只允许被认领一次：手动重试与自动退避共用此原子检查，
	// 避免用户在等待退避期间手动重试后，调度器到期又执行一次。
	if old.retried {
		m.mu.Unlock()
		return nil, errors.New("该任务已重试过，请在任务页查看重试生成的任务")
	}
	if len(old.retryArgs) == 0 {
		m.mu.Unlock()
		return nil, errors.New("该任务缺少原始执行参数，无法重试，请在业务页面重新操作")
	}
	old.retried = true
	kind, title, domain, preview := old.Kind, old.Title, old.Domain, old.Preview
	args := append([]string(nil), old.retryArgs...)
	env := make(map[string]string, len(old.retryEnv))
	for k, v := range old.retryEnv {
		env[k] = v
	}
	m.mu.Unlock()

	j := m.start(kind, title, domain, preview, env, args, true)
	m.mu.Lock()
	j.attempt = old.attempt + 1
	m.mu.Unlock()
	m.savePersisted()
	m.push(j, "↻ 重试任务（原任务 "+id+"，第 "+strconv.Itoa(j.attempt+1)+" 次执行）")
	m.push(j, "  提示：若上次失败是证书尚未到续期时间，重试仍会跳过；如需强制续签请到证书页勾选强制续签")
	return j, nil
}

func (m *JobManager) Start(kind, title, domain, preview string, env map[string]string, args []string) *Job {
	return m.start(kind, title, domain, preview, env, args, true)
}

// StartAuto 用于内置调度触发的任务：不展示"未到续签时间"提示。
func (m *JobManager) StartAuto(kind, title, domain, preview string, env map[string]string, args []string) *Job {
	return m.start(kind, title, domain, preview, env, args, false)
}

func (m *JobManager) start(kind, title, domain, preview string, env map[string]string, args []string, manual bool) *Job {
	envCopy := make(map[string]string, len(env))
	for k, v := range env {
		envCopy[k] = v
	}
	j := &Job{
		ID:        randToken(9),
		Kind:      kind,
		Title:     title,
		Domain:    domain,
		Status:    "queued",
		Preview:   preview,
		Created:   time.Now(),
		Manual:    manual,
		retryArgs: append([]string(nil), args...),
		retryEnv:  envCopy,
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
	// Start 失败时 cmd.Wait 不会被调用，pipe 读端不会自动关闭；持续故障下会耗尽 fd。
	// Wait 内部也会关闭它，重复 Close 是安全的。
	defer stdout.Close()
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		m.finish(j, "failed", err.Error())
		return
	}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
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
	// Scanner 触及上限会静默停止读取；此时子进程仍在写管道，cmd.Wait 会一直
	// 等到 15 分钟超时。必须显式检查 Err 并取消进程，让任务立即失败。
	scanErr := sc.Err()
	logTooLong := errors.Is(scanErr, bufio.ErrTooLong)
	if scanErr != nil {
		if logTooLong {
			m.push(j, "✗ 单行日志超过 8MB，已中止任务")
		} else {
			m.push(j, "✗ 读取任务日志失败: "+scanErr.Error())
		}
		cancel()
	}
	err = cmd.Wait()
	m.mu.Lock()
	delete(m.canc, j.ID)
	m.mu.Unlock()
	if logTooLong {
		m.finish(j, "failed", "日志行过长（超过 8MB），已中止")
	} else if err == nil {
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
	// 失败任务按指数退避自动重试。排期日志必须写在 __done__ 之前，
	// 否则前端收到结束事件后会忽略后续 SSE 消息。
	if status == "failed" && m.retryScheduler != nil {
		m.mu.Lock()
		attempt := j.attempt
		m.mu.Unlock()
		if m.retryScheduler.Schedule(j.ID, attempt, errMsg) {
			p := m.retryScheduler.policy()
			delay := p.BaseDelay << uint(attempt)
			if delay > p.MaxDelay {
				delay = p.MaxDelay
			}
			m.push(j, fmt.Sprintf("↻ 已排入自动重试队列，%d 秒后重试（第 %d 次重试）", delay, attempt+1))
		}
	}
	msg := "__done__:" + status
	m.mu.Lock()
	j.Status = status
	j.Error = errMsg
	j.Ended = time.Now()
	// 把结束标记也写入日志历史：历史任务回放时能显示终态，前端也不必挂起 SSE 等 done。
	j.logs = append(j.logs, msg)
	if len(j.logs) > 2000 {
		j.logs = append([]string(nil), j.logs[len(j.logs)-2000:]...)
	}
	chans := make([]chan string, 0, len(m.subs[j.ID]))
	for ch := range m.subs[j.ID] {
		chans = append(chans, ch)
	}
	m.mu.Unlock()
	for _, ch := range chans {
		select {
		case ch <- msg:
		default:
		}
	}
	// 一次性清理钩子：任务真正结束后才执行，不受轮询窗口限制。
	// 在锁内取出并删除，保证只触发一次。
	m.mu.Lock()
	hook := m.purgeHooks[j.ID]
	delete(m.purgeHooks, j.ID)
	// 整个副本必须在同一把锁内构造：push() 会在其它 goroutine 并发改 j.logs，
	// 锁外的 `cp := *j` 会读到一个撕裂的 slice header（race detector 会报）。
	var cp *Job
	if m.onDone != nil {
		tmp := *j
		tmp.logs = append([]string(nil), j.logs...)
		cp = &tmp
	}
	m.mu.Unlock()
	if hook != nil {
		hook()
	}
	if cp != nil {
		go m.onDone(cp)
	}
	m.savePersisted()
}

// redactArgs / redactLine 保证凭证不会出现在任务预览和实时日志里。
// KEY=value 形式的参数只保留键名，值一律打码（当前凭证走 env，这是防御未来改动的安全网）。
func redactArgs(args []string) string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if k, _, ok := strings.Cut(a, "="); ok && !strings.HasPrefix(k, "-") {
			out = append(out, shellQuote(k+"=••••"))
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
