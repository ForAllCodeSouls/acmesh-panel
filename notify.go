package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// ---------------- 事件与渠道目录 ----------------

type NotifyEvent struct {
	Code string `json:"code"`
	Name string `json:"name"`
}

var notifyEvents = []NotifyEvent{
	{"cert_issued", "签发成功"},
	{"issue_failed", "签发失败"},
	{"cert_renewed", "续期成功"},
	{"renew_failed", "续期失败"},
	{"cert_expiring", "证书临期（≤30 天，每天一次）"},
	{"cert_revoked", "证书吊销"},
	{"cert_removed", "证书移除"},
	{"cert_deployed", "证书部署"},
	{"action_failed", "吊销 / 移除 / 部署失败"},
	{"cert_synced", "证书同步成功"},
	{"sync_failed", "证书同步失败"},
	{"security_alert", "安全告警（私钥查看 / 改密 / 登录锁定）"},
	{"update_available", "面板新版本（自动检测发现）"},
}

var notifyEventCodes = func() map[string]bool {
	m := map[string]bool{}
	for _, e := range notifyEvents {
		m[e.Code] = true
	}
	return m
}()

type NotifierKind struct {
	Code        string `json:"code"`
	Name        string `json:"name"`
	NeedTarget  bool   `json:"need_target"`
	NeedSecret  bool   `json:"need_secret"`
	TargetLabel string `json:"target_label"`
	SecretLabel string `json:"secret_label"`
	Hint        string `json:"hint"`
}

var notifierKinds = []NotifierKind{
	{"gotify", "Gotify", true, true, "服务地址", "应用 Token", "例如 https://push.example.com，面板会 POST /message?token=..."},
	{"generic", "通用 Webhook", true, false, "完整 URL", "Bearer Token（可选）", "POST JSON：{title, message, event, time, level}"},
	{"serverchan", "Server 酱³", false, true, "无需填写", "SendKey", "通过 sctapi.ftqq.com 发送微信通知"},
	{"dingtalk", "钉钉群机器人", true, true, "Webhook 完整 URL", "加签 Secret（可选）", "支持加签与不加签两种模式"},
	{"feishu", "飞书群机器人", true, true, "Webhook 完整 URL", "签名密钥（可选）", "支持签名校验"},
	{"bark", "Bark (iOS)", false, true, "无需填写", "Bark Key", "通过 api.day.app 推送到 iPhone"},
}

var notifierKindByCode = func() map[string]NotifierKind {
	m := map[string]NotifierKind{}
	for _, k := range notifierKinds {
		m[k.Code] = k
	}
	return m
}()

// ---------------- 发送引擎 ----------------

type NotifyMessage struct {
	Title   string `json:"title"`
	Message string `json:"message"`
	Event   string `json:"event"`
	Time    string `json:"time"`
	Level   string `json:"level"` // info | warn | error
}

type NotifyEngine struct {
	store  *Store
	client *http.Client
}

// dialIPKey 让 post 把「已校验过的 IP」传给 DialContext，避免校验与连接各解析一次 DNS
// 造成 DNS rebinding（校验时公网、连接时内网）。
type dialIPKey struct{}

func NewNotifyEngine(store *Store) *NotifyEngine {
	return &NotifyEngine{
		store: store,
		client: &http.Client{
			Timeout: 10 * time.Second,
			// Webhook 不做重定向：safeURL 只校验了初始 URL，跟随 307/308 会把
			// 请求（含 body）带到未校验的地址，形成 SSRF。通知场景不需要跳转。
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					if ip, ok := ctx.Value(dialIPKey{}).(net.IP); ok {
						_, port, err := net.SplitHostPort(addr)
						if err != nil {
							return nil, err
						}
						return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(
							ctx, network, net.JoinHostPort(ip.String(), port))
					}
					return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, addr)
				},
			},
		},
	}
}

// Send 向所有订阅了 event 的已启用渠道推送。返回成功发送数。
func (e *NotifyEngine) Send(event, title, message string) int {
	if !notifyEventCodes[event] {
		return 0
	}
	msg := NotifyMessage{
		Title:   title,
		Message: message,
		Event:   event,
		Time:    time.Now().Format(time.RFC3339),
		Level:   levelForEvent(event),
	}
	sent := 0
	for _, view := range e.store.ListNotifiers() {
		if !view.Enabled {
			continue
		}
		has := false
		for _, ev := range view.Events {
			if ev == event {
				has = true
				break
			}
		}
		if !has {
			continue
		}
		n, err := e.store.GetNotifier(view.ID)
		if err != nil {
			log.Printf("通知渠道 %s 读取失败: %v", view.Name, err)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err = e.sendOne(ctx, n, msg)
		cancel()
		if err != nil {
			log.Printf("通知渠道 %s 推送失败: %v", n.Name, err)
		} else {
			sent++
		}
	}
	return sent
}

// SendTest 忽略事件订阅，直接测试某个渠道是否可用。
func (e *NotifyEngine) SendTest(n Notifier) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return e.sendOne(ctx, n, NotifyMessage{
		Title:   "✅ acmesh-panel 通知测试",
		Message: "如果你收到这条消息，说明通知渠道配置正确。\n时间：" + time.Now().Format(time.RFC3339),
		Event:   "test",
		Time:    time.Now().Format(time.RFC3339),
		Level:   "info",
	})
}

func levelForEvent(event string) string {
	switch event {
	case "issue_failed", "renew_failed", "action_failed", "security_alert":
		return "error"
	case "cert_expiring", "cert_revoked", "cert_removed", "update_available":
		return "warn"
	default:
		return "info"
	}
}

func (e *NotifyEngine) sendOne(ctx context.Context, n Notifier, msg NotifyMessage) error {
	def, ok := notifierKindByCode[n.Kind]
	if !ok {
		return fmt.Errorf("未知通知渠道类型: %s", n.Kind)
	}
	if def.NeedTarget && n.Target == "" {
		return fmt.Errorf("%s 缺少目标地址", def.Name)
	}
	if def.NeedSecret && n.Secret == "" {
		return fmt.Errorf("%s 缺少密钥", def.Name)
	}

	switch n.Kind {
	case "gotify":
		base, err := safeURL(n.Target)
		if err != nil {
			return err
		}
		u := *base
		u.Path = strings.TrimSuffix(u.Path, "/") + "/message"
		q := u.Query()
		q.Set("token", n.Secret)
		u.RawQuery = q.Encode()
		endpoint := u.String()
		payload := map[string]any{
			"title":    msg.Title,
			"message":  msg.Message,
			"priority": priorityFor(msg.Level),
			"extras": map[string]any{
				"client::display": map[string]string{"contentType": "text/markdown"},
			},
		}
		return e.postJSON(ctx, endpoint, payload, nil)

	case "generic":
		endpoint, err := safeURL(n.Target)
		if err != nil {
			return err
		}
		var headers map[string]string
		if n.Secret != "" {
			headers = map[string]string{"Authorization": "Bearer " + n.Secret}
		}
		return e.postJSON(ctx, endpoint.String(), msg, headers)

	case "serverchan":
		endpoint := "https://sctapi.ftqq.com/" + url.PathEscape(n.Secret) + ".send"
		form := url.Values{}
		form.Set("title", msg.Title)
		form.Set("desp", msg.Message)
		return e.postForm(ctx, endpoint, form)

	case "dingtalk":
		endpoint, err := signedWebhook(n.Target, n.Secret)
		if err != nil {
			return err
		}
		payload := map[string]any{
			"msgtype": "markdown",
			"markdown": map[string]string{
				"title": msg.Title,
				"text":  "### " + msg.Title + "\n\n" + strings.ReplaceAll(msg.Message, "\n", "\n\n"),
			},
		}
		return e.postJSON(ctx, endpoint, payload, nil)

	case "feishu":
		endpoint, err := signedWebhook(n.Target, n.Secret)
		if err != nil {
			return err
		}
		payload := map[string]any{
			"msg_type": "text",
			"content":  map[string]string{"text": msg.Title + "\n" + msg.Message},
		}
		return e.postJSON(ctx, endpoint, payload, nil)

	case "bark":
		endpoint := "https://api.day.app/" + url.PathEscape(n.Secret) + "/" +
			url.PathEscape(msg.Title) + "/" + url.PathEscape(msg.Message)
		return e.postJSON(ctx, endpoint, map[string]any{}, nil)
	}
	return fmt.Errorf("不支持的通知类型: %s", n.Kind)
}

func priorityFor(level string) int {
	switch level {
	case "error":
		return 8
	case "warn":
		return 5
	default:
		return 3
	}
}

// blockedTargetIP 拒绝私网/环回/链路本地/云元数据等地址，防止 Webhook 变成 SSRF 入口。
func blockedTargetIP(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
}

// allowLocalWebhook 仅供本地端到端测试显式开启，默认关闭。
func allowLocalWebhook() bool {
	v := os.Getenv("ACME_PANEL_ALLOW_LOCAL_WEBHOOK")
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
}

// safeURL 只允许 http(s)，并拒绝指向内网 / 元数据服务的地址（防 SSRF）。
func safeURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("URL 格式错误: %v", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("Webhook 地址必须是完整的 http(s) URL")
	}
	if allowLocalWebhook() {
		return u, nil
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		if blockedTargetIP(ip) {
			return nil, fmt.Errorf("Webhook 地址不能指向本机或内网 IP")
		}
		return u, nil
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("Webhook 域名无法解析: %s", host)
	}
	for _, ip := range ips {
		if blockedTargetIP(ip) {
			return nil, fmt.Errorf("Webhook 域名解析到内网地址，已拒绝")
		}
	}
	return u, nil
}

// safeResolvedIP 返回 safeURL 校验时实际使用的 IP，供 post 固定连接目标，
// 消除校验与连接两次 DNS 解析之间的 rebinding 窗口。
// 返回 nil 表示由 Transport 正常解析（仅本地测试开关开启时）。
func safeResolvedIP(u *url.URL) (net.IP, error) {
	if allowLocalWebhook() {
		return nil, nil
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		return ip, nil
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("Webhook 域名无法解析: %s", host)
	}
	for _, ip := range ips {
		if blockedTargetIP(ip) {
			return nil, fmt.Errorf("Webhook 域名解析到内网地址，已拒绝")
		}
	}
	return ips[0], nil
}

// signedWebhook 为钉钉/飞书追加 timestamp + sign（Secret 为空时原样返回）。
func signedWebhook(webhook, secret string) (string, error) {
	u, err := safeURL(webhook)
	if err != nil {
		return "", err
	}
	if secret == "" {
		return u.String(), nil
	}
	ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
	h := hmac.New(sha256.New, []byte(secret))
	_, _ = h.Write([]byte(ts + "\n" + secret))
	sig := base64.StdEncoding.EncodeToString(h.Sum(nil))
	q := u.Query()
	q.Set("timestamp", ts)
	q.Set("sign", sig)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (e *NotifyEngine) postJSON(ctx context.Context, endpoint string, payload any, headers map[string]string) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	h := map[string]string{"Content-Type": "application/json"}
	for k, v := range headers {
		h[k] = v
	}
	return e.post(ctx, endpoint, b, h)
}

func (e *NotifyEngine) postForm(ctx context.Context, endpoint string, form url.Values) error {
	return e.post(ctx, endpoint, []byte(form.Encode()), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})
}

func (e *NotifyEngine) post(ctx context.Context, endpoint string, body []byte, headers map[string]string) error {
	u, err := safeURL(endpoint)
	if err != nil {
		return err
	}
	fixedIP, err := safeResolvedIP(u)
	if err != nil {
		return err
	}
	if fixedIP != nil {
		// 保留 URL 里的 Host 头（证书/虚拟主机的 SNI 依赖它），只把连接目标钉在已校验的 IP。
		ctx = context.WithValue(ctx, dialIPKey{}, fixedIP)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return nil
}

// ---------------- 由任务 / 定时检查触发 ----------------

// eventForJob 根据任务类型与结果决定推送哪个事件。
func eventForJob(j *Job) string {
	// 未到续期时间而跳过：不是失败，也不推送通知（自动调度尤其要保持静默）。
	if j.Status == "skipped" {
		return ""
	}
	failed := j.Status == "failed" || j.Status == "canceled"
	switch j.Kind {
	case "issue":
		if failed {
			return "issue_failed"
		}
		return "cert_issued"
	case "renew", "cron":
		if failed {
			return "renew_failed"
		}
		return "cert_renewed"
	case "revoke":
		if failed {
			return "action_failed"
		}
		return "cert_revoked"
	case "remove":
		if failed {
			return "action_failed"
		}
		return "cert_removed"
	case "install":
		if failed {
			return "action_failed"
		}
		return "cert_deployed"
	}
	return ""
}

func (e *NotifyEngine) OnJob(j *Job) {
	event := eventForJob(j)
	if event == "" {
		return
	}
	domain := j.Domain
	if domain == "" {
		domain = "全部证书"
	}
	icon := "✅"
	if j.Status == "failed" || j.Status == "canceled" {
		icon = "❌"
	} else if j.Status == "success" && j.Kind == "cron" {
		icon = "🔁"
	}
	titles := map[string]string{
		"cert_issued":   "证书签发成功",
		"issue_failed":  "证书签发失败",
		"cert_renewed":  "证书续期完成",
		"renew_failed":  "证书续期失败",
		"cert_revoked":  "证书已吊销",
		"cert_removed":  "证书已移除",
		"cert_deployed": "证书已部署",
	}
	label := titles[event]
	if label == "" {
		label = j.Title
	}
	title := icon + " " + label + " · " + domain

	var b strings.Builder
	fmt.Fprintf(&b, "**任务**：%s\n", j.Title)
	fmt.Fprintf(&b, "**域名**：%s\n", domain)
	fmt.Fprintf(&b, "**状态**：%s\n", j.Status)
	fmt.Fprintf(&b, "**时间**：%s\n", j.Ended.Format("2006-01-02 15:04:05"))
	if j.Error != "" {
		fmt.Fprintf(&b, "**错误**：%s\n", j.Error)
	}
	lines := j.logs
	if len(lines) > 6 {
		lines = lines[len(lines)-6:]
	}
	if len(lines) > 0 {
		b.WriteString("\n```\n")
		b.WriteString(strings.Join(lines, "\n"))
		b.WriteString("\n```")
	}
	e.Send(event, title, b.String())
}

// CheckExpiring 每天对临期证书提醒一次（去重状态存在 state.json）。
func (e *NotifyEngine) CheckExpiring(certs []CertInfo) {
	day := time.Now().UTC().Format("2006-01-02")
	for _, c := range certs {
		if c.Status == "expired" || c.DaysLeft > 30 || c.DaysLeft < 0 {
			continue
		}
		if e.store.NotifiedToday(c.Name, day) {
			continue
		}
		e.Send("cert_expiring", fmt.Sprintf("⚠ 证书临期 · %s", c.Domain), fmt.Sprintf(
			"**域名**：%s\n**剩余**：%d 天\n**到期时间**：%s\n**签发者**：%s\n\n请及时续期。",
			c.Domain, c.DaysLeft, c.NotAfter.Format("2006-01-02 15:04:05"), c.Issuer))
		_ = e.store.MarkNotified(c.Name, day)
	}
}
