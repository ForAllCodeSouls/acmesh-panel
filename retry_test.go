package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// drainJobs 等待已提交的异步任务跑完（run 结束会归还信号量）。
func drainJobs(m *JobManager) {
	for i := 0; i < cap(m.sem); i++ {
		m.sem <- struct{}{}
	}
}

func addJob(m *JobManager, j *Job) {
	m.mu.Lock()
	m.jobs[j.ID] = j
	m.order = append(m.order, j.ID)
	m.mu.Unlock()
}

func TestSealOpenForRetry(t *testing.T) {
	st, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.db.Close()
	env := map[string]string{"DuckDNS_Token": "secret-token", "CF_Token": "another"}
	plain, _ := json.Marshal(env)
	blob, err := st.SealForRetry(plain, "job-aaa")
	if err != nil {
		t.Fatal(err)
	}
	if blob == "" || string(plain) == blob {
		t.Fatal("密文不应为空或等同明文")
	}
	got, err := st.OpenForRetry(blob, "job-aaa")
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]string
	if json.Unmarshal(got, &back) != nil || back["DuckDNS_Token"] != "secret-token" {
		t.Fatalf("往返解密失败: %s", got)
	}
	// AAD 绑定任务 ID：换一个 ID 应解不开，防止密文被挪用到别的任务。
	if _, err := st.OpenForRetry(blob, "job-bbb"); err == nil {
		t.Fatal("更换 AAD 后仍可解密，密文可被挪用")
	}
}

func TestRetryPersistsEnvEncrypted(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.db.Close()
	m := NewJobManager(&ACME{Bin: "/nonexistent"}, st, 1)

	j := &Job{
		ID: "job-retry-persist", Kind: "issue", Title: "签发 www.example.com",
		Domain: "www.example.com", Status: "failed", Ended: time.Now(),
		retryEnv:  map[string]string{"DuckDNS_Token": "super-secret"},
		retryArgs: []string{"--issue", "--dns", "dns_duckdns", "-d", "www.example.com"},
	}
	addJob(m, j)
	m.savePersisted()

	var raw string
	if err := st.DB().QueryRow(`SELECT data FROM jobs WHERE id = ?`, j.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if contains(raw, "super-secret") {
		t.Fatal("任务落盘记录出现明文凭证")
	}
	var p persistedJob
	if json.Unmarshal([]byte(raw), &p) != nil {
		t.Fatal("落盘 JSON 解析失败")
	}
	if p.EnvBlob == "" || len(p.Args) == 0 {
		t.Fatalf("未保存重试参数: %+v", p)
	}

	// 重启后恢复：凭证与参数都应可用。
	m2 := NewJobManager(&ACME{Bin: "/nonexistent"}, st, 1)
	restored := m2.Get(j.ID)
	if restored == nil || restored.Status != "failed" {
		t.Fatalf("历史失败任务未恢复: %+v", restored)
	}
	if len(restored.retryArgs) == 0 || restored.retryEnv["DuckDNS_Token"] != "super-secret" {
		t.Fatalf("重试参数未恢复: args=%v env=%v", restored.retryArgs, restored.retryEnv)
	}
}

func TestRetryStatusGuard(t *testing.T) {
	st, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.db.Close()
	acme := &ACME{Bin: "/nonexistent", Home: t.TempDir()}
	m := NewJobManager(acme, st, 1)

	addJob(m, &Job{ID: "running-1", Kind: "issue", Status: "running",
		retryArgs: []string{"--issue"}, retryEnv: map[string]string{}})
	addJob(m, &Job{ID: "success-1", Kind: "issue", Status: "success",
		retryArgs: []string{"--issue"}, retryEnv: map[string]string{}})
	addJob(m, &Job{ID: "queued-1", Kind: "issue", Status: "queued",
		retryArgs: []string{"--issue"}, retryEnv: map[string]string{}})
	for _, id := range []string{"running-1", "success-1", "queued-1"} {
		if _, err := m.Retry(id); err == nil {
			t.Fatalf("状态 %s 不应允许重试", id)
		}
	}

	failed := &Job{ID: "failed-1", Kind: "issue", Title: "签发 x.example.com",
		Domain: "x.example.com", Status: "failed", Ended: time.Now(),
		retryArgs: []string{"--issue", "-d", "x.example.com"},
		retryEnv:  map[string]string{"K": "v"}}
	addJob(m, failed)
	nj, err := m.Retry(failed.ID)
	if err != nil {
		t.Fatal(err)
	}
	drainJobs(m) // 等待 start 启动的异步任务结束，避免 DB 句柄泄漏
	if nj.ID == failed.ID || nj.Title != failed.Title {
		t.Fatalf("重试应生成新任务且继承标题: %+v", nj)
	}
	m.mu.Lock()
	args := append([]string(nil), nj.retryArgs...)
	env := nj.retryEnv["K"]
	m.mu.Unlock()
	if len(args) == 0 || args[0] != "--issue" || env != "v" {
		t.Fatalf("重试未继承原参数: args=%v env=%q", args, env)
	}
}

// 同一失败任务只能被认领一次：手动重试后，自动退避队列到期不得再次执行。
func TestRetryClaimOnce(t *testing.T) {
	st, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.db.Close()
	m := NewJobManager(&ACME{Bin: "/nonexistent", Home: t.TempDir()}, st, 1)

	failed := &Job{ID: "claim-once", Kind: "issue", Status: "failed", Ended: time.Now(),
		retryArgs: []string{"--issue", "-d", "x.example.com"}, retryEnv: map[string]string{}}
	addJob(m, failed)
	if _, err := m.Retry(failed.ID); err != nil {
		t.Fatal(err)
	}
	drainJobs(m)
	if _, err := m.Retry(failed.ID); err == nil {
		t.Fatal("同一任务被重复认领，自动退避可能触发第二次执行")
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

func TestReissueParamsPersistWithoutSecrets(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.db.Close()
	m := NewJobManager(&ACME{Bin: "/nonexistent"}, st, 1)

	j := &Job{
		ID: "job-reissue-persist", Kind: "issue", Title: "签发 reissue.example.com",
		Domain: "reissue.example.com", Status: "failed", Ended: time.Now(),
		retryEnv:  map[string]string{"Ali_Secret": "SUPERSECRET-VALUE"},
		retryArgs: []string{"--issue", "--dns", "dns_ali", "-d", "reissue.example.com"},
	}
	addJob(m, j)
	m.SetReissue(j.ID, &ReissueInfo{
		Kind: "issue", Domains: []string{"reissue.example.com"}, Code: "dns_ali",
		KeyLength: "ec-256", CA: "letsencrypt", DNSSleep: 30, Force: true, TempEnv: true,
	})

	var raw string
	if err := st.DB().QueryRow(`SELECT data FROM jobs WHERE id = ?`, j.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if contains(raw, "SUPERSECRET-VALUE") {
		t.Fatal("重选参数落盘时出现明文凭证")
	}

	// 重启后重选参数仍可恢复，且环境凭证仍可用于原样重试。
	m2 := NewJobManager(&ACME{Bin: "/nonexistent"}, st, 1)
	info := m2.ReissueInfo(j.ID)
	if info == nil || info.CA != "letsencrypt" || !info.Force || !info.TempEnv {
		t.Fatalf("重选参数未恢复: %+v", info)
	}
	if len(info.Domains) != 1 || info.Domains[0] != "reissue.example.com" {
		t.Fatalf("域名未恢复: %v", info.Domains)
	}
	restored := m2.Get(j.ID)
	if restored == nil || restored.retryEnv["Ali_Secret"] != "SUPERSECRET-VALUE" {
		t.Fatal("原任务的凭证未恢复，影响原样重试")
	}
}

func TestPermanentFailureHint(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
		want  string
	}{
		{"eab", []string{"Account registration error:{\"type\":\"urn:ietf:params:acme:error:externalAccountRequired\"}"}, "EAB"},
		{"rate limit", []string{"The retryafter=86400 value is too large (> 600), will not retry anymore."}, "限流"},
		{"rate limit header", []string{"Retry-After: 86400"}, "限流"},
		{"short rate limit (Let's Encrypt)", []string{"too many failed authorizations recently: see https://letsencrypt.org/docs/failed-validation-limit/"}, ""},
		{"short retryafter", []string{"retryafter=30"}, ""},
		{"dns", []string{"curl error code: 6", "Cannot init API for: buypass."}, "DNS"},
		{"transient", []string{"Processing. The CA is processing your order, please wait."}, ""},
	}
	for _, c := range cases {
		got := permanentFailureHint(c.lines, "exit status 1")
		if c.want == "" && got != "" {
			t.Fatalf("%s: 不应识别为永久失败: %s", c.name, got)
		}
		if c.want != "" && !strings.Contains(got, c.want) {
			t.Fatalf("%s: 期望提示含 %q，得到 %q", c.name, c.want, got)
		}
	}
}

func TestEABEnvNeverInArgs(t *testing.T) {
	extra, err := eabEnv("kid12345", "hmac_ABCDEF123456")
	if err != nil {
		t.Fatal(err)
	}
	if extra[eabKidEnv] != "kid12345" || extra[eabHMACEnv] != "hmac_ABCDEF123456" {
		t.Fatal("EAB env 未正确生成")
	}
	if _, err := eabEnv("kid12345", ""); err == nil {
		t.Fatal("缺少 HMAC 时应拒绝")
	}
	// EAB 只存在 env，args 由 buildIssueArgs 构造，绝不含 kid/hmac。
	args := buildIssueArgs("dns_duckdns", 30, "a@example.net", "ec-256", "google", false, []string{"x.example.net"}, "")
	for _, a := range args {
		if strings.Contains(a, "kid12345") || strings.Contains(a, "hmac_ABCDEF123456") {
			t.Fatalf("args 泄漏 EAB: %v", args)
		}
	}
	// acme.sh 在执行前才把 env 转成命令行参数；子进程环境不应残留这两个变量。
	cmd := (&ACME{Home: t.TempDir(), Bin: "/bin/true", Log: "/tmp/acme.log"}).cmd(context.Background(), extra, "--version")
	joined := strings.Join(cmd.Args, " ")
	if !strings.Contains(joined, "--eab-kid kid12345") || !strings.Contains(joined, "--eab-hmac-key hmac_ABCDEF123456") {
		t.Fatalf("acme.sh 未收到 EAB 参数: %s", joined)
	}
	for _, e := range cmd.Env {
		if strings.HasPrefix(e, eabKidEnv+"=") || strings.HasPrefix(e, eabHMACEnv+"=") {
			t.Fatalf("EAB 敏感变量泄漏到子进程环境: %s", e)
		}
	}
}

func TestEABStandardBase64Normalization(t *testing.T) {
	cases := []struct {
		name     string
		kid      string
		hmac     string
		wantKid  string
		wantHMAC string
		wantErr  bool
	}{
		{"base64url 原样", "kid12345678", "SGVsbG9Xb3JsZEFiY2RlZjEyMzQ1Njc4OTBfLQ", "kid12345678", "SGVsbG9Xb3JsZEFiY2RlZjEyMzQ1Njc4OTBfLQ", false},
		{"标准 base64 带 padding", "kid12345678", "abcdefgh=", "kid12345678", "abcdefgh", false},
		{"标准 base64 含 +/", "kid12345678", "abc+def/ghi12345", "kid12345678", "abc-def_ghi12345", false},
		{"前后空格", "  kid12345678  ", "  hmac_ABCDEF123456  ", "kid12345678", "hmac_ABCDEF123456", false},
	}
	for _, c := range cases {
		got, err := eabEnv(c.kid, c.hmac)
		if c.wantErr {
			if err == nil {
				t.Fatalf("%s: 期望拒绝但通过: %+v", c.name, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: 不应报错: %v", c.name, err)
		}
		if got[eabKidEnv] != c.wantKid || got[eabHMACEnv] != c.wantHMAC {
			t.Fatalf("%s: 归一化结果不符: kid=%q hmac=%q", c.name, got[eabKidEnv], got[eabHMACEnv])
		}
	}
}
