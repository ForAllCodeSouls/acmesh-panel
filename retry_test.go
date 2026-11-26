package main

import (
	"encoding/json"
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
