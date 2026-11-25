package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestJobHugeLogLineFailsFast 验证单行日志超过上限时任务立即失败，
// 不会因 Scanner 静默停止读取、子进程写满管道而挂到 15 分钟超时。
func TestJobHugeLogLineFailsFast(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("fake acme.sh 需要 POSIX shell，CI/Linux 环境运行")
	}
	dir := t.TempDir()
	// 用 shell 打印一行 9MB 的字符，超过 8MB 的 Scanner 上限。
	script := filepath.Join(dir, "acme.sh")
	body := "#!/bin/sh\nhead -c 9437184 /dev/zero | tr '\\000' 'x'\necho\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	acme := &ACME{Bin: script, Home: dir}
	m := NewJobManager(acme, st, 1)

	start := time.Now()
	j := m.Start("issue", "长日志测试", "x.example.com", "", nil, []string{"--issue"})
	done := make(chan struct{})
	go func() { drainJobs(m); close(done) }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("超长日志任务未在 20 秒内结束（疑似挂到 15 分钟超时）")
	}

	m.mu.Lock()
	status, jobErr := j.Status, j.Error
	m.mu.Unlock()
	if status != "failed" || !strings.Contains(jobErr, "日志行过长") {
		t.Fatalf("超长日志应快速失败并说明原因，得到 status=%s error=%q", status, jobErr)
	}
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Fatalf("耗时过长: %s", elapsed)
	}
}
