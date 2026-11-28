package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBackupImportRejectsForeignEAB(t *testing.T) {
	_, stA := newBackupTestServer(t)
	srvB, _ := newBackupTestServer(t) // 独立目录 → 不同 secret.key
	if err := stA.PutEAB("google-main", "google", "kid-value", "hmac-value"); err != nil {
		t.Fatal(err)
	}
	bf := BackupFile{
		Format: backupFormat, Version: backupVersion, AppVersion: "test",
		ExportedAt: time.Now(), State: stA.Snapshot(),
	}
	body, err := json.Marshal(bf)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	srvB.handleBackupImport(w, backupReq(http.MethodPost, "/api/backup", body))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("含 EAB 凭证的跨实例恢复应拒绝，实际 %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "EAB 凭证") || !strings.Contains(w.Body.String(), "secret.key") {
		t.Fatalf("错误应提示 EAB 凭证与密钥不匹配: %s", w.Body.String())
	}
	if counts := backupCounts(stA.Snapshot()); counts["eab_creds"] != 1 {
		t.Fatalf("备份预览应包含 EAB 凭证计数: %+v", counts)
	}
}

func TestNotifyRetryBackoff(t *testing.T) {
	cases := []struct {
		attempts int
		want     time.Duration
	}{
		{1, time.Minute},
		{2, time.Minute},
		{3, 2 * time.Minute},
		{4, 4 * time.Minute},
		{5, 24 * time.Hour},
	}
	for _, c := range cases {
		if got := notifyRetryBackoff(c.attempts); got != c.want {
			t.Errorf("notifyRetryBackoff(%d)=%v want %v", c.attempts, got, c.want)
		}
	}
}

func TestAddNotifyFailurePreservesBackoff(t *testing.T) {
	st, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	n := Notifier{ID: "n1", Name: "渠道", Kind: "generic", Events: []string{"issue_failed"}, Enabled: true}
	msg := NotifyMessage{Title: "签发失败", Event: "issue_failed", Time: time.Now().Format(time.RFC3339)}
	st.AddNotifyFailure(n, msg, errString("第一次"))
	st.AddNotifyFailure(n, msg, errString("第二次"))
	list := st.ListNotifyFailures(10)
	if len(list) != 1 || list[0].Attempts != 2 {
		t.Fatalf("同类失败应去重且 attempts=2: %+v", list)
	}
	if !list[0].NextAttempt.After(time.Now().Add(45 * time.Second)) {
		t.Fatalf("第二次失败应按退避排队而非立即重试，实际 %v", list[0].NextAttempt)
	}
	if len(st.DueNotifyFailures(time.Now(), 10)) != 0 {
		t.Fatal("退避中的记录不应进入重试队列")
	}
	for i := 0; i < 3; i++ {
		st.AddNotifyFailure(n, msg, errString("再次失败"))
	}
	list = st.ListNotifyFailures(10)
	if len(list) != 1 || list[0].Status != "exhausted" || list[0].Attempts != notifyRetryMax {
		t.Fatalf("累计失败应标为耗尽: %+v", list)
	}
	if len(st.DueNotifyFailures(time.Now(), 10)) != 0 {
		t.Fatal("耗尽记录不应进入重试队列")
	}
}
