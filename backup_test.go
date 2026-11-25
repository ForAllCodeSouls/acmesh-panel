package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRestoreCapsSyncEvents(t *testing.T) {
	st, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	in := State{}
	for i := 0; i < 300; i++ {
		in.SyncEvents = append(in.SyncEvents, SyncEvent{
			Time:   fmt.Sprintf("2026-11-25T10:%02d:00+08:00", i%60),
			Rule:   fmt.Sprintf("事件 %d", i),
			Result: "ok",
		})
	}
	if err := st.Restore(in); err != nil {
		t.Fatal(err)
	}
	got := st.AllSyncEvents()
	if len(got) != 120 {
		t.Fatalf("恢复后同步记录应为 120 条，得到 %d", len(got))
	}
	// AllSyncEvents 是倒序，保留的应是最新的 120 条（事件 180..299）。
	if !strings.Contains(got[0].Rule, "299") || !strings.Contains(got[len(got)-1].Rule, "180") {
		t.Fatalf("保留的不是最新 120 条: 首=%s 尾=%s", got[0].Rule, got[len(got)-1].Rule)
	}
}

// ---------------- 合并同步记录的筛选 ----------------

func TestFilterSyncEvents(t *testing.T) {
	all := []SyncEvent{
		{Time: "2026-11-20T08:00:00+08:00", Scope: "local", Rule: "本地覆盖", Source: "example.com",
			Target: "/certs/a_cert.pem", Result: "ok", Detail: "写入成功", Files: []string{"a_cert.pem"}},
		{Time: "2026-11-24T09:00:00+08:00", Scope: "remote", Rule: "远程同步 · NAS", Source: "/certs",
			Target: "nas:/srv/certs", Result: "fail", Detail: "连接超时", Files: []string{"a_key.pem"}},
		{Time: "2026-11-25T10:00:00+08:00", Scope: "", Rule: "旧记录", Target: "/certs/b.pem",
			Result: "skip", Detail: "内容未变化"},
	}
	cases := []struct {
		name                       string
		q, result, scope, from, to string
		want                       int
	}{
		{"无筛选返回全部", "", "", "", "", "", 3},
		{"关键词命中规则", "NAS", "", "", "", "", 1},
		{"关键词不区分大小写", "nas", "", "", "", "", 1},
		{"关键词命中文件名", "a_key.pem", "", "", "", "", 1},
		{"关键词命中详情", "连接超时", "", "", "", "", 1},
		{"按结果筛选", "", "fail", "", "", "", 1},
		{"本地范围含无 scope 旧记录", "", "", "local", "", "", 2},
		{"远程范围", "", "", "remote", "", "", 1},
		{"起始日期", "", "", "", "2026-11-24", "", 2},
		{"结束日期", "", "", "", "", "2026-11-20", 1},
		{"日期区间", "", "", "", "2026-11-21", "2026-11-24", 1},
		{"组合筛选", "", "skip", "local", "", "", 1},
		{"无匹配", "不存在的主机", "", "", "", "", 0},
		{"result=all 视为不过滤", "", "all", "", "", "", 3},
		{"scope=all 视为不过滤", "", "", "all", "", "", 3},
	}
	for _, c := range cases {
		got := filterSyncEvents(all, c.q, c.result, c.scope, c.from, c.to)
		if len(got) != c.want {
			t.Errorf("%s: 期望 %d 条，实际 %d 条", c.name, c.want, len(got))
		}
	}
}

// ---------------- 配置备份 / 恢复 ----------------

func newBackupTestServer(t *testing.T) (*Server, *Store) {
	t.Helper()
	st, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.SetUsername("admin"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetPassword("Passw0rd1234"); err != nil {
		t.Fatal(err)
	}
	return &Server{store: st}, st
}

func backupReq(method, path string, body []byte) *http.Request {
	var r *http.Request
	if body == nil {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, bytes.NewReader(body))
	}
	r = r.WithContext(context.WithValue(r.Context(), sessKey, &Session{User: "admin"}))
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	return r
}

func TestBackupExport(t *testing.T) {
	srv, st := newBackupTestServer(t)
	if err := st.SetCredSource("env"); err != nil {
		t.Fatal(err)
	}
	_ = st.PutSyncRule(SyncRule{ID: "r1", Name: "测试规则", Enabled: true, Mode: syncExact, Source: "*"})
	w := httptest.NewRecorder()
	srv.handleBackupExport(w, backupReq(http.MethodGet, "/api/backup", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("导出返回 %d: %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Content-Disposition") == "" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("导出缺少下载 / 安全响应头")
	}
	var bf BackupFile
	if err := json.Unmarshal(w.Body.Bytes(), &bf); err != nil {
		t.Fatal(err)
	}
	if bf.Format != backupFormat || bf.Version != backupVersion || bf.AppVersion != appVersion {
		t.Fatalf("备份元数据错误: %+v", bf)
	}
	if bf.ExportedAt.IsZero() {
		t.Fatal("备份缺少导出时间")
	}
	// 登录凭据绝不出现在备份文件里
	if bf.State.Username != "" || bf.State.Hash != "" || bf.State.Salt != "" ||
		bf.State.Iter != 0 || bf.State.CredSource != "" {
		t.Fatalf("备份泄漏了登录凭据或来源标记: %+v", bf.State)
	}
	if len(bf.State.SyncRules) != 1 || bf.State.SyncRules[0].Name != "测试规则" {
		t.Fatalf("备份未包含同步规则: %+v", bf.State.SyncRules)
	}
	// 导出写审计
	found := false
	for _, e := range st.AuditTail(20) {
		if e["action"] == "backup_export" {
			found = true
		}
	}
	if !found {
		t.Fatal("导出未写入审计日志")
	}
}

func TestBackupImportKeepsCredentials(t *testing.T) {
	srv, st := newBackupTestServer(t)
	if err := st.SetCredSource("web"); err != nil {
		t.Fatal(err)
	}
	before := st.Snapshot()
	importState := State{
		Username: "evil", Salt: "evil-salt", Hash: "evil-hash", Iter: 1, CredSource: "env",
		DefaultEmail: "backup@example.com", RetentionDays: 7, CronHour: 5,
		SyncRules: []SyncRule{{ID: "r1", Name: "恢复的规则", Enabled: true, Mode: syncExact, Source: "*"}},
		Update:    UpdateState{AutoCheck: true, Interval: updateIntervalWeekly},
	}
	bf := BackupFile{Format: backupFormat, Version: backupVersion, AppVersion: "0.1.27",
		ExportedAt: time.Now(), State: importState}
	body, _ := json.Marshal(bf)
	w := httptest.NewRecorder()
	srv.handleBackupImport(w, backupReq(http.MethodPost, "/api/backup", body))
	if w.Code != http.StatusOK {
		t.Fatalf("恢复返回 %d: %s", w.Code, w.Body.String())
	}
	after := st.Snapshot()
	if after.Username != "admin" || after.Hash != before.Hash || after.Salt != before.Salt || after.Iter != before.Iter {
		t.Fatal("恢复覆盖了登录凭据，应始终沿用当前数据库里的值")
	}
	if after.CredSource != "web" || st.CredSource() != "web" {
		t.Fatalf("恢复不应覆盖凭据来源标记，实际 %q", after.CredSource)
	}
	if after.DefaultEmail != "backup@example.com" || after.RetentionDays != 7 || after.CronHour != 5 {
		t.Fatalf("配置未恢复: %+v", after)
	}
	rules := st.ListSyncRules()
	if len(rules) != 1 || rules[0].Name != "恢复的规则" {
		t.Fatalf("同步规则未恢复: %+v", rules)
	}
	found := false
	for _, e := range st.AuditTail(20) {
		if e["action"] == "backup_restore" {
			found = true
		}
	}
	if !found {
		t.Fatal("恢复未写入审计日志")
	}
}

func TestBackupImportRejectsBadFiles(t *testing.T) {
	srv, _ := newBackupTestServer(t)
	cases := []struct {
		name string
		body string
	}{
		{"非 JSON", `not json at all`},
		{"格式不对", `{"format":"other","version":1,"exported_at":"2026-11-25T00:00:00Z","state":{"default_email":"x"}}`},
		{"版本不对", `{"format":"acmesh-panel-backup","version":99,"exported_at":"2026-11-25T00:00:00Z","state":{"default_email":"x"}}`},
		{"缺导出时间", `{"format":"acmesh-panel-backup","version":1,"state":{"default_email":"x"}}`},
		{"内容为空", `{"format":"acmesh-panel-backup","version":1,"exported_at":"2026-11-25T00:00:00Z","state":{}}`},
	}
	for _, c := range cases {
		w := httptest.NewRecorder()
		srv.handleBackupImport(w, backupReq(http.MethodPost, "/api/backup", []byte(c.body)))
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: 期望 400，实际 %d (%s)", c.name, w.Code, w.Body.String())
		}
	}
}

func TestGroupSyncEvents(t *testing.T) {
	base := []SyncEvent{
		{Time: "2026-11-26T00:00:25+08:00", Scope: "remote", Rule: "按证书内容同步 · 服务器1", Source: "pythonscript.duckdns.org_ecc", Target: "root@203.0.113.10:/home/web/certs/panel_key.pem", Result: "ok", Count: 1, Files: []string{"panel_key.pem"}},
		{Time: "2026-11-26T00:00:25+08:00", Scope: "remote", Rule: "按证书内容同步 · 服务器1", Source: "pythonscript.duckdns.org_ecc", Target: "root@203.0.113.10:/home/web/certs/news_key.pem", Result: "ok", Count: 1, Files: []string{"news_key.pem"}},
		{Time: "2026-11-26T00:00:26+08:00", Scope: "remote", Rule: "按证书内容同步 · 服务器1", Source: "pythonscript.duckdns.org_ecc", Target: "root@203.0.113.10:/home/web/certs/panel_cert.pem", Result: "ok", Count: 1, Files: []string{"panel_cert.pem"}},
		{Time: "2026-11-26T00:00:27+08:00", Scope: "local", Rule: "本地覆盖", Source: "loveli.de5.net_ecc", Target: "/certs/x.pem", Result: "ok", Count: 1, Files: []string{"x.pem"}},
		{Time: "2026-11-26T00:00:28+08:00", Scope: "remote", Rule: "按证书内容同步 · 服务器1", Source: "pythonscript.duckdns.org_ecc", Target: "root@203.0.113.10:/home/web/certs/bad.pem", Result: "fail", Detail: "写入失败"},
		{Time: "2026-11-26T00:05:10+08:00", Scope: "remote", Rule: "按证书内容同步 · 服务器1", Source: "pythonscript.duckdns.org_ecc", Target: "root@203.0.113.10:/home/web/certs/again.pem", Result: "ok", Count: 1, Files: []string{"again.pem"}},
	}
	groups := groupSyncEvents(base)
	if len(groups) != 4 {
		t.Fatalf("期望 4 组，实际 %d: %+v", len(groups), groups)
	}
	if groups[0].Merged != 3 || groups[0].Count != 3 || len(groups[0].Files) != 3 {
		t.Errorf("同批次事件未合并: %+v", groups[0])
	}
	if groups[0].Target != "root@203.0.113.10:/home/web/certs" {
		t.Errorf("目标目录未提取: %q", groups[0].Target)
	}
	if groups[1].Scope != "local" || groups[2].Result != "fail" || groups[2].Detail != "写入失败" || groups[3].Merged != 1 {
		t.Errorf("范围/结果/时间分组错误: %+v", groups[1:])
	}
}

func TestBackupImportRejectsForeignKey(t *testing.T) {
	_, stA := newBackupTestServer(t)
	srvB, _ := newBackupTestServer(t) // 独立目录 → 不同 secret.key
	if err := stA.PutProvider("p1", "dns_test", map[string]string{"token": "secret-value"}); err != nil {
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
		t.Fatalf("跨实例恢复应拒绝，实际 %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "secret.key") {
		t.Errorf("错误应提示密钥不匹配: %s", w.Body.String())
	}
}

func TestAllSyncEventsNewestFirst(t *testing.T) {
	st, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.AddSyncEvents([]SyncEvent{
		{Time: "2026-11-20T08:00:00+08:00", Rule: "旧", Result: "ok"},
		{Time: "2026-11-25T08:00:00+08:00", Rule: "新", Result: "ok"},
	}); err != nil {
		t.Fatal(err)
	}
	all := st.AllSyncEvents()
	if len(all) != 2 || all[0].Rule != "新" || all[1].Rule != "旧" {
		t.Fatalf("合并记录应按时间倒序: %+v", all)
	}
}
