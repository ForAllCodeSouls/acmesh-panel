package main

import "testing"

// TestCredSourcePersistence 验证凭据来源随状态落盘，重启（重新打开 Store）后仍在。
func TestCredSourcePersistence(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.CredSource(); got != "" {
		t.Fatalf("全新库凭据来源应为空（待启动时初始化/迁移），实际 %q", got)
	}
	if err := st.SetUsername("admin"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetPassword("InitPassw0rd!2026"); err != nil {
		t.Fatal(err)
	}
	for _, src := range []string{"env", "generated", "web"} {
		if err := st.SetCredSource(src); err != nil {
			t.Fatal(err)
		}
		if got := st.CredSource(); got != src {
			t.Fatalf("设置 %q 后读回为 %q", src, got)
		}
	}
	// 单纯改密码/改账号不应擅自改变来源，来源由调用方显式维护。
	if err := st.SetPassword("AnotherPassw0rd!2026"); err != nil {
		t.Fatal(err)
	}
	if got := st.CredSource(); got != "web" {
		t.Fatalf("SetPassword 不应清除凭据来源，实际 %q", got)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	st2, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	if got := st2.CredSource(); got != "web" {
		t.Fatalf("重新打开后凭据来源丢失，实际 %q", got)
	}
	if st2.Username() != "admin" {
		t.Fatalf("重新打开后账号异常: %q", st2.Username())
	}
	if !st2.CheckPassword("AnotherPassw0rd!2026") {
		t.Fatal("重新打开后密码校验失败")
	}
}

// TestCredSourceLegacyState 模拟 v0.1.28 及更早版本的 state：没有 cred_source 字段，
// load() 后应保持空串，由启动逻辑按 env 推断迁移，不误报为 web。
func TestCredSourceLegacyState(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.saveLocked(); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	// 直接用不含 cred_source 的 JSON 覆盖 state 表。
	db, err := openDB(dir)
	if err != nil {
		t.Fatal(err)
	}
	legacy := `{"username":"admin","salt":"","hash":"","iter":0,"cron_hour":3,"retention_days":30}`
	if _, err := db.Exec(`INSERT INTO state(key,value) VALUES('main',?) `+
		`ON CONFLICT(key) DO UPDATE SET value=excluded.value`, legacy); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	st2, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	if got := st2.CredSource(); got != "" {
		t.Fatalf("旧 state 应保留空来源等待启动迁移，实际 %q", got)
	}
	hour, _ := st2.CronSchedule()
	if st2.Username() != "admin" || hour != 3 {
		t.Fatalf("旧 state 其它字段读取异常: user=%q cron=%d", st2.Username(), hour)
	}
}
