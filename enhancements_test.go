package main

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestInQuietWindow(t *testing.T) {
	base := time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC) // 周四
	cases := []struct {
		name string
		q    QuietHours
		at   time.Time
		want bool
	}{
		{"disabled", QuietHours{}, base, false},
		{"same hour disabled", QuietHours{Enabled: true, StartHour: 10, EndHour: 10}, base, false},
		{"inside", QuietHours{Enabled: true, StartHour: 9, EndHour: 12}, base, true},
		{"before", QuietHours{Enabled: true, StartHour: 11, EndHour: 12}, base, false},
		{"after", QuietHours{Enabled: true, StartHour: 8, EndHour: 10}, base, false},
		{"overnight night", QuietHours{Enabled: true, StartHour: 22, EndHour: 7},
			time.Date(2026, 11, 26, 23, 0, 0, 0, time.UTC), true},
		{"overnight morning", QuietHours{Enabled: true, StartHour: 22, EndHour: 7},
			time.Date(2026, 11, 26, 6, 0, 0, 0, time.UTC), true},
		{"overnight outside", QuietHours{Enabled: true, StartHour: 22, EndHour: 7},
			time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC), false},
		{"weekday hit", QuietHours{Enabled: true, StartHour: 9, EndHour: 12, Days: []int{4}}, base, true},
		{"weekday miss", QuietHours{Enabled: true, StartHour: 9, EndHour: 12, Days: []int{1, 2}}, base, false},
		// 跨午夜：周五 22 点开始，周六凌晨仍属于周五的窗口。
		{"overnight friday night", QuietHours{Enabled: true, StartHour: 22, EndHour: 7, Days: []int{5}},
			time.Date(2026, 11, 27, 23, 0, 0, 0, time.UTC), true},
		{"overnight saturday morning", QuietHours{Enabled: true, StartHour: 22, EndHour: 7, Days: []int{5}},
			time.Date(2026, 11, 28, 2, 0, 0, 0, time.UTC), true},
		{"overnight next day miss", QuietHours{Enabled: true, StartHour: 22, EndHour: 7, Days: []int{5}},
			time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := inQuietWindow(c.q, c.at); got != c.want {
				t.Fatalf("inQuietWindow = %v, want %v", got, c.want)
			}
		})
	}
}

func TestQuietAllows(t *testing.T) {
	q := QuietHours{Enabled: true, AllowCritical: true}
	if !quietAllows(q, "security_alert") || !quietAllows(q, "issue_failed") {
		t.Fatal("关键事件应放行")
	}
	if quietAllows(q, "cert_issued") {
		t.Fatal("普通事件不应放行")
	}
	q.AllowCritical = false
	if quietAllows(q, "security_alert") {
		t.Fatal("关闭后所有事件都应静默")
	}
}

func TestQuietHoursAllowCriticalMigration(t *testing.T) {
	dir := t.TempDir()
	s1, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	// 模拟 v0.1.70 写入的 state：quiet_hours 中没有 allow_critical 键。
	old := `{"username":"admin","quiet_hours":{"enabled":true,"start_hour":22,"end_hour":7,"days":[5]}}`
	if _, err := s1.DB().Exec(`INSERT OR REPLACE INTO state(key,value) VALUES('main',?)`, old); err != nil {
		t.Fatal(err)
	}
	_ = s1.db.Close()

	s2, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.db.Close()
	if !s2.Snapshot().QuietHours.AllowCritical {
		t.Fatal("旧配置升级后应默认放行关键告警")
	}

	// 显式写 false 的用户选择必须保留。
	explicit := `{"username":"admin","quiet_hours":{"enabled":true,"allow_critical":false}}`
	if _, err := s2.DB().Exec(`INSERT OR REPLACE INTO state(key,value) VALUES('main',?)`, explicit); err != nil {
		t.Fatal(err)
	}
	_ = s2.db.Close()
	s3, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s3.db.Close()
	if s3.Snapshot().QuietHours.AllowCritical {
		t.Fatal("显式关闭的关键告警放行不应被迁移覆盖")
	}
}

func TestNormalizeRenewNames(t *testing.T) {
	got, err := normalizeRenewNames([]string{" a.com ", "a.com", "b.com", ""})
	if err != nil || len(got) != 2 || got[0] != "a.com" || got[1] != "b.com" {
		t.Fatalf("normalizeRenewNames = %v, %v", got, err)
	}
	// acme.sh 目录名恒小写，大小写不同的同一域名应合并为一张。
	got, err = normalizeRenewNames([]string{"A.COM", "a.com", "B.com_ECC", "b.com_ecc"})
	if err != nil || len(got) != 2 || got[0] != "a.com" || got[1] != "b.com_ecc" {
		t.Fatalf("大小写去重失败: %v, %v", got, err)
	}
	if _, err := normalizeRenewNames([]string{}); err == nil {
		t.Fatal("空列表应报错")
	}
	if _, err := normalizeRenewNames([]string{"../etc/passwd"}); err == nil {
		t.Fatal("非法证书名应报错")
	}
	big := make([]string, 51)
	for i := range big {
		big[i] = "d" + strconv.Itoa(i) + ".example.com"
	}
	if _, err := normalizeRenewNames(big); err == nil {
		t.Fatal("超过 50 个应报错")
	}
}

func TestRenewArgsFor(t *testing.T) {
	args := renewArgsFor("example.com", true, true)
	want := []string{"--renew", "-d", "example.com", "--ecc", "--force"}
	if len(args) != len(want) {
		t.Fatalf("args = %v", args)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("args = %v, want %v", args, want)
		}
	}
	args = renewArgsFor("x.com", false, false)
	if len(args) != 3 || args[0] != "--renew" || args[1] != "-d" || args[2] != "x.com" {
		t.Fatalf("args = %v", args)
	}
}

func TestResolveAccountKeyPath(t *testing.T) {
	root := t.TempDir()
	// 正常路径：home/letsencrypt_account.key
	if err := os.WriteFile(filepath.Join(root, "letsencrypt_account.key"), []byte("KEY"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := resolveAccountKeyPath(root, "letsencrypt_account.conf")
	if err != nil || filepath.Base(p) != "letsencrypt_account.key" {
		t.Fatalf("resolve = %q, %v", p, err)
	}
	// 子目录路径：home/zerossl/account.key
	if err := os.MkdirAll(filepath.Join(root, "zerossl"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "zerossl", "account.key"), []byte("KEY2"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err = resolveAccountKeyPath(root, "zerossl_account.conf")
	if err != nil || filepath.Base(p) != "account.key" {
		t.Fatalf("resolve nested = %q, %v", p, err)
	}
	// 非法账户 ID
	for _, bad := range []string{"", "../account.conf", "a/b/account.conf", "account.txt", "a..account.conf"} {
		if _, err := resolveAccountKeyPath(root, bad); err == nil {
			t.Fatalf("非法 ID %q 应被拒绝", bad)
		}
	}
	// 符号链接越界
	outside := filepath.Join(t.TempDir(), "secret.key")
	if err := os.WriteFile(outside, []byte("SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Symlink(outside, filepath.Join(root, "buypass_account.key"))
	if _, err := resolveAccountKeyPath(root, "buypass_account.conf"); err == nil {
		t.Fatal("指向目录外的符号链接应被拒绝")
	}
}

func TestSetQuietHoursNormalizes(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	q := QuietHours{Enabled: true, StartHour: 99, EndHour: -3, Days: []int{9, 2, 2, -1, 4}}
	if err := s.SetQuietHours(q); err != nil {
		t.Fatal(err)
	}
	got := s.Snapshot().QuietHours
	if got.StartHour != 23 || got.EndHour != 0 {
		t.Fatalf("hours = %d/%d", got.StartHour, got.EndHour)
	}
	if len(got.Days) != 2 || got.Days[0] != 2 || got.Days[1] != 4 {
		t.Fatalf("days = %v", got.Days)
	}
	if err := s.SetDefaultCAOverride("zerossl"); err != nil {
		t.Fatal(err)
	}
	if s.Snapshot().DefaultCAOverride != "zerossl" {
		t.Fatal("默认 CA 覆盖未持久化")
	}
}
