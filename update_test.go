package main

import (
	"encoding/json"
	"testing"
	"time"
)

func TestValidUpdateInterval(t *testing.T) {
	for _, v := range []string{"off", "startup", "6h", "daily", "weekly"} {
		if !validUpdateInterval(v) {
			t.Fatalf("合法频次被拒绝: %s", v)
		}
	}
	for _, v := range []string{"", "hourly", "DAILY", "30m", "1"} {
		if validUpdateInterval(v) {
			t.Fatalf("非法频次被接受: %s", v)
		}
	}
}

func TestUpdateIntervalDuration(t *testing.T) {
	cases := map[string]time.Duration{
		"6h":      6 * time.Hour,
		"daily":   24 * time.Hour,
		"weekly":  168 * time.Hour,
		"off":     0,
		"startup": 0,
	}
	for k, want := range cases {
		if got := updateIntervalDuration(k); got != want {
			t.Fatalf("%s 间隔 = %v，期望 %v", k, got, want)
		}
	}
}

func TestVersionNewer(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"v0.1.25", "0.1.24", true},
		{"0.2.0", "0.1.99", true},
		{"1.0.0", "0.9.9", true},
		{"0.1.24", "0.1.24", false},
		{"0.1.23", "0.1.24", false},
		{"v0.1.9", "0.1.10", false},
	}
	for _, c := range cases {
		if got := versionNewer(c.a, c.b); got != c.want {
			t.Fatalf("versionNewer(%q,%q)=%v，期望 %v", c.a, c.b, got, c.want)
		}
	}
}

// CI 构建注入的非语义版本号（如 "ci"、"dev"）不应触发"有新版本"，
// 否则 CI 上 e2e 的「默认未检测时无新版本」断言会因仓库存在 Release 而必挂。
func TestIsSemanticVersion(t *testing.T) {
	cases := []struct {
		v    string
		want bool
	}{
		{"0.1.40", true},
		{"v0.1.40", true},
		{"ci", false},
		{"dev", false},
		{"", false},
		{"v", false},
		{"1", true},
	}
	for _, c := range cases {
		if got := isSemanticVersion(c.v); got != c.want {
			t.Fatalf("isSemanticVersion(%q)=%v，期望 %v", c.v, got, c.want)
		}
	}
}

func TestUpdateConfigDefaultsAndPersistence(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	st := s.UpdateConfig()
	if !st.AutoCheck || st.Interval != updateIntervalDaily {
		t.Fatalf("默认应为开启+每天，实际 %+v", st)
	}
	if err := s.SetUpdateConfig(false, "weekly"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUpdateConfig(true, "bogus"); err == nil {
		t.Fatal("非法频次应被拒绝")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	st = again.UpdateConfig()
	if st.AutoCheck || st.Interval != "weekly" {
		t.Fatalf("重启后配置丢失: %+v", st)
	}
}

func TestUpdateConfigLegacyState(t *testing.T) {
	dir := t.TempDir()
	raw := `{"username":"admin","cron_hour":3,"retention_days":30}`
	if err := writeLegacyMainState(t, dir, raw); err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	st := s.UpdateConfig()
	if !st.AutoCheck || st.Interval != updateIntervalDaily {
		t.Fatalf("旧数据应补默认开启+每天，实际 %+v", st)
	}
}

func TestRecordUpdateCheckAndNotifyOnce(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := s.RecordUpdateCheck("v9.9.9", true, "", "https://example.com/rel"); err != nil {
		t.Fatal(err)
	}
	first, err := s.MarkUpdateNotified("v9.9.9")
	if err != nil || !first {
		t.Fatalf("首次应提醒: %v %v", first, err)
	}
	second, err := s.MarkUpdateNotified("v9.9.9")
	if err != nil || second {
		t.Fatalf("同版本不应重复提醒: %v %v", second, err)
	}
	// 版本无更新后清空已提醒版本，再出现新版本应重新提醒。
	if err := s.RecordUpdateCheck("v9.9.9", false, "", ""); err != nil {
		t.Fatal(err)
	}
	third, err := s.MarkUpdateNotified("v9.9.9")
	if err != nil || !third {
		t.Fatalf("恢复新版本后应重新提醒: %v %v", third, err)
	}
	st := s.UpdateConfig()
	if st.Latest != "v9.9.9" || st.NeedUpdate || st.LastCheck.IsZero() {
		t.Fatalf("检测结果异常: %+v", st)
	}
}

// writeLegacyMainState 把一段旧格式 JSON 写入 state 表，模拟升级前的状态。
func writeLegacyMainState(t *testing.T, dir, raw string) error {
	t.Helper()
	s, err := NewStore(dir)
	if err != nil {
		return err
	}
	if err := s.Close(); err != nil {
		return err
	}
	db, err := openDB(dir)
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = db.Exec(`INSERT INTO state(key,value) VALUES('main',?) `+
		`ON CONFLICT(key) DO UPDATE SET value=excluded.value`, raw)
	return err
}

func TestReleaseInfoParsing(t *testing.T) {
	var rel releaseInfo
	if err := json.Unmarshal([]byte(`{"tag_name":"v9.8.7","html_url":"https://example.com/rel"}`), &rel); err != nil {
		t.Fatal(err)
	}
	if rel.TagName != "v9.8.7" || rel.HTMLURL != "https://example.com/rel" {
		t.Fatalf("Release 解析错误: %+v", rel)
	}
}
