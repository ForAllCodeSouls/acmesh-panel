package main

import (
	"path/filepath"
	"runtime"
	"testing"
)

// 平台无关的同步目录基准：Linux 容器里是 /certs，Windows 上用盘符模拟绝对路径。
func testSyncBase() (string, string, string, string) {
	if runtime.GOOS == "windows" {
		return `C:\certs`, `baihu.loveli.de5.net_cert.pem`, `C:\certs\baihu.loveli.de5.net_cert.pem`, `..\etc\passwd`
	}
	return "/certs", "baihu.loveli.de5.net_cert.pem", "/certs/baihu.loveli.de5.net_cert.pem", "../etc/passwd"
}

// 复现截图中的路径缺陷：目录 + 已在目录内的绝对路径曾被拼成 .../certs/certs/...。
func TestResolveSyncLocalPath(t *testing.T) {
	dir, name, abs, escape := testSyncBase()
	outside := "/etc/passwd"
	if runtime.GOOS == "windows" {
		outside = `C:\etc\passwd`
	}
	cases := []struct {
		label string
		in    string
		want  string
		fail  bool
	}{
		{"相对文件名", name, abs, false},
		{"已是绝对路径（强制推送入口）", abs, abs, false},
		{"目录穿越被拒绝", escape, "", true},
		{"其它目录的绝对路径被拒绝", outside, "", true},
		{"空文件名被拒绝", "  ", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			got, err := resolveSyncLocalPath(dir, tc.in)
			if tc.fail {
				if err == nil {
					t.Fatalf("期望拒绝 %q，实际得到 %q", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("解析 %q 失败: %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("解析 %q = %q，期望 %q", tc.in, got, tc.want)
			}
			if got == filepath.Join(dir, "certs", name) {
				t.Fatal("仍然出现目录重复前缀")
			}
		})
	}
}

func TestResolveSyncLocalPathInTempDir(t *testing.T) {
	dir := t.TempDir()
	name := "site_cert.pem"
	got, err := resolveSyncLocalPath(dir, filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("绝对路径解析失败: %v", err)
	}
	if want := filepath.Join(dir, name); got != want {
		t.Fatalf("得到 %q，期望 %q", got, want)
	}
}

func TestSplitSyncEvents(t *testing.T) {
	all := []SyncEvent{
		{Scope: "local", Result: "ok", Rule: "本地覆盖"},
		{Scope: "remote", Result: "fail", Rule: "远程同步 · NAS"},
		{Scope: "", Result: "ok", Rule: "旧记录"}, // 无 scope 归本地
		{Scope: "remote", Result: "ok", Rule: "远程同步 · VPS"},
	}
	local, remote := splitSyncEvents(all)
	if len(local) != 2 || len(remote) != 2 {
		t.Fatalf("分流结果错误: local=%d remote=%d", len(local), len(remote))
	}
	for _, ev := range remote {
		if ev.Scope != "remote" {
			t.Fatalf("远程记录混入 scope=%q 的事件", ev.Scope)
		}
	}
	for _, ev := range local {
		if ev.Scope == "remote" {
			t.Fatalf("本地记录混入远程事件: %+v", ev)
		}
	}
}
