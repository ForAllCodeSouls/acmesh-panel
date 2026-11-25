package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestSelectRemoteFilesDedup(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a_cert.pem")
	b := filepath.Join(dir, "b_cert.pem")
	if err := os.WriteFile(a, []byte("cert A"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("cert B"), 0o644); err != nil {
		t.Fatal(err)
	}
	digestA, err := remoteFileDigest(a)
	if err != nil {
		t.Fatal(err)
	}
	files := []string{"a_cert.pem", "b_cert.pem"}
	seen := map[string]string{remoteSeenKey("h1", dir, "a_cert.pem"): digestA}

	got := selectRemoteFiles("h1", dir, files, false, seen, map[string]string{})
	if !reflect.DeepEqual(got, []string{"b_cert.pem"}) {
		t.Fatalf("普通同步应跳过未变化文件，实际推送 %v", got)
	}

	got = selectRemoteFiles("h2", dir, files, false, seen, map[string]string{})
	if !reflect.DeepEqual(got, files) {
		t.Fatalf("不同主机应各自记录摘要，实际推送 %v", got)
	}

	got = selectRemoteFiles("h1", dir, files, true, seen, map[string]string{})
	if !reflect.DeepEqual(got, files) {
		t.Fatalf("强制同步应重推全部文件，实际推送 %v", got)
	}

	if err := os.WriteFile(a, []byte("cert A renewed"), 0o644); err != nil {
		t.Fatal(err)
	}
	got = selectRemoteFiles("h1", dir, files, false, seen, map[string]string{})
	if !reflect.DeepEqual(got, files) {
		t.Fatalf("证书内容变化后应重新推送，实际推送 %v", got)
	}
}

func TestRemoteSeenPersists(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	key := remoteSeenKey("h1", "/certs", "a_cert.pem")
	if err := s.MarkRemoteSeen(map[string]string{key: "deadbeef"}); err != nil {
		t.Fatal(err)
	}
	if got := s.RemoteSeenCount(); got != 1 {
		t.Fatalf("摘要计数应为 1，实际 %d", got)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := again.RemoteSeens()[key]; got != "deadbeef" {
		t.Fatalf("重启后摘要丢失: %q", got)
	}
	if err := again.Close(); err != nil {
		t.Fatal(err)
	}
}
