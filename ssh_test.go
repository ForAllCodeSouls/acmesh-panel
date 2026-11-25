package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestValidateRemoteHostAuthModes(t *testing.T) {
	h := RemoteHost{
		Name: "n", Host: "192.0.2.1", Port: 22, User: "u",
		RemoteDir: "/tmp/ssl", Password: "StrongPass123!",
	}
	if err := validateRemoteHost(h); err != nil {
		t.Fatalf("密码认证应合法: %v", err)
	}
	h.Key = "PRIVATE-KEY"
	if err := validateRemoteHost(h); err == nil {
		t.Fatal("私钥与密码同时配置应被拒绝")
	}
	h.Key, h.Password = "", ""
	if err := validateRemoteHost(h); err == nil {
		t.Fatal("没有任何凭证应被拒绝")
	}
	h.Password = "p"
	h.Host = "192.0.2.1; rm -rf /"
	if err := validateRemoteHost(h); err == nil {
		t.Fatal("主机名含 shell 片段应被拒绝")
	}
}

func TestHostKeyTOFU(t *testing.T) {
	dir := t.TempDir()
	store := &Store{dir: dir}
	cb, err := hostKeyCallback(store)
	if err != nil {
		t.Fatal(err)
	}
	addr := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 22}
	host := "192.0.2.1:22"
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if err := cb(host, addr, key); err != nil {
		t.Fatalf("首次连接应记录主机密钥: %v", err)
	}
	if err := cb(host, addr, key); err != nil {
		t.Fatalf("同一密钥再次连接应通过: %v", err)
	}
	pub2, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := ssh.NewPublicKey(pub2)
	if err != nil {
		t.Fatal(err)
	}
	if err := cb(host, addr, key2); err == nil {
		t.Fatal("主机密钥变化必须拒绝（防中间人攻击）")
	}
	if runtime.GOOS == "windows" {
		t.Skip("Windows 的 chmod 不提供 POSIX 0600 语义，此断言仅适用于 Linux/macOS")
	}
	if st, err := os.Stat(filepath.Join(dir, "known_hosts")); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("known_hosts 权限应为 0600: %v", err)
	}
}
