package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// 启动一个只接受密码认证并提供 sftp 子系统的测试 SSH server。
func startSFTPTestServer(t *testing.T, password string) (int, func()) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	serverCfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == "deploy" && string(pass) == password {
				return nil, nil
			}
			return nil, errors.New("bad credentials")
		},
	}
	serverCfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, chans, reqs, err := ssh.NewServerConn(conn, serverCfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					if nc.ChannelType() != "session" {
						_ = nc.Reject(ssh.UnknownChannelType, "unsupported")
						continue
					}
					ch, chReqs, err := nc.Accept()
					if err != nil {
						continue
					}
					go func() {
						defer ch.Close()
						for req := range chReqs {
							if req.Type != "subsystem" {
								_ = req.Reply(false, nil)
								continue
							}
							var payload struct{ Name string }
							if ssh.Unmarshal(req.Payload, &payload) != nil || payload.Name != "sftp" {
								_ = req.Reply(false, nil)
								continue
							}
							_ = req.Reply(true, nil)
							srv, err := sftp.NewServer(ch)
							if err != nil {
								return
							}
							_ = srv.Serve()
							_ = srv.Close()
							return
						}
					}()
				}
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, func() { _ = ln.Close() }
}

// TestPushToRemoteWithPassword 用真实的 SSH + SFTP server 验证密码认证与文件推送。
func TestPushToRemoteWithPassword(t *testing.T) {
	port, stop := startSFTPTestServer(t, "TestPass123!")
	defer stop()

	src := filepath.Join(t.TempDir(), "site_cert.pem")
	if err := os.WriteFile(src, []byte("CERT-CONTENT"), 0o644); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "certs") // 故意不存在，验证自动创建
	store := &Store{dir: t.TempDir()}
	h := RemoteHost{
		Name: "test", Host: "127.0.0.1", Port: port,
		User: "deploy", RemoteDir: dest, Password: "TestPass123!", Enabled: true,
	}
	if err := pushToRemote(store, h, []string{src}); err != nil {
		t.Fatalf("密码认证 + SFTP 推送失败: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "site_cert.pem"))
	if err != nil || string(got) != "CERT-CONTENT" {
		t.Fatalf("远程文件内容不符: %q err=%v", got, err)
	}
	// 原子替换不应残留临时文件
	entries, err := os.ReadDir(dest)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".acmesh-tmp") {
			t.Fatalf("推送后残留临时文件: %s", e.Name())
		}
	}
	h.Password = "wrong-password"
	if err := pushToRemote(store, h, []string{src}); err == nil {
		t.Fatal("错误密码应被拒绝")
	}
}
