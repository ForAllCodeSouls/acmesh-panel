package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// scpSink 是测试用的 scp -t 接收端，按标准 scp 协议回 ACK 并落盘。
func scpSink(ch ssh.Channel, dest string) {
	one := make([]byte, 1)
	_, _ = ch.Write([]byte{0})
	line := []byte{}
	for {
		n, err := ch.Read(one)
		if err != nil || n == 0 {
			return
		}
		if one[0] == '\n' {
			break
		}
		line = append(line, one[0])
	}
	fields := strings.Fields(string(line))
	if len(fields) < 3 {
		return
	}
	size, err := strconv.Atoi(fields[1])
	if err != nil || size < 0 || size > 1<<20 {
		return
	}
	_, _ = ch.Write([]byte{0})
	buf := make([]byte, size+1)
	if _, err := io.ReadFull(ch, buf); err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(dest, filepath.Base(fields[2])), buf[:size], 0o644)
	_, _ = ch.Write([]byte{0})
	_, _ = ch.Read(one) // 客户端结束信号
}

// TestPushToRemoteWithPassword 用真实的内存 SSH server 验证密码认证 + scp 推送。
func TestPushToRemoteWithPassword(t *testing.T) {
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
			if c.User() == "deploy" && string(pass) == "TestPass123!" {
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
	defer ln.Close()
	dest := t.TempDir()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, chans, reqs, err := ssh.NewServerConn(c, serverCfg)
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
							if req.Type != "exec" {
								_ = req.Reply(false, nil)
								continue
							}
							var payload struct{ Command string }
							if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
								return
							}
							_ = req.Reply(true, nil)
							if strings.HasPrefix(payload.Command, "scp -t ") {
								scpSink(ch, dest)
							}
							_, _ = ch.SendRequest("exit-status", false,
								ssh.Marshal(struct{ Status uint32 }{0}))
							return
						}
					}()
				}
			}()
		}
	}()

	src := filepath.Join(t.TempDir(), "site_cert.pem")
	if err := os.WriteFile(src, []byte("CERT-CONTENT"), 0o644); err != nil {
		t.Fatal(err)
	}
	store := &Store{dir: t.TempDir()}
	h := RemoteHost{
		Name: "test", Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port,
		User: "deploy", RemoteDir: dest, Password: "TestPass123!", Enabled: true,
	}
	if err := pushToRemote(store, h, []string{src}); err != nil {
		t.Fatalf("密码认证推送失败: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "site_cert.pem"))
	if err != nil || string(got) != "CERT-CONTENT" {
		t.Fatalf("远程文件内容不符: %q err=%v", got, err)
	}
	h.Password = "wrong-password"
	if err := pushToRemote(store, h, []string{src}); err == nil {
		t.Fatal("错误密码应被拒绝")
	}
}
