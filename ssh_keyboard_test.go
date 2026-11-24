package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"testing"

	"golang.org/x/crypto/ssh"
)

// TestDialRemoteKeyboardInteractive 覆盖只开放 keyboard-interactive 的 SSH 服务，
// 这类服务（群晖 / Windows OpenSSH / PAM 配置）用单独的 ssh.Password 会登录失败。
func TestDialRemoteKeyboardInteractive(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	serverCfg := &ssh.ServerConfig{
		KeyboardInteractiveCallback: func(c ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			answers, err := challenge(c.User(), "", []string{"Password: "}, []bool{false})
			if err != nil {
				return nil, err
			}
			if c.User() == "deploy" && len(answers) == 1 && answers[0] == "TestPass123!" {
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
				for range chans {
				}
			}()
		}
	}()

	store := &Store{dir: t.TempDir()}
	h := RemoteHost{
		Name: "test", Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port,
		User: "deploy", RemoteDir: "/tmp", Password: "TestPass123!", Enabled: true,
	}
	client, err := dialRemote(store, h)
	if err != nil {
		t.Fatalf("keyboard-interactive 认证应成功: %v", err)
	}
	_ = client.Close()

	h.Password = "wrong-password"
	client, err = dialRemote(store, h)
	if err == nil {
		_ = client.Close()
		t.Fatal("错误密码应被拒绝")
	}
}
