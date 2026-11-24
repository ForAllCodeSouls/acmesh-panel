package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// ---------------- 远程主机（加密存储） ----------------

func (s *Store) PutRemoteHost(h RemoteHost) error {
	if h.ID == "" || h.Name == "" || h.Host == "" || h.User == "" || h.RemoteDir == "" {
		return errors.New("ID / 名称 / 主机 / 用户 / 远程目录不能为空")
	}
	if h.Port == 0 {
		h.Port = 22
	}
	if h.Port < 1 || h.Port > 65535 {
		return errors.New("端口必须在 1-65535 之间")
	}
	plain, err := json.Marshal(h)
	if err != nil {
		return err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	ct := s.aead.Seal(nil, nonce, plain, []byte(h.ID))
	blob := base64.StdEncoding.EncodeToString(append(nonce, ct...))

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.RemoteHosts == nil {
		s.state.RemoteHosts = map[string]EncRemote{}
	}
	s.state.RemoteHosts[h.ID] = EncRemote{Blob: blob}
	return s.saveLocked()
}

func (s *Store) GetRemoteHost(id string) (RemoteHost, error) {
	s.mu.RLock()
	enc, ok := s.state.RemoteHosts[id]
	s.mu.RUnlock()
	if !ok {
		return RemoteHost{}, errors.New("远程主机不存在")
	}
	b, err := base64.StdEncoding.DecodeString(enc.Blob)
	if err != nil || len(b) < s.aead.NonceSize() {
		return RemoteHost{}, errors.New("远程主机数据损坏")
	}
	nonce, ct := b[:s.aead.NonceSize()], b[s.aead.NonceSize():]
	plain, err := s.aead.Open(nil, nonce, ct, []byte(id))
	if err != nil {
		return RemoteHost{}, errors.New("远程主机解密失败")
	}
	var h RemoteHost
	if json.Unmarshal(plain, &h) != nil {
		return RemoteHost{}, errors.New("远程主机数据格式错误")
	}
	if h.Port == 0 {
		h.Port = 22
	}
	return h, nil
}

func (s *Store) DeleteRemoteHost(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.state.RemoteHosts, id)
	return s.saveLocked()
}

func (s *Store) ListRemoteHosts() []RemoteHostView {
	s.mu.RLock()
	ids := make([]string, 0, len(s.state.RemoteHosts))
	for id := range s.state.RemoteHosts {
		ids = append(ids, id)
	}
	s.mu.RUnlock()
	sort.Strings(ids)
	out := make([]RemoteHostView, 0, len(ids))
	for _, id := range ids {
		h, err := s.GetRemoteHost(id)
		if err != nil {
			continue
		}
		authMode := "key"
		if h.Password != "" {
			authMode = "password"
		}
		out = append(out, RemoteHostView{
			ID: h.ID, Name: h.Name, Host: h.Host, Port: h.Port,
			User: h.User, RemoteDir: h.RemoteDir,
			KeyMasked: mask(h.Key), HasKey: h.Key != "",
			PasswordMasked: mask(h.Password), HasPassword: h.Password != "",
			AuthMode: authMode, Enabled: h.Enabled,
		})
	}
	return out
}

// ---------------- SSH 推送（纯 Go，不使用 ssh/scp 外部命令） ----------------

// validateRemoteHost 校验远程配置：主机、用户、路径严格白名单，杜绝命令/路径注入。
func validateRemoteHost(h RemoteHost) error {
	name := strings.TrimSpace(h.Name)
	if name == "" || len(name) > 64 || strings.ContainsAny(name, "\t\n\r\x00<>&\"'") {
		return errors.New("名称不能为空且不能含换行或尖括号等特殊字符")
	}
	if h.Host == "" || len(h.Host) > 253 || strings.ContainsAny(h.Host, " /\\\t\n\r\x00'\"$;`|&*?<>") {
		return errors.New("主机名含非法字符")
	}
	if h.User == "" || len(h.User) > 64 || strings.ContainsAny(h.User, " /\\\t\n\r\x00'\"$;`|&*?<>") {
		return errors.New("用户名含非法字符")
	}
	if !strings.HasPrefix(h.RemoteDir, "/") || strings.Contains(h.RemoteDir, "..") ||
		strings.ContainsAny(h.RemoteDir, "\t\n\r\x00'\"$;`|&*?<>") {
		return errors.New("远程目录必须是绝对路径且不含非法字符")
	}
	if h.Port < 1 || h.Port > 65535 {
		return errors.New("端口非法")
	}
	if h.Key == "" && h.Password == "" {
		return errors.New("请配置 SSH 私钥或登录密码")
	}
	if h.Key != "" && h.Password != "" {
		return errors.New("私钥与密码只能选一种认证方式")
	}
	if len(h.Password) > 1024 || len(h.Key) > 1024*1024 {
		return errors.New("凭证内容过长")
	}
	return nil
}

var hostKeyMu sync.Mutex

// hostKeyCallback 首次信任（TOFU）并在 known_hosts 中记录主机密钥；
// 之后严格校验，主机密钥变化直接拒绝，防止中间人攻击。
func hostKeyCallback(store *Store) (ssh.HostKeyCallback, error) {
	path := filepath.Join(store.dir, "known_hosts")
	if err := ensurePrivateFile(path); err != nil {
		return nil, err
	}
	cb, err := knownhosts.New(path)
	if err != nil {
		return nil, err
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := cb(hostname, remote, key)
		if err == nil {
			return nil
		}
		var keyErr *knownhosts.KeyError
		if !errors.As(err, &keyErr) || len(keyErr.Want) > 0 {
			return err // 密钥不匹配或文件格式错误，拒绝
		}
		// 该主机尚无记录：重新读文件确认，避免闭包缓存导致密钥变化被误当成首次连接
		hostKeyMu.Lock()
		defer hostKeyMu.Unlock()
		if fresh, e := knownhosts.New(path); e == nil {
			e2 := fresh(hostname, remote, key)
			if e2 == nil {
				return nil // 已被其它并发请求写入且密钥一致
			}
			var freshErr *knownhosts.KeyError
			if errors.As(e2, &freshErr) && len(freshErr.Want) > 0 {
				return e2 // 密钥已变，拒绝连接（防中间人攻击）
			}
		}
		line := knownhosts.Line([]string{knownhosts.Normalize(hostname)}, key) + "\n"
		f, e := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if e != nil {
			return e
		}
		_, e = f.WriteString(line)
		_ = f.Close()
		if e != nil {
			return e
		}
		logRemoteInfof("已记录远程主机 %s 的密钥指纹 %s", hostname, ssh.FingerprintSHA256(key))
		return nil
	}, nil
}

func ensurePrivateFile(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	return f.Close()
}

// dialRemote 建立 SSH 连接。密码/私钥只存在于内存，不写入命令行或临时文件。
func dialRemote(store *Store, h RemoteHost) (*ssh.Client, error) {
	if err := validateRemoteHost(h); err != nil {
		return nil, err
	}
	var auth ssh.AuthMethod
	if h.Password != "" {
		auth = ssh.Password(h.Password)
	} else {
		signer, err := ssh.ParsePrivateKey([]byte(h.Key))
		if err != nil {
			return nil, fmt.Errorf("SSH 私钥解析失败: %v", err)
		}
		auth = ssh.PublicKeys(signer)
	}
	hcb, err := hostKeyCallback(store)
	if err != nil {
		return nil, err
	}
	cfg := &ssh.ClientConfig{
		User:            h.User,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: hcb,
		Timeout:         10 * time.Second,
	}
	addr := net.JoinHostPort(h.Host, strconv.Itoa(h.Port))
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("SSH 连接失败: %v", err)
	}
	return client, nil
}

// pushToRemote 通过 scp -t 协议推送文件。文件名取 basename，远程目录已校验，
// 命令不含任何用户可控的 shell 片段。
func pushToRemote(store *Store, h RemoteHost, localFiles []string) error {
	if !h.Enabled || len(localFiles) == 0 {
		return nil
	}
	client, err := dialRemote(store, h)
	if err != nil {
		return err
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("创建 SSH 会话失败: %v", err)
	}
	defer session.Close()
	stdin, err := session.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return err
	}
	stdoutReader := bufio.NewReader(stdout)
	var stderrBuf strings.Builder
	session.Stderr = &stderrBuf

	// 远程目录已通过白名单校验（无空格/引号/分号），单引号包裹后安全。
	if err := session.Start("scp -t '" + h.RemoteDir + "'"); err != nil {
		return fmt.Errorf("启动远程 scp 失败: %v", err)
	}
	ack := make([]byte, 1)
	waitAck := func() error {
		if _, err := io.ReadFull(stdoutReader, ack); err != nil {
			return fmt.Errorf("scp 响应异常: %v (%s)", err, strings.TrimSpace(stderrBuf.String()))
		}
		switch ack[0] {
		case 0:
			return nil
		case 1, 2:
			line, _ := stdoutReader.ReadString('\n')
			return fmt.Errorf("远程拒绝: %s", strings.TrimSpace(line))
		default:
			return fmt.Errorf("scp 响应异常: %d", ack[0])
		}
	}
	if err := waitAck(); err != nil {
		_ = stdin.Close()
		return err
	}
	for _, f := range localFiles {
		if !filepath.IsAbs(f) || strings.Contains(f, "..") {
			_ = stdin.Close()
			return errors.New("本地文件路径非法")
		}
		data, err := os.ReadFile(f)
		if err != nil {
			_ = stdin.Close()
			return fmt.Errorf("读取本地文件失败: %s: %v", filepath.Base(f), err)
		}
		mode := "0644"
		if syncFileKind(filepath.Base(f)) == "key" {
			mode = "0600"
		}
		name := filepath.Base(f)
		if strings.ContainsAny(name, "\n\r\x00") {
			_ = stdin.Close()
			return errors.New("文件名含非法字符")
		}
		if _, err := fmt.Fprintf(stdin, "C%s %d %s\n", mode, len(data), name); err != nil {
			_ = stdin.Close()
			return err
		}
		if err := waitAck(); err != nil {
			_ = stdin.Close()
			return err
		}
		if _, err := stdin.Write(data); err != nil {
			_ = stdin.Close()
			return err
		}
		if _, err := stdin.Write([]byte{0}); err != nil {
			_ = stdin.Close()
			return err
		}
		if err := waitAck(); err != nil {
			_ = stdin.Close()
			return err
		}
	}
	_, _ = stdin.Write([]byte{0})
	_ = stdin.Close()
	if err := session.Wait(); err != nil {
		return fmt.Errorf("scp 传输失败: %v (%s)", err, strings.TrimSpace(stderrBuf.String()))
	}
	return nil
}

// pushAllRemotes 把文件推到所有启用的远程主机，返回每台主机的结果。
func pushAllRemotes(store *Store, localDir string, files []string) []SyncEvent {
	out := []SyncEvent{}
	for _, view := range store.ListRemoteHosts() {
		if !view.Enabled {
			continue
		}
		h, err := store.GetRemoteHost(view.ID)
		if err != nil {
			continue
		}
		ev := SyncEvent{
			Time:   time.Now().Format(time.RFC3339),
			Rule:   "远程同步 · " + h.Name,
			Source: localDir,
			Target: fmt.Sprintf("%s@%s:%s", h.User, h.Host, h.RemoteDir),
			Result: "skip",
			Detail: "无文件需要推送",
		}
		paths := make([]string, 0, len(files))
		for _, f := range files {
			paths = append(paths, filepath.Join(localDir, f))
		}
		if err := pushToRemote(store, h, paths); err == nil {
			names := make([]string, 0, len(paths))
			for _, p := range paths {
				names = append(names, filepath.Base(p))
			}
			ev.Result, ev.Count, ev.Files = "ok", len(names), names
			ev.Detail = fmt.Sprintf("推送 %d 个文件到远程主机", len(names))
		} else {
			ev.Result, ev.Detail = "fail", err.Error()
		}
		out = append(out, ev)
	}
	return out
}

// testRemoteHost 测试 SSH 连接与认证是否可用。
func testRemoteHost(store *Store, h RemoteHost) error {
	client, err := dialRemote(store, h)
	if err != nil {
		return err
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("创建 SSH 会话失败: %v", err)
	}
	defer session.Close()
	if err := session.Run("true"); err != nil {
		return fmt.Errorf("SSH 会话测试失败: %v", err)
	}
	return nil
}

// logRemoteInfof 由 main 包注入日志函数，避免此处依赖 log 包。
var logRemoteInfof = func(format string, args ...any) {}
