package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
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
		out = append(out, RemoteHostView{
			ID: h.ID, Name: h.Name, Host: h.Host, Port: h.Port,
			User: h.User, RemoteDir: h.RemoteDir,
			KeyMasked: mask(h.Key), HasKey: h.Key != "", Enabled: h.Enabled,
		})
	}
	return out
}

// ---------------- SSH 推送 ----------------

// validateRemoteHost 校验远程配置，防止 argv 注入与路径穿越。
func validateRemoteHost(h RemoteHost) error {
	name := strings.TrimSpace(h.Name)
	if name == "" || len(name) > 64 || strings.ContainsAny(name, "\t\n\r\x00<>&\"'") {
		return errors.New("名称不能为空且不能含换行或尖括号等特殊字符")
	}
	if strings.ContainsAny(h.Host, " /\\\t\n\r\x00'\"$;`|&*?<>") {
		return errors.New("主机名含非法字符")
	}
	if strings.ContainsAny(h.User, " /\\\t\n\r\x00'\"$;`|&*?<>") {
		return errors.New("用户名含非法字符")
	}
	if !strings.HasPrefix(h.RemoteDir, "/") || strings.Contains(h.RemoteDir, "..") || strings.ContainsAny(h.RemoteDir, "\t\n\r\x00'\"$;`|&*?<>") {
		return errors.New("远程目录必须是绝对路径且不含非法字符")
	}
	if h.Port < 1 || h.Port > 65535 {
		return errors.New("端口非法")
	}
	return nil
}

// pushToRemote 用 scp 把本地文件推到远程主机（argv-only，无 shell）。
// 私钥写到 0600 临时文件，用完即删。
func pushToRemote(h RemoteHost, localFiles []string) error {
	if !h.Enabled || len(localFiles) == 0 {
		return nil
	}
	if err := validateRemoteHost(h); err != nil {
		return err
	}
	if h.Key == "" {
		return errors.New("未配置 SSH 私钥")
	}
	// 校验本地文件是绝对路径且真实存在
	for _, f := range localFiles {
		if !filepath.IsAbs(f) || strings.Contains(f, "..") {
			return errors.New("本地文件路径非法")
		}
		if st, err := os.Stat(f); err != nil || st.IsDir() {
			return fmt.Errorf("本地文件不存在: %s", f)
		}
	}

	tmp, err := os.CreateTemp("/tmp", "acmesh-key-*")
	if err != nil {
		return err
	}
	keyPath := tmp.Name()
	defer os.Remove(keyPath)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(strings.TrimRight(h.Key, "\r\n") + "\n"); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()

	args := []string{
		"-i", keyPath,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=10",
		"-P", strconv.Itoa(h.Port),
	}
	args = append(args, localFiles...)
	target := fmt.Sprintf("%s@%s:%s", h.User, h.Host, h.RemoteDir)
	args = append(args, target)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "scp", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("scp 失败: %v (%s)", err, strings.TrimSpace(string(out)))
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
		// 拼出本地完整路径
		paths := make([]string, 0, len(files))
		for _, f := range files {
			paths = append(paths, filepath.Join(localDir, f))
		}
		if err := pushToRemote(h, paths); err == nil {
			fullPaths := []string{}
			for _, p := range paths {
				fullPaths = append(fullPaths, filepath.Base(p))
			}
			ev.Result, ev.Count, ev.Files = "ok", len(fullPaths), fullPaths
			ev.Detail = fmt.Sprintf("推送 %d 个文件到远程主机", len(fullPaths))
		} else {
			ev.Result, ev.Detail = "fail", err.Error()
		}
		out = append(out, ev)
	}
	return out
}

// writeKeyTemp 把 SSH 私钥写入 0600 临时文件，返回路径与清理函数。
func writeKeyTemp(key string) (string, func(), error) {
	tmp, err := os.CreateTemp("/tmp", "acmesh-key-*")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.Remove(tmp.Name()) }
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		cleanup()
		return "", nil, err
	}
	if _, err := tmp.WriteString(strings.TrimRight(key, "\r\n") + "\n"); err != nil {
		tmp.Close()
		cleanup()
		return "", nil, err
	}
	tmp.Close()
	return tmp.Name(), cleanup, nil
}

// testRemoteHost 测试 SSH 连接是否可用。
func testRemoteHost(h RemoteHost) error {
	if err := validateRemoteHost(h); err != nil {
		return err
	}
	if h.Key == "" {
		return errors.New("未配置 SSH 私钥")
	}
	if _, err := exec.LookPath("ssh"); err != nil {
		return errors.New("容器内缺少 ssh 客户端，请升级到包含 openssh-client 的镜像")
	}
	keyPath, cleanup, err := writeKeyTemp(h.Key)
	if err != nil {
		return err
	}
	defer cleanup()
	args := []string{
		"-i", keyPath,
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=10",
		"-p", strconv.Itoa(h.Port),
		fmt.Sprintf("%s@%s", h.User, h.Host),
		"true",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ssh", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("SSH 连接失败: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}
