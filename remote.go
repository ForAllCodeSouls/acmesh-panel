package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
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
			User: h.User, RemoteDir: h.RemoteDir, Domains: h.Domains,
			KeyMasked: mask(h.Key), HasKey: h.Key != "",
			PasswordMasked: mask(h.Password), HasPassword: h.Password != "",
			AuthMode: authMode, AutoPush: h.AutoPush, Enabled: h.Enabled,
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
	// 目标运行环境是 Linux（/...），同时兼容 Windows 上的盘符绝对路径（本地测试用）。
	if (!strings.HasPrefix(h.RemoteDir, "/") && !filepath.IsAbs(h.RemoteDir)) || strings.Contains(h.RemoteDir, "..") ||
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
	h.Domains = normalizeHostDomains(h.Domains)
	for _, d := range h.Domains {
		if len(d) > 253 || strings.ContainsAny(d, " /\\\t\n\r\x00'\"$;`|&*?<>") {
			return errors.New("负责域名含非法字符")
		}
	}
	return nil
}

// normalizeHostDomains 清理主机负责域名：去空白、转小写、去重、丢弃空项。
func normalizeHostDomains(in []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, d := range in {
		d = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(d), "*.")))
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out
}

// hostWantsDomain 判断某个域名是否属于该主机负责范围：未配置负责域名时不限制（兼容旧行为）。
// 按内容同步时传的是证书 CN/SAN 里的域名，而不是文件名——文件名只是存放名。
func hostWantsDomain(h RemoteHost, domain string) bool {
	if len(h.Domains) == 0 {
		return true
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return false
	}
	for _, d := range h.Domains {
		d = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(d), "*.")))
		if d == "" {
			continue
		}
		if domain == d || isSubdomainOf(domain, d) {
			return true
		}
	}
	return false
}

// hostWantsFile 供规则驱动的自动推送使用：那里本地文件已是证书本身，按文件名域名过滤。
func hostWantsFile(h RemoteHost, name string) bool {
	return hostWantsDomain(h, certFileDomain(name))
}

// filesForHost 按主机的负责域名过滤待推文件列表。
func filesForHost(h RemoteHost, files []string) []string {
	if len(h.Domains) == 0 {
		return files
	}
	out := make([]string, 0, len(files))
	for _, name := range files {
		if hostWantsFile(h, name) {
			out = append(out, name)
		}
	}
	return out
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
	var auths []ssh.AuthMethod
	if h.Password != "" {
		// 同时提供 password 与 keyboard-interactive：不少 SSH 服务（群晖、Windows OpenSSH、
		// 启用 PAM 的 OpenSSH）只开放后者，只发 ssh.Password 会被服务器拒绝。
		auths = []ssh.AuthMethod{
			ssh.Password(h.Password),
			ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range questions {
					answers[i] = h.Password
				}
				return answers, nil
			}),
		}
	} else {
		signer, err := ssh.ParsePrivateKey([]byte(h.Key))
		if err != nil {
			return nil, fmt.Errorf("SSH 私钥解析失败: %v", err)
		}
		auths = []ssh.AuthMethod{ssh.PublicKeys(signer)}
	}
	hcb, err := hostKeyCallback(store)
	if err != nil {
		return nil, err
	}
	cfg := &ssh.ClientConfig{
		User:            h.User,
		Auth:            auths,
		HostKeyCallback: hcb,
		Timeout:         10 * time.Second,
	}
	addr := net.JoinHostPort(h.Host, strconv.Itoa(h.Port))
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		var authErr *ssh.ServerAuthError
		if errors.As(err, &authErr) {
			return nil, fmt.Errorf("SSH 认证失败（%s）。请确认账号密码正确、服务器已开启密码或交互式登录；若只允许公钥认证，请改用 SSH 私钥。",
				strings.Trim(authErr.Error(), "[]"))
		}
		return nil, fmt.Errorf("SSH 连接失败: %v", err)
	}
	return client, nil
}

// resolveSyncLocalPath 把同步目录内的文件名解析为唯一的绝对路径。
// 调用方可能传相对文件名（本地同步写入结果）或已经是绝对路径（手动强制推送），
// 这里统一归一化，杜绝 filepath.Join("/certs", "/certs/x.pem") 变成 /certs/certs/x.pem。
func resolveSyncLocalPath(localDir, name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("本地文件名为空")
	}
	if !filepath.IsAbs(localDir) {
		return "", errors.New("本地同步目录必须是绝对路径")
	}
	base := filepath.Clean(localDir)
	full := name
	if !filepath.IsAbs(full) {
		full = filepath.Join(base, full)
	} else {
		full = filepath.Clean(full)
	}
	if !filepath.IsAbs(full) || strings.Contains(full, "..") {
		return "", fmt.Errorf("本地文件路径非法: %s", name)
	}
	// 绝对路径也必须落在本次同步目录内，避免误推无关文件。
	rel, err := filepath.Rel(base, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("本地文件不在同步目录 %s 内: %s", base, name)
	}
	return full, nil
}

// RemoteFileItem 是远程目录里的一个证书文件，用于页面展示（不含内容）。
type RemoteFileItem struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	IsDir   bool   `json:"is_dir"`
	ModTime string `json:"mod_time"`
}

// listRemoteFiles 通过 SFTP 列出远程目录里的文件，供页面像本地挂载目录一样查看。
func listRemoteFiles(store *Store, h RemoteHost, dir string) ([]RemoteFileItem, string, error) {
	if strings.TrimSpace(dir) == "" {
		dir = h.RemoteDir
	}
	dir = strings.TrimSpace(dir)
	if !strings.HasPrefix(dir, "/") || strings.Contains(dir, "..") {
		return nil, dir, errors.New("远程目录必须是绝对路径，且不能包含 ..")
	}
	client, err := dialRemote(store, h)
	if err != nil {
		return nil, dir, err
	}
	defer client.Close()
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return nil, dir, fmt.Errorf("启动 SFTP 失败（目标主机需开启 sftp 子系统）: %v", err)
	}
	defer sftpClient.Close()
	entries, err := sftpClient.ReadDir(dir)
	if err != nil {
		return nil, dir, fmt.Errorf("读取远程目录 %s 失败: %v", dir, err)
	}
	out := []RemoteFileItem{}
	for _, entry := range entries {
		if len(out) >= 200 {
			break
		}
		// 隐藏推送过程中可能残留的临时文件（正常流程结束后会被改名掉）
		if strings.HasSuffix(entry.Name(), ".acmesh-tmp") {
			continue
		}
		out = append(out, RemoteFileItem{
			Name:    entry.Name(),
			Size:    entry.Size(),
			IsDir:   entry.IsDir(),
			ModTime: entry.ModTime().Format(time.RFC3339),
		})
	}
	sortRemoteFiles(out)
	return out, dir, nil
}

// sortRemoteFiles 排序展示顺序：目录在前，其余按文件名升序（大小写不敏感）。
// SFTP ReadDir 返回顺序取决于服务器（通常是 inode 顺序），不排序会显得混乱。
func sortRemoteFiles(items []RemoteFileItem) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].IsDir != items[j].IsDir {
			return items[i].IsDir
		}
		return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name)
	})
}

// readRemoteCertFiles 通过 SFTP 批量读取远程目录里的证书文件内容。
// 以前跳过私钥：因为同步匹配只需要证书内容。现在目录标注也要识别私钥，
// 所以把「读哪些文件」交给参数控制，读取逻辑共用一份。
func readRemoteCertFiles(store *Store, h RemoteHost, names []string) (map[string][]byte, error) {
	candidates := []string{}
	for _, name := range names {
		lower := strings.ToLower(name)
		if !(strings.HasSuffix(lower, ".pem") || strings.HasSuffix(lower, ".cer") || strings.HasSuffix(lower, ".crt")) {
			continue
		}
		if syncFileKind(name) == "key" {
			continue // 这条路径只服务同步匹配，私钥按文件名配对，不读内容
		}
		candidates = append(candidates, name)
	}
	return readRemoteNamedFiles(store, h, candidates)
}

// readRemoteAllPEMFiles 读取目录里所有 PEM/证书文件（含私钥），用于类型标注——
// 私钥文件本身也需要读内容才能确认它确实是 PEM 私钥，而不是靠文件名猜。
func readRemoteAllPEMFiles(store *Store, h RemoteHost, names []string) (map[string][]byte, error) {
	candidates := []string{}
	for _, name := range names {
		lower := strings.ToLower(name)
		if strings.HasSuffix(lower, ".pem") || strings.HasSuffix(lower, ".cer") ||
			strings.HasSuffix(lower, ".crt") || strings.HasSuffix(lower, ".key") {
			candidates = append(candidates, name)
		}
	}
	return readRemoteNamedFiles(store, h, candidates)
}

// readRemoteNamedFiles 连接 SFTP 批量读取指定文件内容（单文件上限 1MB）。
// 连接失败返回空 map 与错误；单个文件读不到不影响其它文件。
func readRemoteNamedFiles(store *Store, h RemoteHost, candidates []string) (map[string][]byte, error) {
	out := map[string][]byte{}
	if len(candidates) == 0 {
		return out, nil
	}
	client, err := dialRemote(store, h)
	if err != nil {
		return out, err
	}
	defer client.Close()
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return out, err
	}
	defer sftpClient.Close()
	for _, name := range candidates {
		if strings.ContainsAny(name, "\n\r\x00") {
			continue
		}
		f, err := sftpClient.Open(path.Join(h.RemoteDir, name))
		if err != nil {
			continue // 单个文件读不到不影响其它文件
		}
		b, err := io.ReadAll(io.LimitReader(f, 1<<20))
		_ = f.Close()
		if err == nil && len(b) > 0 {
			out[name] = b
		}
	}
	return out, nil
}

// pairedKeyName 由目标证书文件名推导配套私钥文件名：
// app.example.com_cert.pem / _fullchain.pem / app.example.com.pem -> app.example.com_key.pem。
func pairedKeyName(name string) string {
	for _, suffix := range []string{
		"_fullchain.pem", "-fullchain.pem", "_cert.pem", "-cert.pem",
		"_chain.pem", "-chain.pem", ".pem", ".cer", ".crt",
	} {
		if len(name) > len(suffix) && strings.EqualFold(name[len(name)-len(suffix):], suffix) {
			return name[:len(name)-len(suffix)] + "_key.pem"
		}
	}
	return ""
}

// pushMatchedToRemote 把面板已签名证书的最新内容写到目标主机上的指定文件（按文件名一一对应）。
// 与 pushToRemote 的区别：这里的目标文件名来自「目标机器现有证书」的匹配结果，
// 内容来自面板已签名证书（ci.Name），所以写进去的是 dockge.xxx_cert.pem 对应的最新证书，
// 而不是把本地 /certs 里规则命中的同名文件整批推过去。
func pushMatchedToRemote(store *Store, certs *CertScanner, h RemoteHost, matches map[string]RemoteCertMatch, force bool, remoteNames ...string) ([]SyncEvent, int) {
	out := []SyncEvent{}
	if !h.Enabled || len(matches) == 0 {
		return out, 0
	}
	// 证书命中后必须连私钥一起同步：目标机器已有配套私钥就沿用它的文件名，
	// 没有则按 <域名>_key.pem 新建。之前只写命中的证书文件，用户看到「密钥没同步」。
	full := map[string]RemoteCertMatch{}
	for name, m := range matches {
		full[name] = m
	}
	for name, m := range matches {
		if m.Kind == "key" {
			continue
		}
		keyName := pairedKeyName(name)
		if keyName == "" {
			continue
		}
		// 已有任意命名的配套私钥（_key.pem / .key.pem / -key.pem）就不重复创建。
		hasKey := false
		for n, km := range matches {
			if km.Kind == "key" && strings.EqualFold(certFileDomain(n), certFileDomain(keyName)) {
				hasKey = true
				break
			}
		}
		if !hasKey {
			for _, n := range remoteNames {
				if strings.EqualFold(certFileDomain(n), certFileDomain(keyName)) && syncFileKind(n) == "key" {
					hasKey = true
					break
				}
			}
		}
		if !hasKey {
			full[keyName] = RemoteCertMatch{Source: m.Source, Domain: m.Domain, Kind: "key"}
		}
	}
	matches = full
	all, err := certs.Scan()
	if err != nil {
		return out, 0
	}
	byName := map[string]CertInfo{}
	for _, ci := range all {
		byName[ci.Name] = ci
	}
	client, err := dialRemote(store, h)
	if err != nil {
		return []SyncEvent{{
			Time: time.Now().Format(time.RFC3339), Scope: "remote",
			Rule: "按证书内容同步 · " + h.Name, Result: "fail", Detail: err.Error(),
		}}, 0
	}
	defer client.Close()
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return []SyncEvent{{
			Time: time.Now().Format(time.RFC3339), Scope: "remote",
			Rule: "按证书内容同步 · " + h.Name, Result: "fail", Detail: "启动 SFTP 失败: " + err.Error(),
		}}, 0
	}
	defer sftpClient.Close()

	seen := store.RemoteSeens()
	updates := map[string]string{}
	skipped := 0
	fail := func(name, source, detail string) {
		out = append(out, SyncEvent{
			Time: time.Now().Format(time.RFC3339), Scope: "remote",
			Rule: "按证书内容同步 · " + h.Name, Source: source, Target: name,
			Result: "fail", Detail: detail,
		})
	}
	for name, m := range matches {
		ci, ok := byName[m.Source]
		if !ok || ci.Status == "invalid" || ci.Status == "expired" {
			fail(name, m.Source, "面板证书不存在或已失效，无法读取内容")
			continue
		}
		var content []byte
		var mode os.FileMode = 0o644
		if m.Kind == "key" {
			s, err := certs.ReadKey(ci.Name)
			if err != nil {
				fail(name, m.Source, "面板私钥读取失败: "+err.Error())
				continue
			}
			content, mode = []byte(s), 0o600
		} else {
			s, err := certs.ReadPEM(ci.Name, "fullchain")
			if err != nil {
				fail(name, m.Source, "面板证书读取失败: "+err.Error())
				continue
			}
			content = []byte(s)
		}
		sum := sha256.Sum256(content)
		digest := hex.EncodeToString(sum[:])
		key := remoteSeenKey(h.ID, h.RemoteDir, name)
		if !force && seen[key] == digest {
			skipped++
			continue
		}
		remotePath := path.Join(h.RemoteDir, name)
		tmpPath := remotePath + ".acmesh-tmp"
		rf, err := sftpClient.Create(tmpPath)
		if err != nil {
			fail(name, m.Source, "远程临时文件创建失败: "+err.Error())
			continue
		}
		_, werr := rf.Write(content)
		cerr := rf.Chmod(mode)
		clerr := rf.Close()
		if werr != nil || cerr != nil || clerr != nil {
			_ = sftpClient.Remove(tmpPath)
			fail(name, m.Source, "远程文件写入失败")
			continue
		}
		if err := sftpClient.PosixRename(tmpPath, remotePath); err != nil {
			_ = sftpClient.Remove(remotePath)
			if err2 := sftpClient.Rename(tmpPath, remotePath); err2 != nil {
				_ = sftpClient.Remove(tmpPath)
				fail(name, m.Source, "远程文件替换失败: "+err2.Error())
				continue
			}
		}
		updates[key] = digest
		out = append(out, SyncEvent{
			Time: time.Now().Format(time.RFC3339), Scope: "remote",
			Rule: "按证书内容同步 · " + h.Name, Source: m.Source,
			Target: fmt.Sprintf("%s@%s:%s/%s", h.User, h.Host, h.RemoteDir, name),
			Result: "ok", Count: 1, Files: []string{name},
			Detail: fmt.Sprintf("%s ← %s（%s）", name, m.Source, m.Domain),
		})
	}
	_ = store.MarkRemoteSeen(updates)
	return out, skipped
}

// pushToRemote 通过 SFTP 推送文件。相比 scp -t 协议，SFTP 是标准子系统，
// 对 OpenSSH 9+ / 群晖 / Windows OpenSSH 兼容性更好，且能可靠创建目录与设置权限。
func pushToRemote(store *Store, h RemoteHost, localFiles []string, localDir ...string) error {
	if !h.Enabled || len(localFiles) == 0 {
		return nil
	}
	// 兼容既有调用：未显式传目录时，以第一个文件的父目录为基准。
	base := ""
	if len(localDir) > 0 {
		base = localDir[0]
	} else {
		base = filepath.Dir(localFiles[0])
	}
	client, err := dialRemote(store, h)
	if err != nil {
		return err
	}
	defer client.Close()

	clientSFTP, err := sftp.NewClient(client)
	if err != nil {
		return fmt.Errorf("启动 SFTP 失败（目标主机需开启 sftp 子系统）: %v", err)
	}
	defer clientSFTP.Close()

	if err := clientSFTP.MkdirAll(h.RemoteDir); err != nil {
		return fmt.Errorf("创建远程目录 %s 失败: %v", h.RemoteDir, err)
	}

	for _, raw := range localFiles {
		f, err := resolveSyncLocalPath(base, raw)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(f)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("读取本地文件失败: %s（路径 %s 不存在）。请检查面板容器内 ACME_PANEL_SYNC_DIR 的挂载路径，不要填写宿主机路径", filepath.Base(f), f)
			}
			return fmt.Errorf("读取本地文件失败: %s（路径 %s）: %v", filepath.Base(f), f, err)
		}
		name := filepath.Base(f)
		if strings.ContainsAny(name, "\n\r\x00") {
			return errors.New("文件名含非法字符")
		}
		mode := os.FileMode(0o644)
		if syncFileKind(name) == "key" {
			mode = 0o600
		}
		remotePath := path.Join(h.RemoteDir, name)
		// 先写临时文件再原子改名：避免远端消费者（如 nginx）读到上传到一半的半写文件。
		// 与本地同步的 writeAtomic 保持同一原子替换标准。
		tmpPath := remotePath + ".acmesh-tmp"
		rf, err := clientSFTP.Create(tmpPath)
		if err != nil {
			return fmt.Errorf("写入远程文件 %s 失败: %v", name, err)
		}
		if _, err := rf.Write(data); err != nil {
			_ = rf.Close()
			_ = clientSFTP.Remove(tmpPath)
			return fmt.Errorf("写入远程文件 %s 失败: %v", name, err)
		}
		if err := rf.Chmod(mode); err != nil {
			_ = rf.Close()
			_ = clientSFTP.Remove(tmpPath)
			return fmt.Errorf("设置远程文件权限失败: %v", err)
		}
		if err := rf.Close(); err != nil {
			_ = clientSFTP.Remove(tmpPath)
			return fmt.Errorf("关闭远程文件失败: %v", err)
		}
		// 原子替换：优先 posix-rename 扩展（OpenSSH 支持，可覆盖已存在文件）；
		// 不支持该扩展的服务器退化为先删旧文件再改名，绝不留下半写文件。
		if err := clientSFTP.PosixRename(tmpPath, remotePath); err != nil {
			_ = clientSFTP.Remove(remotePath)
			if err2 := clientSFTP.Rename(tmpPath, remotePath); err2 != nil {
				_ = clientSFTP.Remove(tmpPath)
				return fmt.Errorf("替换远程文件 %s 失败: %v", name, err2)
			}
		}
	}
	return nil
}

// remoteSeenKey 是每台主机、每个本地目录、每个文件的推送摘要键。
// 只存内容摘要，不存证书或私钥明文。
func remoteSeenKey(hostID, dir, name string) string {
	return hostID + "|" + dir + "|" + name
}

// remoteFileDigest 计算本地证书文件的 SHA-256 摘要，用于远程普通同步去重。
func remoteFileDigest(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// pushRemoteFiles 按主机推送各自的文件清单；清单为空的主机不产生记录。
// 每条记录都对应一次真实的远端推送尝试，避免出现"跳过也刷屏"的假结果。
func pushRemoteFiles(store *Store, localDir string, byHost map[string][]string) []SyncEvent {
	out := []SyncEvent{}
	for _, view := range store.ListRemoteHosts() {
		if !view.Enabled {
			continue
		}
		files, ok := byHost[view.ID]
		if !ok || len(files) == 0 {
			continue
		}
		paths := make([]string, 0, len(files))
		var pathErr error
		for _, f := range files {
			resolved, err := resolveSyncLocalPath(localDir, f)
			if err != nil {
				pathErr = err
				break
			}
			paths = append(paths, resolved)
		}
		h, err := store.GetRemoteHost(view.ID)
		if err != nil {
			continue
		}
		ev := SyncEvent{
			Time:   time.Now().Format(time.RFC3339),
			HostID: view.ID,
			Scope:  "remote",
			Rule:   "远程同步 · " + h.Name,
			Source: localDir,
			Target: fmt.Sprintf("%s@%s:%s", h.User, h.Host, h.RemoteDir),
			Result: "fail",
		}
		if pathErr != nil {
			ev.Detail = pathErr.Error()
			out = append(out, ev)
			continue
		}
		if err := pushToRemote(store, h, paths, localDir); err == nil {
			names := make([]string, 0, len(paths))
			for _, p := range paths {
				names = append(names, filepath.Base(p))
			}
			ev.Result, ev.Count, ev.Files = "ok", len(names), names
			ev.Detail = fmt.Sprintf("同步 %d 个文件到远程主机", len(names))
		} else {
			ev.Detail = err.Error()
		}
		out = append(out, ev)
	}
	return out
}

// pushAllRemotes 把文件推到启用的远程主机，返回每台主机的推送结果（scope=remote）。
// onlyHostID 非空时只推指定主机；force 表示忽略「自动推送」开关（本地同步的手动强制路径）。
func pushAllRemotes(store *Store, localDir string, files []string, force bool, onlyHostID ...string) []SyncEvent {
	byHost := map[string][]string{}
	for _, view := range store.ListRemoteHosts() {
		if !view.Enabled {
			continue
		}
		// onlyHostID 传多个时表示规则选中的全部主机（任一匹配即推送）。
		if len(onlyHostID) > 0 {
			found := false
			for _, id := range onlyHostID {
				if view.ID == id {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		// 本地同步触发时只推开启了「自动推送」的主机；手动强制推送忽略此开关
		if !force && !view.AutoPush {
			continue
		}
		h, err := store.GetRemoteHost(view.ID)
		if err != nil {
			continue
		}
		// 主机配置了负责域名时，只推属于该主机的文件，避免把 A 域名的证书推到 B 主机。
		byHost[view.ID] = filesForHost(h, files)
	}
	return pushRemoteFiles(store, localDir, byHost)
}

// selectRemoteFiles 按主机挑选本次真正要推的文件。
// 普通同步跳过内容摘要与上次成功推送一致的文件；摘要算不出来时仍推，暴露真实错误。
func selectRemoteFiles(hostID, localDir string, files []string, force bool, seen, digests map[string]string) []string {
	selected := []string{}
	if force {
		return append(selected, files...)
	}
	for _, name := range files {
		digest, ok := digests[name]
		if !ok {
			p, err := resolveSyncLocalPath(localDir, name)
			if err == nil {
				digest, err = remoteFileDigest(p)
			}
			if err == nil {
				digests[name] = digest
				ok = true
			}
		}
		if ok && seen[remoteSeenKey(hostID, localDir, name)] == digest {
			continue
		}
		selected = append(selected, name)
	}
	return selected
}

// pushAllRemotesOnce 处理页面上的手动远程同步。
// 普通同步只推内容变化过的文件（按主机独立记录摘要）；勾选强制同步后忽略摘要全部重推。
// 返回推送记录与因内容未变化而被跳过的文件数。
func pushAllRemotesOnce(store *Store, localDir string, files []string, force bool, onlyHostID ...string) ([]SyncEvent, int) {
	hostID := ""
	if len(onlyHostID) > 0 {
		hostID = onlyHostID[0]
	}
	seen := store.RemoteSeens()
	digests := map[string]string{}
	byHost := map[string][]string{}
	selectedCount := 0
	for _, view := range store.ListRemoteHosts() {
		if !view.Enabled || (hostID != "" && view.ID != hostID) {
			continue
		}
		h, err := store.GetRemoteHost(view.ID)
		if err != nil {
			continue
		}
		selected := selectRemoteFiles(view.ID, localDir, filesForHost(h, files), force, seen, digests)
		byHost[view.ID] = selected
		selectedCount += len(selected)
	}

	events := pushRemoteFiles(store, localDir, byHost)
	updates := map[string]string{}
	for _, ev := range events {
		if ev.Result != "ok" || ev.HostID == "" {
			continue
		}
		for _, name := range ev.Files {
			digest, ok := digests[name]
			if !ok {
				p, err := resolveSyncLocalPath(localDir, name)
				if err == nil {
					digest, err = remoteFileDigest(p)
				}
				if err != nil {
					continue
				}
				digests[name] = digest
			}
			if digest != "" {
				updates[remoteSeenKey(ev.HostID, localDir, name)] = digest
			}
		}
	}
	_ = store.MarkRemoteSeen(updates)
	return events, len(files)*len(byHost) - selectedCount
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
