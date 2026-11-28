package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// 导入已有证书：PEM 只在本次请求中经过内存，私钥以 0600 写入 acme.sh 证书目录，
// 不进备份导出内容以外的任何日志、审计或任务预览。目录名与路径均做越界校验。

type certImportReq struct {
	CertPEM  string `json:"cert_pem"`
	KeyPEM   string `json:"key_pem"`
	ChainPEM string `json:"chain_pem"`
	Name     string `json:"name"`
	CA       string `json:"ca"`
	Force    bool   `json:"force"`
}

func firstCertPEM(text string) ([]byte, error) {
	b := []byte(text)
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("证书 PEM 格式错误")
	}
	return b, nil
}

func keyLengthLabel(cert *x509.Certificate) string {
	switch k := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		bits := k.N.BitLen()
		if bits >= 3840 {
			return "4096"
		}
		if bits >= 3072 {
			return "3072"
		}
		return "2048"
	case *ecdsa.PublicKey:
		if k.Curve.Params().BitSize >= 384 {
			return "ec-384"
		}
		return "ec-256"
	default:
		return ""
	}
}

// safeImportDir 在词法校验之外再做一次符号链接越界检查。
// 私钥写入是高危操作，不能让 ACME_HOME 内的符号链接把文件带到宿主机其它路径。
func safeImportDir(home, name string) (string, error) {
	dir, err := filepath.Abs(filepath.Join(home, name))
	if err != nil {
		return "", err
	}
	root, err := filepath.Abs(home)
	if err != nil {
		return "", err
	}
	if resolvedRoot, e := filepath.EvalSymlinks(root); e == nil {
		root = resolvedRoot
	}
	target := dir
	if resolved, e := filepath.EvalSymlinks(dir); e == nil {
		target = resolved
	} else if resolvedParent, e := filepath.EvalSymlinks(filepath.Dir(dir)); e == nil {
		target = filepath.Join(resolvedParent, filepath.Base(dir))
	}
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
		return "", errors.New("证书目录越出 ACME_HOME")
	}
	return dir, nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".import.tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	if err := os.Chmod(tmp, perm); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func (s *Server) handleCertImport(w http.ResponseWriter, r *http.Request) {
	var req certImportReq
	if err := readJSONLimit(w, r, &req, 4<<20); err != nil {
		writeErr(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	certPEM, err := firstCertPEM(req.CertPEM)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.KeyPEM) == "" {
		writeErr(w, http.StatusBadRequest, "缺少私钥 PEM")
		return
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "证书解析失败: "+err.Error())
		return
	}
	leaf := certPEM
	if strings.TrimSpace(req.ChainPEM) != "" {
		if _, err := firstCertPEM(req.ChainPEM); err != nil {
			writeErr(w, http.StatusBadRequest, "证书链 PEM 格式错误")
			return
		}
		leaf = append(append([]byte(nil), certPEM...), '\n')
		leaf = append(leaf, []byte(req.ChainPEM)...)
	}
	if _, err := tls.X509KeyPair(leaf, []byte(req.KeyPEM)); err != nil {
		writeErr(w, http.StatusBadRequest, "私钥与证书不匹配或私钥格式错误: "+err.Error())
		return
	}

	primary := ""
	for _, d := range cert.DNSNames {
		if validDomain(d) {
			primary = strings.ToLower(d)
			break
		}
	}
	if primary == "" && validDomain(cert.Subject.CommonName) {
		primary = strings.ToLower(cert.Subject.CommonName)
	}
	if primary == "" {
		writeErr(w, http.StatusBadRequest, "证书缺少可识别的 DNS 域名，请确认这是域名证书")
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = primary
	}
	if !validCertName(name) {
		writeErr(w, http.StatusBadRequest, "证书目录名含非法字符")
		return
	}
	dir, err := safeImportDir(s.cfg.AcmeHome, name)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := os.Lstat(dir); err == nil && !req.Force {
		writeErr(w, http.StatusConflict, "同名证书已存在；如需覆盖请勾选强制导入")
		return
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		writeErr(w, http.StatusInternalServerError, "检查证书目录失败")
		return
	}
	ca := req.CA
	if ca == "" {
		ca = s.effectiveCA()
	}
	if ca == "" {
		ca = "letsencrypt"
	}
	if _, ok := allowedCA[ca]; !ok {
		writeErr(w, http.StatusBadRequest, "不支持的 CA")
		return
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		writeErr(w, http.StatusInternalServerError, "创建证书目录失败: "+err.Error())
		return
	}
	_ = os.Chmod(dir, 0o700)

	base := filepath.Join(dir, name)
	fullchain := leaf
	if strings.TrimSpace(req.ChainPEM) == "" {
		fullchain = certPEM
	}
	files := []struct {
		path string
		data []byte
		perm os.FileMode
	}{
		{base + ".cer", certPEM, 0o644},
		{filepath.Join(dir, "fullchain.cer"), fullchain, 0o644},
		{base + ".key", []byte(strings.TrimSpace(req.KeyPEM) + "\n"), 0o600},
	}
	if strings.TrimSpace(req.ChainPEM) != "" {
		files = append(files, struct {
			path string
			data []byte
			perm os.FileMode
		}{filepath.Join(dir, "ca.cer"), []byte(strings.TrimSpace(req.ChainPEM) + "\n"), 0o644})
	}
	conf := fmt.Sprintf("export Le_Domain='%s'\nexport Le_API='%s'\nexport Le_Keylength='%s'\n",
		strings.ReplaceAll(name, "'", ""), ca, keyLengthLabel(cert))
	files = append(files, struct {
		path string
		data []byte
		perm os.FileMode
	}{base + ".conf", []byte(conf), 0o644})
	for _, f := range files {
		if err := writeFileAtomic(f.path, f.data, f.perm); err != nil {
			writeErr(w, http.StatusInternalServerError, "写入证书文件失败: "+err.Error())
			return
		}
	}

	s.store.Audit(sess(r).User, clientIP(r, s.cfg.TrustProxy), "cert_import",
		fmt.Sprintf("%s (%s, %s)", name, cert.Subject.CommonName, ca))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "name": name, "domain": primary, "expires": cert.NotAfter,
		"note": "导入证书不会被 acme.sh 自动续期；到期后请改用面板签发或续期。",
	})
}
