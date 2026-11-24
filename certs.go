package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type CertInfo struct {
	Name      string            `json:"name"`
	Domain    string            `json:"domain"`
	IsECC     bool              `json:"is_ecc"`
	Status    string            `json:"status"`
	Subject   string            `json:"subject"`
	SANs      []string          `json:"sans"`
	Issuer    string            `json:"issuer"`
	NotBefore time.Time         `json:"not_before"`
	NotAfter  time.Time         `json:"not_after"`
	DaysLeft  int               `json:"days_left"`
	Serial    string            `json:"serial"`
	KeyType   string            `json:"key_type"`
	KeyBits   int               `json:"key_bits"`
	HasKey    bool              `json:"has_key"`
	CA        string            `json:"ca"`
	KeyLength string            `json:"key_length"`
	HasFiles  map[string]string `json:"files"`
	Wildcard  bool              `json:"wildcard"`
	Email     string            `json:"email"` // 该域名自定义的 ACME 邮箱；空表示使用全局默认
}

func (c *CertScanner) Home() string { return c.home }

type CertScanner struct {
	home string
}

func NewCertScanner(home string) *CertScanner { return &CertScanner{home: home} }

func (s *CertScanner) safeJoin(parts ...string) (string, error) {
	p := filepath.Join(append([]string{s.home}, parts...)...)
	clean := filepath.Clean(p)
	root := filepath.Clean(s.home)
	if clean != root && !strings.HasPrefix(clean, root+string(os.PathSeparator)) {
		return "", errors.New("路径越界")
	}
	return clean, nil
}

// Scan 枚举 acme.sh home 下的所有证书目录并解析。
func (s *CertScanner) Scan() ([]CertInfo, error) {
	entries, err := os.ReadDir(s.home)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []CertInfo{}, nil
		}
		return nil, err
	}
	out := []CertInfo{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, ".") || name == "ca" || name == "deploy" || name == "http.header" {
			continue
		}
		domain := strings.TrimSuffix(name, "_ecc")
		isECC := strings.HasSuffix(name, "_ecc")
		if !validCertName(domain) {
			continue
		}
		if ci, ok := s.parse(name, domain, isECC); ok {
			out = append(out, ci)
		}
	}
	return out, nil
}

func (s *CertScanner) Get(name string) (*CertInfo, error) {
	if !validCertName(name) {
		return nil, errors.New("非法证书名")
	}
	domain := strings.TrimSuffix(name, "_ecc")
	isECC := strings.HasSuffix(name, "_ecc")
	ci, ok := s.parse(name, domain, isECC)
	if !ok {
		return nil, errors.New("证书不存在或无法解析")
	}
	return &ci, nil
}

func (s *CertScanner) parse(dirName, domain string, isECC bool) (CertInfo, bool) {
	dir, err := s.safeJoin(dirName)
	if err != nil {
		return CertInfo{}, false
	}
	ci := CertInfo{
		Name:     dirName,
		Domain:   domain,
		IsECC:    isECC,
		SANs:     []string{},
		HasFiles: map[string]string{},
		Status:   "invalid",
	}
	conf := parseAcmeConf(filepath.Join(dir, domain+".conf"))
	ci.CA = conf["Le_API"]
	ci.KeyLength = conf["Le_Keylength"]

	certPath := filepath.Join(dir, domain+".cer")
	if _, err := os.Stat(certPath); err != nil {
		certPath = filepath.Join(dir, "fullchain.cer")
	}
	pemBytes, err := os.ReadFile(certPath)
	if err == nil {
		if block, _ := pem.Decode(pemBytes); block != nil {
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				ci.Subject = cert.Subject.CommonName
				ci.SANs = append(ci.SANs, cert.DNSNames...)
				if len(ci.SANs) == 0 && cert.Subject.CommonName != "" {
					ci.SANs = append(ci.SANs, cert.Subject.CommonName)
				}
				ci.Issuer = issuerCN(cert)
				ci.NotBefore = cert.NotBefore
				ci.NotAfter = cert.NotAfter
				ci.Serial = cert.SerialNumber.Text(16)
				ci.Wildcard = strings.Contains(strings.Join(ci.SANs, ","), "*.")
				switch pub := cert.PublicKey.(type) {
				case *rsa.PublicKey:
					ci.KeyType = "RSA"
					ci.KeyBits = pub.N.BitLen()
				case *ecdsa.PublicKey:
					ci.KeyType = "ECDSA"
					ci.KeyBits = pub.Curve.Params().BitSize
				default:
					ci.KeyType = "未知"
				}
				ci.DaysLeft = int(time.Until(cert.NotAfter).Hours() / 24)
				switch {
				case time.Now().After(cert.NotAfter):
					ci.Status = "expired"
				case ci.DaysLeft <= 7:
					ci.Status = "critical"
				case ci.DaysLeft <= 30:
					ci.Status = "warning"
				default:
					ci.Status = "valid"
				}
			}
		}
	}
	keyPath := filepath.Join(dir, domain+".key")
	if _, err := os.Stat(keyPath); err == nil {
		ci.HasKey = true
	}

	for label, f := range map[string]string{
		"cert":      domain + ".cer",
		"fullchain": "fullchain.cer",
		"chain":     "ca.cer",
		"key":       domain + ".key",
		"csr":       domain + ".csr",
	} {
		if fi, err := os.Stat(filepath.Join(dir, f)); err == nil && fi.Size() > 0 {
			ci.HasFiles[label] = f
		}
	}
	return ci, ci.Status != "invalid"
}

func issuerCN(c *x509.Certificate) string {
	if c.Issuer.CommonName != "" {
		return c.Issuer.CommonName
	}
	if len(c.Issuer.Organization) > 0 {
		return c.Issuer.Organization[0]
	}
	return "未知"
}

// parseAcmeConf 解析 acme.sh 的 KEY='VALUE' 配置文件。
func parseAcmeConf(path string) map[string]string {
	out := map[string]string{}
	b, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		line = strings.TrimPrefix(line, "export ")
		i := strings.IndexByte(line, '=')
		if i <= 0 {
			continue
		}
		k := strings.TrimSpace(line[:i])
		v := strings.TrimSpace(line[i+1:])
		if len(v) >= 2 {
			if (v[0] == '\'' && v[len(v)-1] == '\'') || (v[0] == '"' && v[len(v)-1] == '"') {
				v = v[1 : len(v)-1]
			}
		}
		out[k] = v
	}
	return out
}

// ReadPEM 读取证书相关文件内容（不含私钥）。只允许白名单文件名。
func (s *CertScanner) ReadPEM(name, kind string) (string, error) {
	ci, err := s.Get(name)
	if err != nil {
		return "", err
	}
	fname, ok := ci.HasFiles[kind]
	if !ok || kind == "key" {
		return "", errors.New("文件不存在")
	}
	dir, err := s.safeJoin(ci.Name)
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(filepath.Join(dir, fname))
	if err != nil {
		return "", errors.New("文件不存在")
	}
	if len(b) > 1<<20 {
		return "", errors.New("文件过大")
	}
	return string(b), nil
}

// ReadKey 读取私钥 PEM。调用方必须已完成二次确认并写审计。
func (s *CertScanner) ReadKey(name string) (string, error) {
	ci, err := s.Get(name)
	if err != nil {
		return "", err
	}
	if !ci.HasKey {
		return "", errors.New("该证书没有私钥文件")
	}
	dir, err := s.safeJoin(ci.Name)
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(filepath.Join(dir, ci.Domain+".key"))
	if err != nil {
		return "", errors.New("私钥读取失败")
	}
	if len(b) > 1<<20 {
		return "", errors.New("文件过大")
	}
	return string(b), nil
}

// Purge 删除证书目录（仅当目录确实位于 acme.sh home 下且名字合法时）。
func (s *CertScanner) Purge(name string) error {
	if !validCertName(name) {
		return errors.New("非法证书名")
	}
	dir, err := s.safeJoin(name)
	if err != nil {
		return err
	}
	if dir == filepath.Clean(s.home) {
		return errors.New("拒绝删除根目录")
	}
	return os.RemoveAll(dir)
}

func parseInt(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
