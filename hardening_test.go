package main

import (
	"strings"
	"testing"
)

func TestRedactArgsMasksKeyValue(t *testing.T) {
	out := redactArgs([]string{
		"--issue", "-d", "example.com",
		"DuckDNS_Token=supersecrettoken", // 凭证走 env 时的历史形式
		"--dnssleep", "30",
		"normal-arg",
	})
	if strings.Contains(out, "supersecrettoken") {
		t.Fatalf("凭证值不应出现在任务预览: %s", out)
	}
	if !strings.Contains(out, "DuckDNS_Token=••••") {
		t.Fatalf("KEY=value 应打码为键名+掩码: %s", out)
	}
	if !strings.Contains(out, "example.com") || !strings.Contains(out, "--dnssleep") {
		t.Fatalf("普通参数应原样保留: %s", out)
	}
}

func TestRandPasswordUsesFullAlphabet(t *testing.T) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
	seen := map[byte]bool{}
	// 采样足够多次，每个字符都应出现（旧实现有 5 个字符永不出现）。
	for i := 0; i < 400; i++ {
		for _, c := range []byte(randPassword(16)) {
			if !strings.ContainsRune(alphabet, rune(c)) {
				t.Fatalf("生成了字符集外的字符 %q", c)
			}
			seen[c] = true
		}
	}
	if len(seen) != len(alphabet) {
		missing := []byte{}
		for i := 0; i < len(alphabet); i++ {
			if !seen[alphabet[i]] {
				missing = append(missing, alphabet[i])
			}
		}
		t.Fatalf("有字符从未出现: %q", missing)
	}
}

func TestSetPasswordStrongPolicy(t *testing.T) {
	st, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.db.Close()
	for _, weak := range []string{"short", "Passw0rd123", "ALLUPPERCASE123", "alllowercase123"} {
		if err := st.SetPassword(weak); err == nil {
			t.Errorf("弱密码 %q 应被拒绝", weak)
		}
	}
	if err := st.SetPassword("Str0ngPassw0rd"); err != nil {
		t.Fatalf("合规密码应被接受: %v", err)
	}
}
