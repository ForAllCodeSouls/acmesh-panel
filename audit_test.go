package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestAuditWhereParameterized(t *testing.T) {
	where, args := auditWhere(AuditFilter{
		Query:  "admin",
		Action: "login_ok",
		User:   "admin",
		IP:     "1.2.3.4",
		From:   "2026-11-01",
		To:     "2026-11-25",
	})
	if !strings.Contains(where, "LIKE ?") {
		t.Fatalf("关键词应使用 LIKE 参数占位: %s", where)
	}
	if strings.Contains(where, "admin") || strings.Contains(where, "1.2.3.4") {
		t.Fatalf("WHERE 子句不应内嵌用户输入（防注入）: %s", where)
	}
	// 4 个 LIKE + action + user + ip + from + to = 9 个参数
	if len(args) != 9 {
		t.Fatalf("参数数量应为 9，实际 %d: %v", len(args), args)
	}
	if args[0] != "%admin%" || args[8] != "2026-11-25\x7f" {
		t.Fatalf("参数值异常: %v", args)
	}
}

func TestAuditWhereEmpty(t *testing.T) {
	where, args := auditWhere(AuditFilter{})
	if where != "1=1" || len(args) != 0 {
		t.Fatalf("空筛选应无条件: %s %v", where, args)
	}
}

func TestAuditQueryFilterAndPaging(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// 写入若干条不同用户/动作的审计记录
	s.Audit("admin", "1.1.1.1", "login_ok", "登录成功")
	s.Audit("admin", "1.1.1.2", "private_key_view", "查看私钥 example.com")
	s.Audit("bob", "2.2.2.2", "login_ok", "登录成功")
	s.Audit("admin", "1.1.1.3", "login_failed", "密码错误")

	if got := s.AuditCount(); got != 4 {
		t.Fatalf("总数应为 4，实际 %d", got)
	}

	// 按动作筛选
	entries, total := s.AuditQuery(AuditFilter{Action: "login_ok", Limit: 50})
	if total != 2 || len(entries) != 2 {
		t.Fatalf("login_ok 应命中 2 条，实际 total=%d len=%d", total, len(entries))
	}

	// 关键词匹配 detail
	entries, total = s.AuditQuery(AuditFilter{Query: "私钥", Limit: 50})
	if total != 1 || entries[0]["action"] != "private_key_view" {
		t.Fatalf("关键词筛选异常: total=%d %v", total, entries)
	}

	// 关键词匹配 user（bob）
	_, total = s.AuditQuery(AuditFilter{Query: "bob", Limit: 50})
	if total != 1 {
		t.Fatalf("用户关键词应命中 1 条，实际 %d", total)
	}

	// 组合筛选：admin + login
	_, total = s.AuditQuery(AuditFilter{User: "admin", Action: "login_ok", Limit: 50})
	if total != 1 {
		t.Fatalf("组合筛选应命中 1 条，实际 %d", total)
	}

	// 分页：每页 2 条
	p1, total := s.AuditQuery(AuditFilter{Limit: 2, Offset: 0})
	p2, _ := s.AuditQuery(AuditFilter{Limit: 2, Offset: 2})
	if total != 4 || len(p1) != 2 || len(p2) != 2 {
		t.Fatalf("分页异常: total=%d p1=%d p2=%d", total, len(p1), len(p2))
	}
	// 两页不应重复（按 id 倒序）
	if reflect.DeepEqual(p1[0]["detail"], p2[0]["detail"]) {
		t.Fatal("两页首条不应相同")
	}

	// 动作 / 用户下拉列表
	actions := s.AuditActions()
	if !reflect.DeepEqual(actions, []string{"login_failed", "login_ok", "private_key_view"}) {
		t.Fatalf("动作列表异常: %v", actions)
	}
	users := s.AuditUsers()
	if !reflect.DeepEqual(users, []string{"admin", "bob"}) {
		t.Fatalf("用户列表异常: %v", users)
	}
}
