package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// 通知失败记录保存在独立 SQLite 表，不进入 State 单条 JSON。
// 同一渠道 + 事件 + 标题只保留一条待重试记录，避免定时提醒刷屏。

type NotifyFailure struct {
	ID           int       `json:"id"`
	TS           time.Time `json:"ts"`
	NotifierID   string    `json:"notifier_id"`
	NotifierName string    `json:"notifier_name"`
	Event        string    `json:"event"`
	Title        string    `json:"title"`
	Message      string    `json:"message"`
	SentTime     string    `json:"sent_time"`
	Attempts     int       `json:"attempts"`
	NextAttempt  time.Time `json:"next_attempt"`
	LastError    string    `json:"last_error"`
	Status       string    `json:"status"`
}

const (
	notifyRetryMax   = 5
	notifyFailureCap = 200
)

func scanNotifyFailure(rows interface{ Scan(...any) error }) (NotifyFailure, error) {
	var f NotifyFailure
	var ts, next string
	err := rows.Scan(&f.ID, &ts, &f.NotifierID, &f.NotifierName, &f.Event, &f.Title,
		&f.Message, &f.SentTime, &f.Attempts, &next, &f.LastError, &f.Status)
	if err != nil {
		return f, err
	}
	f.TS, _ = time.Parse(time.RFC3339, ts)
	f.NextAttempt, _ = time.Parse(time.RFC3339, next)
	return f, nil
}

const notifyFailureColumns = `id,ts,notifier_id,notifier_name,event,title,message,
	sent_time,attempts,next_attempt,last_error,status`

// notifyRetryBackoff 返回第 attempts 次失败后的下一次重试间隔。
// 首次失败为第 1 次，其后按 1、2、4、8 分钟退避；耗尽后为 24 小时，
// AddNotifyFailure 与手动重发共用同一套计算，避免退避被新失败重置为 now。
func notifyRetryBackoff(attempts int) time.Duration {
	if attempts >= notifyRetryMax {
		return 24 * time.Hour
	}
	return time.Duration(1<<minInt(maxInt(attempts-2, 0), 3)) * time.Minute
}

// AddNotifyFailure 记录一次推送失败；相同事件只更新已有待重试项。
func (s *Store) AddNotifyFailure(n Notifier, msg NotifyMessage, sendErr error) {
	if s.db == nil {
		return
	}
	now := time.Now().Format(time.RFC3339)
	var id, attempts int
	err := s.db.QueryRow(`SELECT id, attempts FROM notify_failures
		WHERE notifier_id=? AND event=? AND title=? AND status='pending' LIMIT 1`,
		n.ID, msg.Event, msg.Title).Scan(&id, &attempts)
	if err == nil {
		attempts++
		next := time.Now().Add(notifyRetryBackoff(attempts)).Format(time.RFC3339)
		status := "pending"
		if attempts >= notifyRetryMax {
			status = "exhausted"
		}
		_, _ = s.db.Exec(`UPDATE notify_failures SET ts=?, attempts=?, next_attempt=?,
			last_error=?, status=? WHERE id=?`, now, attempts, next, sendErr.Error(), status, id)
		return
	}
	next := time.Now().Add(notifyRetryBackoff(1)).Format(time.RFC3339)
	_, _ = s.db.Exec(`INSERT INTO notify_failures
		(ts,notifier_id,notifier_name,event,title,message,sent_time,attempts,next_attempt,last_error,status)
		VALUES(?,?,?,?,?,?,?,1,?,?,'pending')`,
		now, n.ID, n.Name, msg.Event, msg.Title, msg.Message, msg.Time, next, sendErr.Error())
	// 控制记录规模；保留最近若干条，避免长期运行后无限增长。
	_, _ = s.db.Exec(`DELETE FROM notify_failures WHERE id NOT IN
		(SELECT id FROM notify_failures ORDER BY id DESC LIMIT ?)`, notifyFailureCap)
}

// ClearNotifyFailure 在同类通知成功后移除待重试记录。
func (s *Store) ClearNotifyFailure(notifierID, event, title string) {
	if s.db == nil {
		return
	}
	_, _ = s.db.Exec(`DELETE FROM notify_failures
		WHERE notifier_id=? AND event=? AND title=? AND status='pending'`, notifierID, event, title)
}

func (s *Store) CountNotifyFailures() int {
	if s.db == nil {
		return 0
	}
	n := 0
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM notify_failures WHERE status='pending'`).Scan(&n)
	return n
}

func (s *Store) ListNotifyFailures(limit int) []NotifyFailure {
	if s.db == nil {
		return []NotifyFailure{}
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.Query(`SELECT `+notifyFailureColumns+` FROM notify_failures
		ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return []NotifyFailure{}
	}
	defer rows.Close()
	out := []NotifyFailure{}
	for rows.Next() {
		f, err := scanNotifyFailure(rows)
		if err == nil {
			out = append(out, f)
		}
	}
	return out
}

func (s *Store) DueNotifyFailures(now time.Time, limit int) []NotifyFailure {
	if s.db == nil {
		return []NotifyFailure{}
	}
	rows, err := s.db.Query(`SELECT `+notifyFailureColumns+` FROM notify_failures
		WHERE status='pending' AND next_attempt<=? ORDER BY id LIMIT ?`,
		now.Format(time.RFC3339), limit)
	if err != nil {
		return []NotifyFailure{}
	}
	defer rows.Close()
	out := []NotifyFailure{}
	for rows.Next() {
		f, err := scanNotifyFailure(rows)
		if err == nil {
			out = append(out, f)
		}
	}
	return out
}

func (s *Store) GetNotifyFailure(id int) (NotifyFailure, error) {
	if s.db == nil {
		return NotifyFailure{}, sql.ErrNoRows
	}
	rows, err := s.db.Query(`SELECT `+notifyFailureColumns+` FROM notify_failures WHERE id=?`, id)
	if err != nil {
		return NotifyFailure{}, err
	}
	defer rows.Close()
	if rows.Next() {
		return scanNotifyFailure(rows)
	}
	return NotifyFailure{}, sql.ErrNoRows
}

func (s *Store) UpdateNotifyFailure(id, attempts int, next time.Time, lastErr, status string) {
	if s.db == nil {
		return
	}
	_, _ = s.db.Exec(`UPDATE notify_failures SET attempts=?, next_attempt=?, last_error=?, status=? WHERE id=?`,
		attempts, next.Format(time.RFC3339), lastErr, status, id)
}

func (s *Store) DeleteNotifyFailure(id int) bool {
	if s.db == nil {
		return false
	}
	res, err := s.db.Exec(`DELETE FROM notify_failures WHERE id=?`, id)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}

// resendNotifyFailure 立即重发一条失败通知；成功则删除记录，失败则更新退避状态。
func (e *NotifyEngine) resendNotifyFailure(ctx context.Context, f NotifyFailure) error {
	n, err := e.store.GetNotifier(f.NotifierID)
	if err != nil {
		e.store.DeleteNotifyFailure(f.ID)
		return fmt.Errorf("渠道已不存在，记录已清除")
	}
	msg := NotifyMessage{
		Title: f.Title, Message: f.Message, Event: f.Event, Time: f.SentTime,
		Level: levelForEvent(f.Event),
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	err = e.sendOne(cctx, n, msg)
	if err == nil {
		e.store.DeleteNotifyFailure(f.ID)
		return nil
	}
	attempts := f.Attempts + 1
	status := "pending"
	if attempts >= notifyRetryMax {
		status = "exhausted"
	}
	next := time.Now().Add(notifyRetryBackoff(attempts))
	e.store.UpdateNotifyFailure(f.ID, attempts, next, err.Error(), status)
	return err
}

func (e *NotifyEngine) RetryFailures(ctx context.Context) {
	for _, f := range e.store.DueNotifyFailures(time.Now(), 20) {
		_ = e.resendNotifyFailure(ctx, f)
	}
}

func (s *Server) notifyRetryLoop(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.notify.RetryFailures(ctx)
		}
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (s *Server) handleNotifyFailures(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"failures": s.store.ListNotifyFailures(100),
		"pending":  s.store.CountNotifyFailures(),
	})
}

func (s *Server) handleNotifyFailureResend(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil || id <= 0 {
		writeErr(w, http.StatusBadRequest, "非法记录 ID")
		return
	}
	f, err := s.store.GetNotifyFailure(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "记录不存在")
		return
	}
	if err := s.notify.resendNotifyFailure(r.Context(), f); err != nil {
		writeErr(w, http.StatusBadRequest, "重发失败: "+err.Error())
		return
	}
	s.store.Audit(sess(r).User, clientIP(r, s.cfg.TrustProxy), "notify_resend", fmt.Sprintf("%d %s", id, strings.TrimSpace(f.Title)))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleNotifyFailureDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil || id <= 0 {
		writeErr(w, http.StatusBadRequest, "非法记录 ID")
		return
	}
	if !s.store.DeleteNotifyFailure(id) {
		writeErr(w, http.StatusNotFound, "记录不存在")
		return
	}
	s.store.Audit(sess(r).User, clientIP(r, s.cfg.TrustProxy), "notify_failure_delete", strconv.Itoa(id))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
