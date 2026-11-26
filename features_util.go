package main

import (
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

func sha256Bytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:16])
}

func mapStr(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func writeCSV(w http.ResponseWriter, header []string, rows [][]string) {
	cw := csv.NewWriter(w)
	_ = cw.Write(header)
	for _, row := range rows {
		_ = cw.Write(row)
	}
	cw.Flush()
}

// ---------------- 失败任务自动重试调度 ----------------

type retryEntry struct {
	JobID     string    `json:"job_id"`
	Attempt   int       `json:"attempt"` // 已经重试的次数（不含首次）
	NextAt    time.Time `json:"next_at"`
	Error     string    `json:"error"`
	CreatedAt time.Time `json:"created_at"`
}

// RetryScheduler 在内存中维护待重试队列。重启后未执行的重试会丢失，
// 但历史任务仍可通过「手动重试」恢复，这是可接受的取舍（凭证不落额外副本）。
type RetryScheduler struct {
	mu      sync.Mutex
	queue   map[string]*retryEntry
	order   []string
	stop    chan struct{}
	trigger chan struct{}
	jobs    *JobManager
	policy  func() RetryPolicy
}

func NewRetryScheduler(jobs *JobManager, policy func() RetryPolicy) *RetryScheduler {
	rs := &RetryScheduler{
		queue: map[string]*retryEntry{}, stop: make(chan struct{}),
		trigger: make(chan struct{}, 1), jobs: jobs, policy: policy,
	}
	go rs.loop()
	return rs
}

func (rs *RetryScheduler) loop() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-rs.stop:
			return
		case <-t.C:
			rs.drain()
		case <-rs.trigger:
			rs.drain()
		}
	}
}

func (rs *RetryScheduler) drain() {
	now := time.Now()
	rs.mu.Lock()
	due := []*retryEntry{}
	for _, id := range rs.order {
		e := rs.queue[id]
		if e != nil && !e.NextAt.After(now) {
			due = append(due, e)
		}
	}
	for _, e := range due {
		delete(rs.queue, e.JobID)
	}
	rs.order = filterOrder(rs.order, rs.queue)
	rs.mu.Unlock()
	for _, e := range due {
		_, _ = rs.jobs.Retry(e.JobID)
	}
}

func filterOrder(order []string, m map[string]*retryEntry) []string {
	out := make([]string, 0, len(order))
	for _, id := range order {
		if _, ok := m[id]; ok {
			out = append(out, id)
		}
	}
	return out
}

// Schedule 在任务失败时调用。返回是否成功排入队列。
func (rs *RetryScheduler) Schedule(jobID string, attempt int, errMsg string) bool {
	p := rs.policy()
	if !p.Enabled || attempt >= p.MaxAttempts-1 {
		return false
	}
	delay := p.BaseDelay << uint(attempt) // 指数退避：base, 2x, 4x...
	if delay > p.MaxDelay {
		delay = p.MaxDelay
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if _, exists := rs.queue[jobID]; exists {
		return false
	}
	rs.queue[jobID] = &retryEntry{
		JobID: jobID, Attempt: attempt + 1,
		NextAt: time.Now().Add(time.Duration(delay) * time.Second),
		Error:  errMsg, CreatedAt: time.Now(),
	}
	rs.order = append(rs.order, jobID)
	select {
	case rs.trigger <- struct{}{}:
	default:
	}
	return true
}

func (rs *RetryScheduler) Cancel(jobID string) {
	rs.mu.Lock()
	delete(rs.queue, jobID)
	rs.order = filterOrder(rs.order, rs.queue)
	rs.mu.Unlock()
}

func (rs *RetryScheduler) Snapshot() []retryEntry {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	out := []retryEntry{}
	for _, id := range rs.order {
		if e := rs.queue[id]; e != nil {
			out = append(out, *e)
		}
	}
	return out
}

func (rs *RetryScheduler) Close() {
	close(rs.stop)
}

// RetryQueue 供 API 展示当前等待重试的任务。
func (m *JobManager) RetryQueue() []retryEntry {
	if m.retryScheduler == nil {
		return []retryEntry{}
	}
	return m.retryScheduler.Snapshot()
}

// ---------------- 自动备份调度 ----------------

// backupLoop 每分钟检查一次是否到达配置的备份时间。
// 同一天/同一周只执行一次；配置的 LastRun 持久化，重启不会重复备份。
func (s *Server) backupLoop(ctx context.Context) {
	t := time.NewTicker(1 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cfg := s.store.Snapshot().AutoBackup
			if !cfg.Enabled {
				continue
			}
			now := time.Now()
			if now.Hour() != cfg.Hour {
				continue
			}
			if cfg.Interval == "weekly" && now.Weekday() != time.Monday {
				continue
			}
			if cfg.LastRun.Format("2006-01-02") == now.Format("2006-01-02") {
				continue
			}
			rec, err := s.createBackup("auto", cfg.IncludeCerts)
			cfg.LastRun = now
			if err != nil {
				cfg.LastResult = "失败: " + err.Error()
				log.Printf("自动备份失败: %v", err)
			} else {
				cfg.LastResult = "成功: " + rec.Name
				s.store.Audit("system", "127.0.0.1", "backup_auto", rec.Name)
			}
			_ = s.store.SetAutoBackup(cfg)
			s.pruneBackups(cfg.Keep)
		}
	}
}

// pruneBackups 按保留份数清理最旧的备份文件与记录。
func (s *Server) pruneBackups(keep int) {
	if keep < 1 {
		keep = 7
	}
	records := s.store.ListBackups(maxBackupRecords)
	if len(records) <= keep {
		return
	}
	for _, rec := range records[keep:] {
		p, err := s.backupPath(rec.Name)
		if err == nil {
			_ = os.Remove(p)
		}
		certPath, _ := s.backupPath(strings.TrimSuffix(rec.Name, ".json") + "-certs.tar.gz")
		_ = os.Remove(certPath)
		s.store.DeleteBackupRecord(rec.ID)
	}
}
