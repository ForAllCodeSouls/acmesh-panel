package main

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Prometheus 文本格式（0.0.4）。只输出聚合指标：不含域名、IP、私钥、
// 凭证或任务标题。端点挂 requireRead，仍受 IP 白名单与 HTTPS 开关保护。

func metricLine(w http.ResponseWriter, name, help, typ, labels, value string) {
	_, _ = fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n%s%s %s\n", name, help, name, typ, name, labels, value)
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")

	metricLine(w, "acmesh_panel_up", "Panel is running", "gauge", "", "1")
	metricLine(w, "acmesh_panel_build_info", "Panel build version", "gauge",
		`{version="`+prometheusEscape(appVersion)+`"}`, "1")
	metricLine(w, "acmesh_panel_uptime_seconds", "Panel uptime in seconds", "gauge", "",
		strconv.Itoa(int(time.Since(s.boot).Seconds())))

	certs, err := s.certs.Scan()
	if err == nil {
		metricLine(w, "acmesh_panel_certificates_total", "Number of managed certificates", "gauge", "",
			strconv.Itoa(len(certs)))
		counts := map[string]int{"valid": 0, "warning": 0, "critical": 0, "expired": 0, "invalid": 0}
		minDays := -1
		for _, c := range certs {
			key := c.Status
			if _, ok := counts[key]; !ok {
				key = "invalid"
			}
			counts[key]++
			if c.DaysLeft >= 0 && (minDays < 0 || c.DaysLeft < minDays) {
				minDays = c.DaysLeft
			}
		}
		keys := []string{"valid", "warning", "critical", "expired", "invalid"}
		for _, k := range keys {
			metricLine(w, "acmesh_panel_certificates", "Certificates by status", "gauge",
				`{status="`+k+`"}`, strconv.Itoa(counts[k]))
		}
		metricLine(w, "acmesh_panel_cert_min_days_left", "Fewest days left among non-expired certificates",
			"gauge", "", strconv.Itoa(minDays))
	}

	jobCounts := map[string]int{}
	for _, j := range s.jobs.List() {
		key := j.Status
		if key == "" {
			key = "unknown"
		}
		jobCounts[key]++
	}
	jobKeys := make([]string, 0, len(jobCounts))
	for k := range jobCounts {
		jobKeys = append(jobKeys, k)
	}
	sort.Strings(jobKeys)
	for _, k := range jobKeys {
		metricLine(w, "acmesh_panel_jobs", "Jobs by status", "gauge",
			`{status="`+prometheusEscape(k)+`"}`, strconv.Itoa(jobCounts[k]))
	}

	st := s.store.Snapshot()
	syncFail := 0
	for _, e := range st.SyncEvents {
		if e.Result == "fail" {
			syncFail++
		}
	}
	metricLine(w, "acmesh_panel_sync_events_total", "Recent sync events by result", "counter",
		`{result="fail"}`, strconv.Itoa(syncFail))
	metricLine(w, "acmesh_panel_notify_failures_total", "Pending notification delivery failures",
		"gauge", "", strconv.Itoa(s.store.CountNotifyFailures()))
}

func prometheusEscape(v string) string {
	r := strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "\n", "\\n")
	return r.Replace(v)
}
