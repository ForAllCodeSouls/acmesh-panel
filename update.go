package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// updateCheckURL 是 GitHub 最新 Release 接口。私钥等信息不会出现在请求里。
const updateCheckURL = "https://api.github.com/repos/ForAllCodeSouls/acmesh-panel/releases/latest"

// releaseInfo 是从 GitHub 解析出的版本信息。
type releaseInfo struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
}

// fetchRelease 查询最新 Release。网络失败由调用方按需处理，不影响面板运行。
func fetchRelease(ctx context.Context) (releaseInfo, error) {
	var rel releaseInfo
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, updateCheckURL, nil)
	if err != nil {
		return rel, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "acmesh-panel/"+appVersion)
	resp, err := (&http.Client{Timeout: 6 * time.Second}).Do(req)
	if err != nil {
		return rel, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return rel, fmt.Errorf("GitHub 返回 %d", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&rel); err != nil {
		return rel, err
	}
	if rel.TagName == "" {
		return rel, fmt.Errorf("版本信息为空")
	}
	return rel, nil
}

// isSemanticVersion 判断版本号是否为语义化版本（至少含一个数字段）。
// CI / 本地开发构建会注入 "ci"、"dev" 等非语义版本号，
// 此类构建不做"有新版本"判定（解析出来恒为 0，任何 Release 都会被误报为更新）。
func isSemanticVersion(v string) bool {
	for _, c := range strings.TrimPrefix(v, "v") {
		if c >= '0' && c <= '9' {
			return true
		}
	}
	return false
}

// runUpdateCheck 执行一次检测，持久化结果，并在发现新版本时去重通知。
// 返回本次检测的结果摘要，供 API 直接响应，避免重复请求 GitHub。
func (s *Server) runUpdateCheck(ctx context.Context) UpdateState {
	cctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()

	rel, err := fetchRelease(cctx)
	if err != nil {
		st := s.store.UpdateConfig()
		_ = s.store.RecordUpdateCheck(st.Latest, st.NeedUpdate, "暂时无法连接 GitHub", st.URL)
		return s.store.UpdateConfig()
	}

	need := isSemanticVersion(appVersion) && versionNewer(rel.TagName, appVersion)
	if err := s.store.RecordUpdateCheck(rel.TagName, need, "", rel.HTMLURL); err != nil {
		log.Printf("保存版本检测结果失败: %v", err)
	}
	result := s.store.UpdateConfig()

	if need {
		if notify, e := s.store.MarkUpdateNotified(rel.TagName); e != nil {
			log.Printf("记录版本提醒状态失败: %v", e)
		} else if notify {
			msg := fmt.Sprintf("发现新版本 %s（当前 %s）。请到 GitHub Release 页面查看更新说明并手动升级。", rel.TagName, appVersion)
			s.notify.Send("update_available", "acmesh-panel 有新版本", msg)
			s.store.Audit("system", "", "update_available", rel.TagName)
		}
	}
	return result
}

// updateIntervalDuration 把频次配置转换为间隔；off/startup 返回 0（不参与周期调度）。
func updateIntervalDuration(interval string) time.Duration {
	switch interval {
	case updateInterval6h:
		return 6 * time.Hour
	case updateIntervalDaily:
		return 24 * time.Hour
	case updateIntervalWeekly:
		return 7 * 24 * time.Hour
	default:
		return 0
	}
}

// dueForUpdateCheck 判断当前是否到达自动检测时间。
// startup 只在进程启动后检测一次，用 LastCheck 是否晚于启动时间判断。
func (s *Server) dueForUpdateCheck() bool {
	st := s.store.UpdateConfig()
	if !st.AutoCheck || st.Interval == updateIntervalOff {
		return false
	}
	if st.Interval == updateIntervalStartup {
		return st.LastCheck.IsZero() || st.LastCheck.Before(s.boot)
	}
	d := updateIntervalDuration(st.Interval)
	if d <= 0 {
		return false
	}
	return st.LastCheck.IsZero() || time.Since(st.LastCheck) >= d
}

// updateLoop 每分钟检查一次是否到达自动检测时间。
// 频次变更立即生效，无需重建定时器。启动时若开启自动检测则先检测一次。
func (s *Server) updateLoop(ctx context.Context) {
	if s.dueForUpdateCheck() {
		s.runUpdateCheck(ctx)
	}
	timer := time.NewTicker(time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if s.dueForUpdateCheck() {
				s.runUpdateCheck(ctx)
			}
		}
	}
}
