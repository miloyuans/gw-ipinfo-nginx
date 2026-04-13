package query

import (
	"bytes"
	"context"
	"fmt"
	"html"
	"sort"
	"strings"
	"time"

	"gw-ipinfo-nginx/internal/config"
	v4model "gw-ipinfo-nginx/internal/v4/model"
	"gw-ipinfo-nginx/internal/v4/repository"
)

type Result struct {
	SummaryHTML string
	FileName    string
	FileContent []byte
	ContentType string
}

type Service struct {
	cfg            config.V4TelegramConfig
	v4Cfg          config.V4Config
	routeFile      config.RouteSetFileConfig
	baseConfigPath string
	serviceNames   map[string]struct{}
	snapshots      *repository.SnapshotRepository
	states         *repository.RuntimeStateRepository
	events         *repository.EventRepository
}

func NewService(cfg config.V4TelegramConfig, v4Cfg config.V4Config, routeFile config.RouteSetFileConfig, baseConfigPath string, serviceNames []string, snapshots *repository.SnapshotRepository, states *repository.RuntimeStateRepository, events *repository.EventRepository) *Service {
	names := make(map[string]struct{}, len(serviceNames))
	for _, name := range serviceNames {
		names[strings.TrimSpace(name)] = struct{}{}
	}
	return &Service{
		cfg:            cfg,
		v4Cfg:          v4Cfg,
		routeFile:      routeFile,
		baseConfigPath: baseConfigPath,
		serviceNames:   names,
		snapshots:      snapshots,
		states:         states,
		events:         events,
	}
}

func (s *Service) BuildRoutesSummary(ctx context.Context) (Result, error) {
	syncState, _, _ := s.snapshots.LoadSyncState(ctx)
	snapshot, hosts, found, err := s.snapshots.LoadLatest(ctx)
	if err != nil {
		return Result{}, err
	}
	if !found {
		return Result{
			SummaryHTML: buildNoSnapshotSummary(syncState),
		}, nil
	}

	states, err := s.states.List(ctx)
	if err != nil {
		return Result{}, err
	}
	stateByHost := make(map[string]v4model.HostRuntimeState, len(states))
	for _, state := range states {
		stateByHost[state.Host] = state
	}

	recentEvents := make([]v4model.Event, 0)
	if s.events != nil {
		if items, listErr := s.events.ListRecent(ctx, 20); listErr == nil {
			recentEvents = filterVisibleEvents(snapshot, syncState, items)
		}
	}
	syncView := buildSyncView(snapshot, syncState, recentEvents)

	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Host < hosts[j].Host })
	fileHosts := append([]v4model.SnapshotHost(nil), hosts...)

	summaryHosts := hosts
	summaryLimit := s.cfg.MaxHosts
	if summaryLimit <= 0 {
		summaryLimit = 3
	}
	if len(summaryHosts) > summaryLimit {
		summaryHosts = summaryHosts[:summaryLimit]
	}

	var summary strings.Builder
	summary.WriteString("<b>V4 Routes Summary</b>\n")
	summary.WriteString(html.EscapeString(fmt.Sprintf("快照时间 / Snapshot time: %s\n", snapshot.UpdatedAt.Format(time.RFC3339))))
	summary.WriteString(html.EscapeString(fmt.Sprintf("主机数量 / Hosts: %d\n", snapshot.HostCount)))
	summary.WriteString(html.EscapeString(fmt.Sprintf("当前状态 / Current status: %s\n", syncView.Status)))
	if !syncView.LastSuccessAt.IsZero() {
		summary.WriteString(html.EscapeString(fmt.Sprintf("最近成功 / Last success: %s\n", syncView.LastSuccessAt.Format(time.RFC3339))))
	}
	if syncView.LastError != "" {
		summary.WriteString(html.EscapeString(fmt.Sprintf("最近错误 / Last error: %s\n", trimForSummary(syncView.LastError, 180))))
	}
	summary.WriteString(html.EscapeString(fmt.Sprintf("摘要主机数 / Top hosts: %d\n", len(summaryHosts))))
	if len(fileHosts) > len(summaryHosts) {
		summary.WriteString(html.EscapeString(fmt.Sprintf("其余 %d 个域名请查看附件 / See attachment for the remaining %d hosts\n", len(fileHosts)-len(summaryHosts), len(fileHosts)-len(summaryHosts))))
	}

	summary.WriteString("\n<b>字段说明 / Field Guide</b>\n")
	summary.WriteString(html.EscapeString("Host = 入口域名；Mode = 当前流量模式；Backend Service = 上游服务名；Backend Host = 反代时覆盖的 Host；Security = 是否开启安全检查；Enrichment = IP 丰富化模式；Probe = 是否启用探测；Targets = 当前探测到的目标数；Last Reason = 最近异常原因；Redirect URL = 当前故障跳转地址。\n"))

	summary.WriteString("\n<b>Top Hosts / 摘要域名</b>\n")
	for _, host := range summaryHosts {
		state := normalizeDisplayedState(host, stateByHost[host.Host])
		mode := strings.TrimSpace(state.Mode)
		if mode == "" {
			mode = v4model.ModePassthrough
		}
		summary.WriteString(html.EscapeString(fmt.Sprintf(
			"• %s | mode=%s | backend=%s | backend_host=%s | security=%t | enrich=%s | probe=%t | targets=%d | reason=%s\n",
			host.Host,
			mode,
			host.BackendService,
			host.BackendHost,
			host.SecurityChecksEnabled,
			host.IPEnrichmentMode,
			host.Probe.Enabled,
			len(state.LastProbeTargets),
			trimForSummary(state.LastProbeError, 60),
		)))
	}

	if len(recentEvents) > 0 {
		summary.WriteString("\n<b>Recent Events / 最近事件</b>\n")
		for _, event := range recentEvents {
			summary.WriteString(html.EscapeString(fmt.Sprintf("• %s | %s | %s\n", event.Type, event.Host, trimForSummary(event.Message, 100))))
		}
	}

	result := Result{
		SummaryHTML: summary.String(),
	}
	if s.cfg.SendHTMLFile {
		result.FileName = "v4-routes.html"
		result.ContentType = "text/html; charset=utf-8"
		result.FileContent = []byte(buildHTMLDocument(snapshot, syncView, fileHosts, stateByHost, recentEvents))
	}
	return result, nil
}

func buildHTMLDocument(snapshot v4model.Snapshot, syncView syncView, hosts []v4model.SnapshotHost, stateByHost map[string]v4model.HostRuntimeState, recentEvents []v4model.Event) string {
	var buffer bytes.Buffer
	buffer.WriteString("<html><head><meta charset=\"utf-8\"><title>V4 Routes</title></head><body>")
	buffer.WriteString("<h1>V4 Routes</h1>")
	buffer.WriteString("<p>" + html.EscapeString(snapshot.UpdatedAt.Format(time.RFC3339)) + "</p>")
	buffer.WriteString("<p>" + html.EscapeString("当前状态 / Current status: "+syncView.Status) + "</p>")
	if !syncView.LastSuccessAt.IsZero() {
		buffer.WriteString("<p>" + html.EscapeString("最近成功 / Last success: "+syncView.LastSuccessAt.Format(time.RFC3339)) + "</p>")
	}
	if syncView.LastError != "" {
		buffer.WriteString("<p>" + html.EscapeString("最近错误 / Last error: "+syncView.LastError) + "</p>")
	}

	buffer.WriteString("<h2>字段说明 / Field Guide</h2>")
	buffer.WriteString("<ul>")
	buffer.WriteString("<li><b>Host（入口域名）</b>: 请求命中的站点域名 / Matched host</li>")
	buffer.WriteString("<li><b>Mode（运行模式）</b>: 当前运行模式，通常是 passthrough 或 degraded_redirect / Current runtime mode</li>")
	buffer.WriteString("<li><b>Backend Service（后端服务）</b>: 对应 routing.services 里的上游服务名 / Upstream service name</li>")
	buffer.WriteString("<li><b>Backend Host（后端 Host）</b>: 反向代理时覆盖的 Host 请求头 / Host header override for upstream</li>")
	buffer.WriteString("<li><b>Security（安全检查）</b>: 是否启用完整安全检查 / Whether full security checks are enabled</li>")
	buffer.WriteString("<li><b>Enrichment（IP 丰富化）</b>: IP 丰富化模式，disabled、cache_only、full / IP enrichment mode</li>")
	buffer.WriteString("<li><b>Probe（探测）</b>: 是否为该 host 显式开启探测 / Whether probe is enabled for this host</li>")
	buffer.WriteString("<li><b>Targets（目标数）</b>: 当前探测到的跳转目标数 / Current discovered target count</li>")
	buffer.WriteString("<li><b>Last Reason（最近原因）</b>: 最近一次探测异常原因 / Most recent probe error</li>")
	buffer.WriteString("<li><b>Redirect URL（降级跳转）</b>: 当前故障跳转地址，仅在 degraded_redirect 时生效 / Current failover target when degraded redirect is active</li>")
	buffer.WriteString("</ul>")

	buffer.WriteString("<table border=\"1\" cellspacing=\"0\" cellpadding=\"6\">")
	buffer.WriteString("<tr><th>Host<br/>入口域名</th><th>Mode<br/>运行模式</th><th>Backend Service<br/>后端服务</th><th>Backend Host<br/>后端 Host</th><th>Security<br/>安全检查</th><th>Enrichment<br/>IP 丰富化</th><th>Probe<br/>探测</th><th>Targets<br/>目标数</th><th>Last Reason<br/>最近原因</th><th>Redirect URL<br/>降级跳转</th></tr>")
	for _, host := range hosts {
		state := normalizeDisplayedState(host, stateByHost[host.Host])
		mode := strings.TrimSpace(state.Mode)
		if mode == "" {
			mode = v4model.ModePassthrough
		}
		buffer.WriteString("<tr>")
		buffer.WriteString("<td>" + html.EscapeString(host.Host) + "</td>")
		buffer.WriteString("<td>" + html.EscapeString(mode) + "</td>")
		buffer.WriteString("<td>" + html.EscapeString(host.BackendService) + "</td>")
		buffer.WriteString("<td>" + html.EscapeString(host.BackendHost) + "</td>")
		buffer.WriteString("<td>" + html.EscapeString(fmt.Sprintf("%t", host.SecurityChecksEnabled)) + "</td>")
		buffer.WriteString("<td>" + html.EscapeString(host.IPEnrichmentMode) + "</td>")
		buffer.WriteString("<td>" + html.EscapeString(fmt.Sprintf("%t", host.Probe.Enabled)) + "</td>")
		buffer.WriteString("<td>" + html.EscapeString(fmt.Sprintf("%d", len(state.LastProbeTargets))) + "</td>")
		buffer.WriteString("<td>" + html.EscapeString(trimForSummary(state.LastProbeError, 120)) + "</td>")
		buffer.WriteString("<td>" + html.EscapeString(state.RedirectURL) + "</td>")
		buffer.WriteString("</tr>")
	}
	buffer.WriteString("</table>")

	if len(recentEvents) > 0 {
		buffer.WriteString("<h2>Recent Events / 最近事件</h2>")
		buffer.WriteString("<p>仅展示当前仍相关的近期事件；已被后续成功同步覆盖的旧 snapshot_sync_failed 会自动隐藏。</p>")
		buffer.WriteString("<table border=\"1\" cellspacing=\"0\" cellpadding=\"6\">")
		buffer.WriteString("<tr><th>Type<br/>事件类型</th><th>Host<br/>域名</th><th>Level<br/>级别</th><th>Message<br/>消息</th><th>Created At<br/>创建时间</th></tr>")
		for _, event := range recentEvents {
			buffer.WriteString("<tr>")
			buffer.WriteString("<td>" + html.EscapeString(event.Type) + "</td>")
			buffer.WriteString("<td>" + html.EscapeString(event.Host) + "</td>")
			buffer.WriteString("<td>" + html.EscapeString(event.Level) + "</td>")
			buffer.WriteString("<td>" + html.EscapeString(event.Message) + "</td>")
			buffer.WriteString("<td>" + html.EscapeString(event.CreatedAt.Format(time.RFC3339)) + "</td>")
			buffer.WriteString("</tr>")
		}
		buffer.WriteString("</table>")
	}

	buffer.WriteString("</body></html>")
	return buffer.String()
}

func buildNoSnapshotSummary(syncState v4model.SyncState) string {
	view := buildSyncView(v4model.Snapshot{}, syncState, nil)
	lines := []string{
		"当前没有可用的 v4 路由快照。",
		"No v4 snapshot is available.",
	}
	if view.Status != "unknown" {
		lines = append(lines, "当前状态 / Current status: "+view.Status)
	}
	if view.LastError != "" {
		lines = append(lines, "最近错误 / Last error: "+trimForSummary(view.LastError, 180))
	}
	return "<pre>" + html.EscapeString(strings.Join(lines, "\n")) + "</pre>"
}

type syncView struct {
	Status        string
	LastSuccessAt time.Time
	LastError     string
}

func buildSyncView(snapshot v4model.Snapshot, syncState v4model.SyncState, events []v4model.Event) syncView {
	lastSuccessAt := latestSuccessTime(snapshot, syncState, events)
	lastFailureAt := latestFailureTime(syncState, events)
	status := strings.TrimSpace(syncState.LastStatus)

	switch status {
	case "":
		if !lastSuccessAt.IsZero() {
			status = "success"
		} else {
			status = "unknown"
		}
	case "success_no_change":
		status = "success"
	case "failed":
		if !lastSuccessAt.IsZero() && (lastFailureAt.IsZero() || !lastSuccessAt.Before(lastFailureAt)) {
			status = "success"
		} else if !snapshot.UpdatedAt.IsZero() || !lastSuccessAt.IsZero() {
			status = "degraded"
		}
	}

	lastError := ""
	if status == "failed" || status == "degraded" {
		lastError = strings.TrimSpace(syncState.LastError)
		if lastError == "" {
			lastError = latestFailureMessage(events)
		}
	}

	return syncView{
		Status:        status,
		LastSuccessAt: lastSuccessAt,
		LastError:     lastError,
	}
}

func latestSuccessTime(snapshot v4model.Snapshot, syncState v4model.SyncState, events []v4model.Event) time.Time {
	latest := snapshot.UpdatedAt
	if syncState.LastSuccessAt.After(latest) {
		latest = syncState.LastSuccessAt
	}
	for _, event := range events {
		if event.Type == v4model.EventSnapshotUpdated && event.CreatedAt.After(latest) {
			latest = event.CreatedAt
		}
	}
	return latest
}

func latestFailureTime(syncState v4model.SyncState, events []v4model.Event) time.Time {
	latest := time.Time{}
	if strings.TrimSpace(syncState.LastStatus) == "failed" {
		latest = syncState.LastSyncAt
	}
	for _, event := range events {
		if event.Type == v4model.EventSnapshotSyncFailed && event.CreatedAt.After(latest) {
			latest = event.CreatedAt
		}
	}
	return latest
}

func latestFailureMessage(events []v4model.Event) string {
	for _, event := range events {
		if event.Type == v4model.EventSnapshotSyncFailed && strings.TrimSpace(event.Message) != "" {
			return strings.TrimSpace(event.Message)
		}
	}
	return ""
}

func filterVisibleEvents(snapshot v4model.Snapshot, syncState v4model.SyncState, events []v4model.Event) []v4model.Event {
	if len(events) == 0 {
		return nil
	}
	lastSuccessAt := latestSuccessTime(snapshot, syncState, events)
	filtered := make([]v4model.Event, 0, len(events))
	for _, event := range events {
		if event.Type == v4model.EventSnapshotSyncFailed && !lastSuccessAt.IsZero() && !event.CreatedAt.After(lastSuccessAt) {
			continue
		}
		filtered = append(filtered, event)
	}
	if len(filtered) > 8 {
		filtered = filtered[:8]
	}
	return filtered
}

func trimForSummary(value string, limit int) string {
	value = strings.TrimSpace(value)
	if limit <= 0 || len(value) <= limit {
		return value
	}
	return value[:limit] + "..."
}

func normalizeDisplayedState(host v4model.SnapshotHost, state v4model.HostRuntimeState) v4model.HostRuntimeState {
	if strings.TrimSpace(state.Host) == "" {
		state.Host = host.Host
	}

	switch strings.TrimSpace(state.Mode) {
	case "", v4model.ModePassthrough:
		state.Mode = v4model.ModePassthrough
	case v4model.ModeDegradedRedirect, v4model.ModeRecovering:
	default:
		state.Mode = v4model.ModePassthrough
	}

	if !host.Probe.Enabled {
		state.Mode = v4model.ModePassthrough
		state.RedirectURL = ""
		state.LastProbeTargets = nil
		state.LastFailedTargets = nil
		state.LastProbeError = ""
		return state
	}

	if state.Mode == v4model.ModePassthrough {
		state.RedirectURL = ""
	}
	return state
}
