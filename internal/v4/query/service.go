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
	cfg       config.V4TelegramConfig
	snapshots *repository.SnapshotRepository
	states    *repository.RuntimeStateRepository
	events    *repository.EventRepository
}

func NewService(cfg config.V4TelegramConfig, snapshots *repository.SnapshotRepository, states *repository.RuntimeStateRepository, events *repository.EventRepository) *Service {
	return &Service{cfg: cfg, snapshots: snapshots, states: states, events: events}
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
		if items, listErr := s.events.ListRecent(ctx, 8); listErr == nil {
			recentEvents = items
		}
	}

	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Host < hosts[j].Host })
	fileHosts := append([]v4model.SnapshotHost(nil), hosts...)

	summaryHosts := hosts
	summaryLimit := 10
	if s.cfg.MaxHosts > 0 && s.cfg.MaxHosts < summaryLimit {
		summaryLimit = s.cfg.MaxHosts
	}
	if summaryLimit > 0 && len(summaryHosts) > summaryLimit {
		summaryHosts = summaryHosts[:summaryLimit]
	}

	var summary strings.Builder
	summary.WriteString("<b>V4 Routes Summary</b>\n")
	summary.WriteString(html.EscapeString(fmt.Sprintf("快照时间 / Snapshot time: %s\n", snapshot.UpdatedAt.Format(time.RFC3339))))
	summary.WriteString(html.EscapeString(fmt.Sprintf("主机数量 / Hosts: %d\n", snapshot.HostCount)))
	summary.WriteString(html.EscapeString(fmt.Sprintf("同步状态 / Sync status: %s\n", displaySyncStatus(syncState))))
	if !syncState.LastSuccessAt.IsZero() {
		summary.WriteString(html.EscapeString(fmt.Sprintf("最近成功 / Last success: %s\n", syncState.LastSuccessAt.Format(time.RFC3339))))
	}
	if syncState.LastError != "" {
		summary.WriteString(html.EscapeString(fmt.Sprintf("最近错误 / Last error: %s\n", trimForSummary(syncState.LastError, 180))))
	}
	summary.WriteString(html.EscapeString(fmt.Sprintf("最近事件 / Recent events: %d\n", len(recentEvents))))
	summary.WriteString("\n<b>Top Hosts</b>\n")

	for _, host := range summaryHosts {
		state := stateByHost[host.Host]
		mode := strings.TrimSpace(state.Mode)
		if mode == "" {
			mode = v4model.ModePassthrough
		}
		summary.WriteString(html.EscapeString(fmt.Sprintf(
			"• %s | mode=%s | backend=%s | backend_host=%s | security=%t | enrich=%s | probe=%t\n",
			host.Host,
			mode,
			host.BackendService,
			host.BackendHost,
			host.SecurityChecksEnabled,
			host.IPEnrichmentMode,
			host.Probe.Enabled,
		)))
	}

	if len(recentEvents) > 0 {
		summary.WriteString("\n<b>Recent Events</b>\n")
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
		result.FileContent = []byte(buildHTMLDocument(snapshot, syncState, fileHosts, stateByHost, recentEvents))
	}
	return result, nil
}

func buildHTMLDocument(snapshot v4model.Snapshot, syncState v4model.SyncState, hosts []v4model.SnapshotHost, stateByHost map[string]v4model.HostRuntimeState, recentEvents []v4model.Event) string {
	var buffer bytes.Buffer
	buffer.WriteString("<html><head><meta charset=\"utf-8\"><title>V4 Routes</title></head><body>")
	buffer.WriteString("<h1>V4 Routes</h1>")
	buffer.WriteString("<p>" + html.EscapeString(snapshot.UpdatedAt.Format(time.RFC3339)) + "</p>")
	buffer.WriteString("<p>" + html.EscapeString("Sync status: "+displaySyncStatus(syncState)) + "</p>")
	if syncState.LastError != "" {
		buffer.WriteString("<p>" + html.EscapeString("Last error: "+syncState.LastError) + "</p>")
	}
	buffer.WriteString("<table border=\"1\" cellspacing=\"0\" cellpadding=\"6\">")
	buffer.WriteString("<tr><th>Host</th><th>Mode</th><th>Backend Service</th><th>Backend Host</th><th>Security</th><th>Enrichment</th><th>Probe</th><th>Redirect URL</th></tr>")
	for _, host := range hosts {
		state := stateByHost[host.Host]
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
		buffer.WriteString("<td>" + html.EscapeString(state.RedirectURL) + "</td>")
		buffer.WriteString("</tr>")
	}
	buffer.WriteString("</table>")
	if len(recentEvents) > 0 {
		buffer.WriteString("<h2>Recent Events</h2>")
		buffer.WriteString("<table border=\"1\" cellspacing=\"0\" cellpadding=\"6\">")
		buffer.WriteString("<tr><th>Type</th><th>Host</th><th>Level</th><th>Message</th><th>Created At</th></tr>")
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
	lines := []string{
		"当前没有可用的 v4 路由快照。",
		"No v4 snapshot is available.",
	}
	if status := displaySyncStatus(syncState); status != "unknown" {
		lines = append(lines, "同步状态 / Sync status: "+status)
	}
	if syncState.LastError != "" {
		lines = append(lines, "最近错误 / Last error: "+trimForSummary(syncState.LastError, 180))
	}
	return "<pre>" + html.EscapeString(strings.Join(lines, "\n")) + "</pre>"
}

func displaySyncStatus(state v4model.SyncState) string {
	status := strings.TrimSpace(state.LastStatus)
	if status == "" {
		return "unknown"
	}
	return status
}

func trimForSummary(value string, limit int) string {
	value = strings.TrimSpace(value)
	if limit <= 0 || len(value) <= limit {
		return value
	}
	return value[:limit] + "..."
}
