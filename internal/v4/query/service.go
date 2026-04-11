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
	"gw-ipinfo-nginx/internal/v4/events"
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
	events    *events.Service
}

func NewService(cfg config.V4TelegramConfig, snapshots *repository.SnapshotRepository, states *repository.RuntimeStateRepository, events *events.Service) *Service {
	return &Service{cfg: cfg, snapshots: snapshots, states: states, events: events}
}

func (s *Service) BuildRoutesSummary(ctx context.Context) (Result, error) {
	snapshot, hosts, found, err := s.snapshots.LoadLatest(ctx)
	if err != nil {
		return Result{}, err
	}
	if !found {
		return Result{SummaryHTML: "<pre>当前没有可用的 v4 路由快照。\nNo v4 snapshot is available.</pre>"}, nil
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
		if items, listErr := s.events.ListRecent(ctx, 10); listErr == nil {
			recentEvents = items
		}
	}

	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Host < hosts[j].Host })
	if s.cfg.MaxHosts > 0 && len(hosts) > s.cfg.MaxHosts {
		hosts = hosts[:s.cfg.MaxHosts]
	}

	var summary strings.Builder
	summary.WriteString("<b>V4 Routes Summary</b>\n")
	summary.WriteString(html.EscapeString(fmt.Sprintf("快照时间 / Snapshot time: %s\n", snapshot.UpdatedAt.Format(time.RFC3339))))
	summary.WriteString(html.EscapeString(fmt.Sprintf("主机数量 / Hosts: %d\n", snapshot.HostCount)))
	summary.WriteString(html.EscapeString(fmt.Sprintf("指纹 / Fingerprint: %s\n", snapshot.Fingerprint)))
	summary.WriteString(html.EscapeString(fmt.Sprintf("最近事件 / Recent events: %d\n", len(recentEvents))))
	summary.WriteString("\n")

	for _, host := range hosts {
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
			summary.WriteString(html.EscapeString(fmt.Sprintf("• %s | %s | %s\n", event.Type, event.Host, event.Message)))
		}
	}

	result := Result{
		SummaryHTML: summary.String(),
	}
	if s.cfg.SendHTMLFile {
		result.FileName = "v4-routes.html"
		result.ContentType = "text/html; charset=utf-8"
		result.FileContent = []byte(buildHTMLDocument(snapshot, hosts, stateByHost, recentEvents))
	}
	return result, nil
}

func buildHTMLDocument(snapshot v4model.Snapshot, hosts []v4model.SnapshotHost, stateByHost map[string]v4model.HostRuntimeState, recentEvents []v4model.Event) string {
	var buffer bytes.Buffer
	buffer.WriteString("<html><head><meta charset=\"utf-8\"><title>V4 Routes</title></head><body>")
	buffer.WriteString("<h1>V4 Routes</h1>")
	buffer.WriteString("<p>")
	buffer.WriteString(html.EscapeString(snapshot.UpdatedAt.Format(time.RFC3339)))
	buffer.WriteString("</p>")
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
