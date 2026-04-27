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

type syncView struct {
	Status        string
	LastSuccessAt time.Time
	LastError     string
}

type hostNoteEntry struct {
	Label string
	Value string
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
	syncStateView := buildSyncView(snapshot, syncState, recentEvents)

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
	summary.WriteString(html.EscapeString(fmt.Sprintf("当前状态 / Current status: %s\n", syncStateView.Status)))
	if !syncStateView.LastSuccessAt.IsZero() {
		summary.WriteString(html.EscapeString(fmt.Sprintf("最近成功 / Last success: %s\n", syncStateView.LastSuccessAt.Format(time.RFC3339))))
	}
	if syncStateView.LastError != "" {
		summary.WriteString(html.EscapeString(fmt.Sprintf("最近错误 / Last error: %s\n", trimForSummary(syncStateView.LastError, 180))))
	}
	summary.WriteString(html.EscapeString(fmt.Sprintf("摘要主机数 / Top hosts: %d\n", len(summaryHosts))))
	if len(fileHosts) > len(summaryHosts) {
		remaining := len(fileHosts) - len(summaryHosts)
		summary.WriteString(html.EscapeString(fmt.Sprintf("其余 %d 个域名请查看附件 / See attachment for the remaining %d hosts\n", remaining, remaining)))
	}

	summary.WriteString("\n<b>字段说明 / Field Guide</b>\n")
	summary.WriteString(html.EscapeString("Host = 入口域名；Mode = 当前流量模式；Backend Service = 上游服务名；Backend Host = 反代覆盖 Host；Security = 是否启用完整安全检查；Enrichment = IP 丰富化模式；Probe = 是否启用探测；Faults = 故障次数；Switch OK = 切换成功次数；Switch Fail = 切换失败次数；Redirect Clients = 切换后去重客户端数；Targets = 当前目标数；Last Reason = 最近探测异常；Notes = 最近故障/切换失败说明；Redirect URL = 当前降级跳转地址。\n"))

	summary.WriteString("\n<b>Top Hosts / 摘要域名</b>\n")
	for _, host := range summaryHosts {
		state := normalizeDisplayedState(snapshot, host, stateByHost[host.Host])
		mode := strings.TrimSpace(state.Mode)
		if mode == "" {
			mode = v4model.ModePassthrough
		}
		summary.WriteString(html.EscapeString(fmt.Sprintf(
			"• %s | mode=%s | backend=%s | backend_host=%s | security=%t | enrich=%s | probe=%t | faults=%d | switch_ok=%d | switch_fail=%d | redirect_clients=%d | targets=%d | reason=%s | note=%s\n",
			host.Host,
			mode,
			host.BackendService,
			host.BackendHost,
			host.SecurityChecksEnabled,
			host.IPEnrichmentMode,
			host.Probe.Enabled,
			state.FaultCount,
			state.SwitchSuccessCount,
			state.SwitchFailureCount,
			state.RedirectUniqueClientCount,
			len(state.LastProbeTargets),
			trimForSummary(state.LastProbeError, 60),
			trimForSummary(buildHostNotesText(state), 90),
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
		result.FileContent = []byte(buildHTMLDocument(snapshot, syncStateView, fileHosts, stateByHost, recentEvents))
	}
	return result, nil
}

func buildHTMLDocument(snapshot v4model.Snapshot, syncStateView syncView, hosts []v4model.SnapshotHost, stateByHost map[string]v4model.HostRuntimeState, recentEvents []v4model.Event) string {
	var buffer bytes.Buffer
	buffer.WriteString(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>V4 Routes</title><style>
:root{color-scheme:dark;--bg:#06111f;--bg2:#091a2b;--panel:rgba(9,26,43,.82);--line:rgba(121,190,255,.18);--text:#e8f1ff;--muted:#8aa6c8;--accent:#6ed6ff;--ok:#78ffcf;--warn:#ffc36e;--danger:#ff8c8c;--shadow:0 18px 60px rgba(0,0,0,.32);}
*{box-sizing:border-box}html,body{margin:0;padding:0;background:radial-gradient(circle at top left,rgba(27,89,153,.26),transparent 28%),radial-gradient(circle at top right,rgba(17,187,153,.16),transparent 24%),linear-gradient(180deg,var(--bg),var(--bg2));color:var(--text);font:14px/1.55 "Segoe UI","PingFang SC","Microsoft YaHei",sans-serif}
body{min-height:100vh}.page{max-width:2048px;margin:0 auto;padding:16px 12px 24px}
.hero,.panel,.events-panel{background:var(--panel);border:1px solid var(--line);border-radius:18px;box-shadow:var(--shadow);backdrop-filter:blur(14px)}
.hero{padding:16px 18px;margin-bottom:14px;position:relative;overflow:hidden}.hero:before{content:"";position:absolute;inset:-20% auto auto 70%;width:180px;height:180px;background:radial-gradient(circle,rgba(110,214,255,.18),transparent 72%);pointer-events:none}
.hero h1{margin:0 0 6px;font-size:28px;letter-spacing:.02em}.hero p{margin:0;color:var(--muted);font-size:12px}
.hero-meta{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}.badge{display:inline-flex;align-items:center;gap:6px;padding:6px 10px;border-radius:999px;background:rgba(10,28,48,.72);border:1px solid var(--line);color:var(--text);font-weight:600;font-size:12px}
.badge.status-success{border-color:rgba(120,255,207,.35);color:var(--ok)}.badge.status-degraded{border-color:rgba(255,195,110,.35);color:var(--warn)}.badge.status-failed{border-color:rgba(255,140,140,.35);color:var(--danger)}
.layout{display:grid;grid-template-columns:228px minmax(0,1fr);gap:12px;align-items:start}.sticky-stack{position:sticky;top:12px;display:grid;gap:10px}
.panel{padding:12px 12px 10px}.panel h2{margin:0 0 10px;font-size:17px}.meta-grid{display:grid;grid-template-columns:1fr;gap:8px}
.metric{padding:8px 9px 7px;border-radius:12px;background:rgba(7,18,31,.56);border:1px solid var(--line)}.metric .label{display:block;color:var(--muted);font-size:10px;margin-bottom:3px}.metric .value{display:block;font-size:11px;font-weight:700;word-break:break-word}
.guide-list{display:grid;gap:7px}.guide-item{padding:7px 8px;border-radius:12px;background:rgba(7,18,31,.46);border:1px solid rgba(121,190,255,.1)}.guide-item strong{display:block;margin-bottom:2px;font-size:11px}.guide-item span{display:block;color:var(--muted);font-size:10px;line-height:1.35}
.panel-head{display:flex;justify-content:space-between;align-items:flex-end;gap:10px;margin-bottom:10px}.panel-head p,.muted{margin:0;color:var(--muted);font-size:12px}
.matrix-panel{display:flex;flex-direction:column}.matrix-panel .table-wrap{flex:1;min-height:560px;max-height:calc(100vh - 210px);overflow:auto}
.table-wrap{overflow-x:auto;overflow-y:visible;border-radius:14px;border:1px solid var(--line);padding-top:2px}table{width:100%;border-collapse:separate;border-spacing:0;table-layout:auto;min-width:1540px;background:rgba(5,14,25,.62)}
th,td{padding:8px 10px;border-bottom:1px solid rgba(121,190,255,.08);vertical-align:top;text-align:left;font-size:11px;line-height:1.4;white-space:normal}th{position:sticky;top:0;background:rgba(8,19,33,.98);backdrop-filter:blur(12px);z-index:3;font-size:10px;text-transform:uppercase;letter-spacing:.03em;min-width:88px}
th span{display:block;margin-top:3px;font-size:10px;text-transform:none;letter-spacing:0;color:var(--muted)}tbody tr:nth-child(odd){background:rgba(255,255,255,.015)}tbody tr:hover{background:rgba(110,214,255,.06)}
.table-wrap th:nth-child(1),.table-wrap td:nth-child(1){min-width:132px}
.table-wrap th:nth-child(2),.table-wrap td:nth-child(2){min-width:90px}
.table-wrap th:nth-child(3),.table-wrap td:nth-child(3){min-width:110px}
.table-wrap th:nth-child(4),.table-wrap td:nth-child(4){min-width:126px}
.table-wrap th:nth-child(8),.table-wrap td:nth-child(8),
.table-wrap th:nth-child(9),.table-wrap td:nth-child(9),
.table-wrap th:nth-child(10),.table-wrap td:nth-child(10),
.table-wrap th:nth-child(11),.table-wrap td:nth-child(11),
.table-wrap th:nth-child(12),.table-wrap td:nth-child(12){min-width:74px}
.table-wrap th:nth-child(13),.table-wrap td:nth-child(13){min-width:180px}
.table-wrap th:nth-child(14),.table-wrap td:nth-child(14){min-width:240px}
.table-wrap th:nth-child(15),.table-wrap td:nth-child(15){min-width:210px}
.mono{font-family:Consolas,"SFMono-Regular",Menlo,monospace}.bool-true{color:var(--ok);font-weight:700}.bool-false{color:var(--muted)}
.reason,.notes,.url-list{word-break:break-word}.notes{display:grid;gap:4px;min-width:190px}.note-line{padding:5px 6px;border-radius:8px;background:rgba(6,17,31,.58);border:1px solid rgba(121,190,255,.08)}
.note-line strong{display:block;font-size:10px;color:var(--accent);margin-bottom:2px;text-transform:uppercase;letter-spacing:.03em}.note-line span{display:block;color:var(--text);font-size:11px;line-height:1.35}.empty-note{color:var(--muted);font-style:italic}
.events-panel{margin-top:18px;overflow:hidden}.events-panel summary{list-style:none;cursor:pointer;padding:16px 18px;font-weight:700;display:flex;justify-content:space-between;align-items:center;gap:12px}.events-panel summary::-webkit-details-marker{display:none}.events-panel[open] summary{border-bottom:1px solid var(--line)}
.events-inner{padding:0 18px 18px}.events-hint{margin:12px 0;color:var(--muted)}.mini-table{min-width:980px}
@media (max-width:1380px){.layout{grid-template-columns:208px minmax(0,1fr)}table{min-width:1420px}.matrix-panel .table-wrap{min-height:500px;max-height:calc(100vh - 190px)}}@media (max-width:1180px){.layout{grid-template-columns:1fr}.sticky-stack{position:static}.matrix-panel .table-wrap{min-height:420px;max-height:none}}@media (max-width:720px){.page{padding:12px 10px 20px}.hero h1{font-size:24px}.matrix-panel .table-wrap{min-height:360px}}
</style></head><body><div class="page">`)

	buffer.WriteString(`<section class="hero"><h1>V4 Routes</h1><p>共享读模型展示页。当前页面只展示数据库中的统一持久化状态，便于多副本一致性排查和故障切换定位。</p><div class="hero-meta">`)
	buffer.WriteString(`<span class="badge ` + statusClass(syncStateView.Status) + `">当前状态 / Current status: ` + html.EscapeString(syncStateView.Status) + `</span>`)
	buffer.WriteString(`<span class="badge">快照主机 / Hosts: ` + html.EscapeString(fmt.Sprintf("%d", snapshot.HostCount)) + `</span>`)
	buffer.WriteString(`<span class="badge">快照时间 / Snapshot: ` + html.EscapeString(snapshot.UpdatedAt.Format(time.RFC3339)) + `</span>`)
	buffer.WriteString(`</div></section>`)

	buffer.WriteString(`<div class="layout"><aside><div class="sticky-stack">`)
	buffer.WriteString(`<section class="panel"><h2>总览 / Overview</h2><div class="meta-grid">`)
	buffer.WriteString(metricCard("当前状态 / Status", syncStateView.Status))
	buffer.WriteString(metricCard("快照主机 / Hosts", fmt.Sprintf("%d", snapshot.HostCount)))
	buffer.WriteString(metricCard("最近成功 / Last success", formatTimeValue(syncStateView.LastSuccessAt)))
	buffer.WriteString(metricCard("最近错误 / Last error", fallbackValue(trimForSummary(syncStateView.LastError, 140))))
	buffer.WriteString(metricCard("读模型 / Read model", "DB snapshot"))
	buffer.WriteString(metricCard("事件数量 / Events", fmt.Sprintf("%d", len(recentEvents))))
	buffer.WriteString(`</div></section>`)

	buffer.WriteString(`<section class="panel"><h2>字段说明 / Field Guide</h2><div class="guide-list">`)
	buffer.WriteString(fieldGuideItem("Host", "入口域名 / Matched host"))
	buffer.WriteString(fieldGuideItem("Mode", "当前运行模式，通常是 passthrough 或 degraded_redirect / Runtime mode"))
	buffer.WriteString(fieldGuideItem("Security", "是否走完整安全检查链 / Whether full security checks are enabled"))
	buffer.WriteString(fieldGuideItem("Enrichment", "IP 丰富化模式：disabled、cache_only、full / IP enrichment mode"))
	buffer.WriteString(fieldGuideItem("Faults", "累计故障次数；按一次故障事件计数 / Total fault occurrences"))
	buffer.WriteString(fieldGuideItem("Switch OK / Switch Fail", "成功或失败切换到故障跳转的次数 / Successful or failed failover switches"))
	buffer.WriteString(fieldGuideItem("Redirect Clients", "切换后访问过降级跳转的去重客户端数 / Unique clients after failover"))
	buffer.WriteString(fieldGuideItem("Notes", "最近故障原因、切换失败原因、失败目标等摘要 / Recent fault and failover details"))
	buffer.WriteString(`</div></section></div></aside><main>`)

	buffer.WriteString(`<section class="panel matrix-panel"><div class="panel-head"><div><h2>Route Matrix / 路由矩阵</h2><p>矩阵区域支持独立上下滚动，表头会固定在矩阵内部。下方表格聚焦每个 host 的当前路由状态、故障统计和原因细节。</p></div><p>` + html.EscapeString(fmt.Sprintf("Hosts: %d", len(hosts))) + `</p></div>`)
	buffer.WriteString(`<div class="table-wrap"><table><thead><tr>`)
	buffer.WriteString(`<th>Host<span>入口域名</span></th>`)
	buffer.WriteString(`<th>Mode<span>运行模式</span></th>`)
	buffer.WriteString(`<th>Backend Service<span>后端服务</span></th>`)
	buffer.WriteString(`<th>Backend Host<span>后端 Host</span></th>`)
	buffer.WriteString(`<th>Security<span>安全检查</span></th>`)
	buffer.WriteString(`<th>Enrichment<span>IP 丰富化</span></th>`)
	buffer.WriteString(`<th>Probe<span>探测</span></th>`)
	buffer.WriteString(`<th>Faults<span>故障次数</span></th>`)
	buffer.WriteString(`<th>Switch OK<span>切换成功</span></th>`)
	buffer.WriteString(`<th>Switch Fail<span>切换失败</span></th>`)
	buffer.WriteString(`<th>Redirect Clients<span>去重客户端</span></th>`)
	buffer.WriteString(`<th>Targets<span>目标数</span></th>`)
	buffer.WriteString(`<th>Last Reason<span>最近原因</span></th>`)
	buffer.WriteString(`<th>Notes<span>备注说明</span></th>`)
	buffer.WriteString(`<th>Redirect URL<span>降级跳转</span></th>`)
	buffer.WriteString(`</tr></thead><tbody>`)
	for _, host := range hosts {
		state := normalizeDisplayedState(snapshot, host, stateByHost[host.Host])
		mode := strings.TrimSpace(state.Mode)
		if mode == "" {
			mode = v4model.ModePassthrough
		}
		buffer.WriteString(`<tr>`)
		buffer.WriteString(`<td class="mono">` + html.EscapeString(host.Host) + `</td>`)
		buffer.WriteString(`<td class="mono">` + html.EscapeString(mode) + `</td>`)
		buffer.WriteString(`<td>` + html.EscapeString(host.BackendService) + `</td>`)
		buffer.WriteString(`<td class="mono">` + html.EscapeString(host.BackendHost) + `</td>`)
		buffer.WriteString(`<td class="` + boolClass(host.SecurityChecksEnabled) + `">` + html.EscapeString(boolText(host.SecurityChecksEnabled)) + `</td>`)
		buffer.WriteString(`<td class="mono">` + html.EscapeString(host.IPEnrichmentMode) + `</td>`)
		buffer.WriteString(`<td class="` + boolClass(host.Probe.Enabled) + `">` + html.EscapeString(boolText(host.Probe.Enabled)) + `</td>`)
		buffer.WriteString(`<td>` + html.EscapeString(fmt.Sprintf("%d", state.FaultCount)) + `</td>`)
		buffer.WriteString(`<td>` + html.EscapeString(fmt.Sprintf("%d", state.SwitchSuccessCount)) + `</td>`)
		buffer.WriteString(`<td>` + html.EscapeString(fmt.Sprintf("%d", state.SwitchFailureCount)) + `</td>`)
		buffer.WriteString(`<td>` + html.EscapeString(fmt.Sprintf("%d", state.RedirectUniqueClientCount)) + `</td>`)
		buffer.WriteString(`<td>` + html.EscapeString(fmt.Sprintf("%d", len(state.LastProbeTargets))) + `</td>`)
		buffer.WriteString(`<td class="reason">` + html.EscapeString(fallbackValue(trimForSummary(state.LastProbeError, 180))) + `</td>`)
		buffer.WriteString(`<td class="notes">` + buildHostNotesHTML(state) + `</td>`)
		buffer.WriteString(`<td class="url-list mono">` + html.EscapeString(fallbackValue(state.RedirectURL)) + `</td>`)
		buffer.WriteString(`</tr>`)
	}
	buffer.WriteString(`</tbody></table></div></section>`)

	if len(recentEvents) > 0 {
		buffer.WriteString(`<details class="events-panel"><summary><span>Recent Events / 最近事件</span><span class="muted">默认折叠，点击展开</span></summary><div class="events-inner">`)
		buffer.WriteString(`<p class="events-hint">仅展示当前仍相关的近期事件；已被后续成功同步覆盖的旧 snapshot_sync_failed 会自动隐藏。</p>`)
		buffer.WriteString(`<div class="table-wrap"><table class="mini-table"><thead><tr><th>Type<span>事件类型</span></th><th>Host<span>域名</span></th><th>Level<span>级别</span></th><th>Message<span>消息</span></th><th>Created At<span>创建时间</span></th></tr></thead><tbody>`)
		for _, event := range recentEvents {
			buffer.WriteString(`<tr>`)
			buffer.WriteString(`<td class="mono">` + html.EscapeString(event.Type) + `</td>`)
			buffer.WriteString(`<td class="mono">` + html.EscapeString(fallbackValue(event.Host)) + `</td>`)
			buffer.WriteString(`<td>` + html.EscapeString(event.Level) + `</td>`)
			buffer.WriteString(`<td class="reason">` + html.EscapeString(event.Message) + `</td>`)
			buffer.WriteString(`<td class="mono">` + html.EscapeString(event.CreatedAt.Format(time.RFC3339)) + `</td>`)
			buffer.WriteString(`</tr>`)
		}
		buffer.WriteString(`</tbody></table></div></div></details>`)
	}

	buffer.WriteString(`</main></div></div></body></html>`)
	return buffer.String()
}

func buildNoSnapshotSummary(syncState v4model.SyncState) string {
	view := buildSyncView(v4model.Snapshot{}, syncState, nil)
	if view.Status == "success" {
		view.Status = "rebuilding"
	}
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

func metricCard(label, value string) string {
	return `<div class="metric"><span class="label">` + html.EscapeString(label) + `</span><span class="value">` + html.EscapeString(fallbackValue(value)) + `</span></div>`
}

func fieldGuideItem(label, description string) string {
	return `<div class="guide-item"><strong>` + html.EscapeString(label) + `</strong><span>` + html.EscapeString(description) + `</span></div>`
}

func statusClass(status string) string {
	switch strings.TrimSpace(strings.ToLower(status)) {
	case "success":
		return "status-success"
	case "degraded", "rebuilding":
		return "status-degraded"
	case "failed":
		return "status-failed"
	default:
		return ""
	}
}

func formatTimeValue(value time.Time) string {
	if value.IsZero() {
		return "-"
	}
	return value.Format(time.RFC3339)
}

func boolText(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func boolClass(value bool) string {
	if value {
		return "bool-true"
	}
	return "bool-false"
}

func fallbackValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	return value
}

func buildHostNotesText(state v4model.HostRuntimeState) string {
	entries := buildHostNoteEntries(state)
	if len(entries) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(entries))
	for _, entry := range entries {
		parts = append(parts, entry.Label+": "+entry.Value)
	}
	return strings.Join(parts, " | ")
}

func buildHostNotesHTML(state v4model.HostRuntimeState) string {
	entries := buildHostNoteEntries(state)
	if len(entries) == 0 {
		return `<span class="empty-note">无 / None</span>`
	}
	var builder strings.Builder
	for _, entry := range entries {
		builder.WriteString(`<div class="note-line"><strong>`)
		builder.WriteString(html.EscapeString(entry.Label))
		builder.WriteString(`</strong><span>`)
		builder.WriteString(html.EscapeString(entry.Value))
		builder.WriteString(`</span></div>`)
	}
	return builder.String()
}

func buildHostNoteEntries(state v4model.HostRuntimeState) []hostNoteEntry {
	entries := make([]hostNoteEntry, 0, 4)
	faultReason := strings.TrimSpace(state.LastFaultReason)
	if faultReason == "" {
		faultReason = strings.TrimSpace(state.LastProbeError)
	}
	if state.FaultCount > 0 && faultReason != "" {
		entries = append(entries, hostNoteEntry{
			Label: "故障原因 / Fault",
			Value: trimForSummary(faultReason, 180),
		})
	}
	switchFailureReason := strings.TrimSpace(state.LastSwitchFailureReason)
	if state.SwitchFailureCount > 0 {
		if switchFailureReason == "" {
			switchFailureReason = strings.TrimSpace(state.LastProbeError)
		}
		if switchFailureReason == "" && len(state.LastFailedTargets) > 0 {
			switchFailureReason = "recent probe failures exist; see failed targets"
		}
		if switchFailureReason == "" && len(state.LastProbeTargets) == 0 {
			switchFailureReason = "no probe targets discovered"
		}
		if switchFailureReason == "" {
			switchFailureReason = "historical state is missing switch-failure detail; wait for the next probe cycle"
		}
		entries = append(entries, hostNoteEntry{
			Label: "切换失败 / Switch fail",
			Value: trimForSummary(switchFailureReason, 180),
		})
	}
	if len(state.LastFailedTargets) > 0 {
		entries = append(entries, hostNoteEntry{
			Label: "失败目标 / Failed targets",
			Value: buildTargetSample(state.LastFailedTargets),
		})
	}
	if state.Mode == v4model.ModeDegradedRedirect && strings.TrimSpace(state.RedirectURL) != "" {
		entries = append(entries, hostNoteEntry{
			Label: "当前降级 / Active redirect",
			Value: trimForSummary(state.RedirectURL, 180),
		})
	}
	return entries
}

func buildTargetSample(values []string) string {
	if len(values) == 0 {
		return "0"
	}
	parts := make([]string, 0, 2)
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		parts = append(parts, trimForSummary(value, 90))
		if len(parts) == 2 {
			break
		}
	}
	if len(parts) == 0 {
		return fmt.Sprintf("%d", len(values))
	}
	if len(values) > len(parts) {
		return fmt.Sprintf("%d total: %s ...", len(values), strings.Join(parts, " | "))
	}
	return strings.Join(parts, " | ")
}

func normalizeDisplayedState(snapshot v4model.Snapshot, host v4model.SnapshotHost, state v4model.HostRuntimeState) v4model.HostRuntimeState {
	if strings.TrimSpace(state.Host) == "" {
		state.Host = host.Host
	}
	if staleDisplayedState(snapshot, state) {
		state = v4model.HostRuntimeState{
			ID:                  host.Host,
			Host:                host.Host,
			SnapshotVersion:     strings.TrimSpace(snapshot.Version),
			SnapshotFingerprint: strings.TrimSpace(snapshot.Fingerprint),
			Mode:                v4model.ModePassthrough,
		}
	}
	if strings.TrimSpace(snapshot.Version) != "" {
		state.SnapshotVersion = strings.TrimSpace(snapshot.Version)
	}
	if strings.TrimSpace(snapshot.Fingerprint) != "" {
		state.SnapshotFingerprint = strings.TrimSpace(snapshot.Fingerprint)
	}

	switch strings.TrimSpace(state.Mode) {
	case "", v4model.ModePassthrough:
		state.Mode = v4model.ModePassthrough
	case v4model.ModeDegradedRedirect, v4model.ModeRecovering:
	default:
		state.Mode = v4model.ModePassthrough
	}

	if !host.Probe.Enabled {
		state.FaultActive = false
		state.FaultCount = 0
		state.SwitchSuccessCount = 0
		state.SwitchFailureCount = 0
		state.RedirectUniqueClientCount = 0
		state.Mode = v4model.ModePassthrough
		state.RedirectURL = ""
		state.RedirectClientKeys = nil
		state.LastProbeTargets = nil
		state.LastFailedTargets = nil
		state.LastProbeError = ""
		state.LastFaultReason = ""
		state.LastSwitchFailureReason = ""
		return state
	}

	if state.Mode == v4model.ModePassthrough {
		state.RedirectURL = ""
	}
	state.RedirectUniqueClientCount = uniqueStringCount(state.RedirectClientKeys)
	return state
}

func uniqueStringCount(values []string) int {
	if len(values) == 0 {
		return 0
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		seen[value] = struct{}{}
	}
	return len(seen)
}

func staleDisplayedState(snapshot v4model.Snapshot, state v4model.HostRuntimeState) bool {
	snapshotVersion := strings.TrimSpace(snapshot.Version)
	snapshotFingerprint := strings.TrimSpace(snapshot.Fingerprint)
	stateVersion := strings.TrimSpace(state.SnapshotVersion)
	stateFingerprint := strings.TrimSpace(state.SnapshotFingerprint)

	if snapshotVersion == "" && snapshotFingerprint == "" {
		return false
	}
	if stateVersion == "" && stateFingerprint == "" {
		return true
	}
	if snapshotVersion != "" && stateVersion != "" && snapshotVersion != stateVersion {
		return true
	}
	if snapshotFingerprint != "" && stateFingerprint != "" && snapshotFingerprint != stateFingerprint {
		return true
	}
	return false
}
