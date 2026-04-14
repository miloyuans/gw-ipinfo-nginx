package audit

import (
	"log/slog"

	"gw-ipinfo-nginx/internal/model"
)

type Logger struct {
	base *slog.Logger
}

func New(base *slog.Logger) *Logger {
	return &Logger{base: base}
}

func (l *Logger) LogDecision(record model.AuditRecord) {
	attrs := []any{
		"event", "gateway_request",
		"request_id", record.RequestID,
		"instance_id", record.InstanceID,
		"client_ip", record.ClientIP,
		"service_name", record.ServiceName,
		"upstream_url", record.UpstreamURL,
		"host", record.Host,
		"method", record.Method,
		"path", record.Path,
		"request_url", record.RequestURL,
		"allowed", record.Allowed,
		"result", record.Result,
		"reason_code", record.ReasonCode,
		"cache_source", record.CacheSource,
		"data_source_mode", record.DataSourceMode,
		"short_circuit_hit", record.ShortCircuitHit,
		"short_circuit_source", record.ShortCircuitSource,
		"short_circuit_decision", record.ShortCircuitDecision,
		"ipinfo_lookup_action", record.IPInfoLookupAction,
		"route_set_kind", record.RouteSetKind,
		"route_id", record.RouteID,
		"source_host", record.SourceHost,
		"source_path_prefix", record.SourcePathPrefix,
		"target_host", record.TargetHost,
		"target_public_url", record.TargetPublicURL,
		"backend_service", record.BackendService,
		"backend_host", record.BackendHost,
		"grant_status", record.GrantStatus,
		"grant_expire_at", record.GrantExpireAt,
		"v3_security_filter_enabled", record.V3SecurityFilterEnabled,
		"v3_selected_target_id", record.V3SelectedTargetID,
		"v3_selected_target_host", record.V3SelectedTargetHost,
		"v3_strategy_mode", record.V3StrategyMode,
		"v3_binding_reused", record.V3BindingReused,
		"v4_runtime_mode", record.V4RuntimeMode,
		"v4_route_source", record.V4RouteSource,
		"v4_security_checks_enabled", record.V4SecurityChecksEnabled,
		"v4_enrichment_mode", record.V4EnrichmentMode,
		"v4_probe_enabled", record.V4ProbeEnabled,
		"v4_evaluation_mode", record.V4EvaluationMode,
		"v4_snapshot_version", record.V4SnapshotVersion,
		"latency_ms", record.LatencyMS,
		"country_code", record.CountryCode,
		"country_name", record.CountryName,
		"city", record.City,
		"region", record.Region,
		"vpn", record.Privacy.VPN,
		"proxy", record.Privacy.Proxy,
		"tor", record.Privacy.Tor,
		"relay", record.Privacy.Relay,
		"hosting", record.Privacy.Hosting,
		"resproxy", record.Privacy.ResidentialProxy,
		"privacy_service", record.Privacy.Service,
	}
	l.base.Info("gateway_decision", attrs...)
}
