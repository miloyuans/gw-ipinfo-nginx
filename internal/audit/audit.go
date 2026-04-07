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
		"client_ip", record.ClientIP,
		"service_name", record.ServiceName,
		"upstream_url", record.UpstreamURL,
		"method", record.Method,
		"path", record.Path,
		"allowed", record.Allowed,
		"result", record.Result,
		"reason_code", record.ReasonCode,
		"cache_source", record.CacheSource,
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
