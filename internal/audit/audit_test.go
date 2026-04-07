package audit

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"gw-ipinfo-nginx/internal/ipctx"
	"gw-ipinfo-nginx/internal/model"
)

func TestLogDecisionIncludesEnhancedFields(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	auditor := New(logger)

	auditor.LogDecision(model.AuditRecord{
		RequestID:            "req-1",
		ClientIP:             "1.1.1.1",
		ServiceName:          "default",
		Host:                 "example.com",
		Path:                 "/login",
		RequestURL:           "/login",
		ReasonCode:           "allow_geo_privacy_clean",
		ShortCircuitHit:      true,
		ShortCircuitSource:   "l1",
		ShortCircuitDecision: "allow",
		IPInfoLookupAction:   "cache_hit_l1",
		DataSourceMode:       "hybrid",
		Privacy:              ipctx.PrivacyFlags{VPN: true},
	})

	output := buf.String()
	for _, field := range []string{"host", "request_url", "short_circuit_hit", "short_circuit_source", "ipinfo_lookup_action", "data_source_mode", "reason_code"} {
		if !strings.Contains(output, field) {
			t.Fatalf("log output missing %q: %s", field, output)
		}
	}
}
