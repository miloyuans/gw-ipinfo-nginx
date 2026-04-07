package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"

	"gw-ipinfo-nginx/internal/alerts"
	"gw-ipinfo-nginx/internal/config"
	"gw-ipinfo-nginx/internal/ipctx"
	"gw-ipinfo-nginx/internal/metrics"
	"gw-ipinfo-nginx/internal/policy"
)

type failingAlertRepo struct{}

func (f failingAlertRepo) Enqueue(ctx context.Context, messageType string, payload alerts.Payload, dedupeWindow time.Duration) (bool, error) {
	return false, errors.New("boom")
}

func (f failingAlertRepo) Claim(ctx context.Context, workerID string, batchSize, maxAttempts int, lease time.Duration) ([]alerts.OutboxMessage, error) {
	return nil, nil
}

func (f failingAlertRepo) MarkSent(ctx context.Context, id string) error { return nil }

func (f failingAlertRepo) MarkRetry(ctx context.Context, id string, attempts int, nextAttempt time.Time, lastError string, dead bool) error {
	return nil
}

func TestEnqueueAlertFailureDoesNotPanic(t *testing.T) {
	handler := &GatewayHandler{
		cfg: &config.Config{
			Alerts: config.AlertsConfig{
				Telegram: config.TelegramConfig{
					Enabled:          true,
					MaskQuery:        true,
					IncludeUserAgent: true,
				},
				Dedupe: config.DedupeConfig{Window: time.Minute},
			},
		},
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		metrics:  metrics.NewGatewayMetrics(metrics.NewRegistry()),
		alertRepo: failingAlertRepo{},
	}

	req := httptest.NewRequest("GET", "http://example.com/login?token=secret", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	handler.enqueueAlert(req, "req-1", "default", "1.1.1.1", ipctx.CacheSourceL1, policy.Decision{
		Allowed:   true,
		Result:    "allow_with_risk",
		Reason:    "allow_privacy_vpn",
		AlertType: "allowed_with_risk",
	}, &ipctx.Context{CountryCode: "US"})
}
