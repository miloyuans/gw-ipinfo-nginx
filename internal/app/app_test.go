package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"gw-ipinfo-nginx/internal/alerts"
	"gw-ipinfo-nginx/internal/audit"
	"gw-ipinfo-nginx/internal/blockpage"
	"gw-ipinfo-nginx/internal/config"
	"gw-ipinfo-nginx/internal/ipctx"
	"gw-ipinfo-nginx/internal/metrics"
	"gw-ipinfo-nginx/internal/policy"
	"gw-ipinfo-nginx/internal/proxy"
	"gw-ipinfo-nginx/internal/realip"
	"gw-ipinfo-nginx/internal/routing"
	"gw-ipinfo-nginx/internal/routesets"
	v4model "gw-ipinfo-nginx/internal/v4/model"
	v4runtime "gw-ipinfo-nginx/internal/v4/runtime"
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

func TestResolveLocalStoragePathUsesPodScopedFile(t *testing.T) {
	t.Setenv("POD_NAME", "gw-ipinfo-abc")

	got := resolveLocalStoragePath(filepath.Join(string(filepath.Separator), "data", "shared", "gw-ipinfo-nginx.db"))
	want := filepath.Join(string(filepath.Separator), "data", "shared", "gw-ipinfo-abc", "gw-ipinfo-nginx.db")
	if got != want {
		t.Fatalf("resolveLocalStoragePath() = %q, want %q", got, want)
	}
}

func TestResolveLocalStoragePathKeepsPathWhenPodNameMissing(t *testing.T) {
	t.Setenv("POD_NAME", "")

	got := resolveLocalStoragePath(filepath.Join(string(filepath.Separator), "data", "shared", "gw-ipinfo-nginx.db"))
	want := filepath.Join(string(filepath.Separator), "data", "shared", "gw-ipinfo-nginx.db")
	if got != want {
		t.Fatalf("resolveLocalStoragePath() = %q, want %q", got, want)
	}
}

func TestServeHTTPDefaultRouteSetUsesDefaultChainBeforeV4Fallback(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Route-Chain", "default")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer backend.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	realIPExtractor, err := realip.NewExtractor(config.RealIPConfig{
		TrustAllSources:      true,
		HeaderPriority:       []string{"CF-Connecting-IP"},
		UntrustedProxyAction: "use_remote_addr",
	})
	if err != nil {
		t.Fatalf("NewExtractor() error = %v", err)
	}
	policyEngine, err := policy.NewEngine(config.SecurityConfig{
		AcceptLanguage: config.AcceptLanguageConfig{RequireHeader: false},
	})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	proxyManager, err := proxy.NewManager([]config.ServiceConfig{
		{
			Name:              "default",
			MatchPathPrefixes: []string{"/"},
			TargetURL:         backend.URL,
			PreserveHost:      true,
		},
	}, config.PerformanceConfig{}, nil, logger)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	denyResponder, err := blockpage.NewResponder(config.DenyPageConfig{}, config.PerformanceConfig{}, logger)
	if err != nil {
		t.Fatalf("NewResponder() error = %v", err)
	}

	compiled := &routesets.Compiled{
		Enabled: true,
		SourceRulesByHost: map[string][]routesets.CompiledRule{
			"game.freefun.live": {
				{
					Kind:             routesets.KindDefault,
					ID:               "default:game.freefun.live/",
					SourceHost:       "game.freefun.live",
					SourcePathPrefix: "/",
				},
			},
		},
		AllowedHosts: map[string]struct{}{
			"game.freefun.live": {},
		},
	}
	handler := &GatewayHandler{
		cfg: &config.Config{
			Server: config.ServerConfig{DenyStatusCode: http.StatusForbidden},
			IPInfo: config.IPInfoConfig{Enabled: false},
			Security: config.SecurityConfig{
				AcceptLanguage: config.AcceptLanguageConfig{RequireHeader: false},
			},
			Logging: config.LoggingConfig{RedactQuery: true},
		},
		logger:          logger,
		auditor:         audit.New(logger),
		realIPExtractor: realIPExtractor,
		resolver: routing.NewResolver(config.RoutingConfig{
			DefaultService: "default",
			Services: []config.ServiceConfig{
				{
					Name:              "default",
					MatchPathPrefixes: []string{"/"},
					TargetURL:         backend.URL,
					PreserveHost:      true,
				},
			},
		}),
		routeRuntime:  routesets.NewRuntime(compiled, config.RouteSetsConfig{}, logger),
		policyEngine:  policyEngine,
		proxyManager:  proxyManager,
		denyResponder: denyResponder,
	}

	req := httptest.NewRequest(http.MethodGet, "http://game.freefun.live/login", nil)
	req.Host = "game.freefun.live"
	req.RemoteAddr = "8.8.8.8:12345"
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("ServeHTTP() status = %d, want %d", recorder.Code, http.StatusNoContent)
	}
	if got := recorder.Header().Get("X-Route-Chain"); got != "default" {
		t.Fatalf("ServeHTTP() X-Route-Chain = %q, want %q", got, "default")
	}
}

func TestV4DirectRedirectUsesConfiguredTargetPool(t *testing.T) {
	resolution := v4runtime.Resolution{
		Host: v4model.SnapshotHost{
			Host: "promo.example.com",
			Probe: v4model.ProbeSpec{
				Enabled:               true,
				DirectRedirectEnabled: true,
				RedirectURLs:          []string{"", "https://fallback.example.net/"},
			},
		},
		State: v4model.HostRuntimeState{
			Mode:        v4model.ModePassthrough,
			RedirectURL: "https://stale.example.net/",
		},
	}

	redirectURL := v4ActiveRedirectURL(resolution, "8.8.8.8")
	if redirectURL != "https://fallback.example.net/" {
		t.Fatalf("v4ActiveRedirectURL() = %q, want configured redirect URL", redirectURL)
	}
	if mode := v4ActiveRuntimeMode(resolution, redirectURL); mode != v4model.ModeDirectRedirect {
		t.Fatalf("v4ActiveRuntimeMode() = %q, want %q", mode, v4model.ModeDirectRedirect)
	}
}

func TestV4RedirectFallsBackToDegradedRuntimeState(t *testing.T) {
	resolution := v4runtime.Resolution{
		Host: v4model.SnapshotHost{
			Host: "promo.example.com",
			Probe: v4model.ProbeSpec{
				Enabled:      true,
				RedirectURLs: []string{"https://configured.example.net/"},
			},
		},
		State: v4model.HostRuntimeState{
			Mode:        v4model.ModeDegradedRedirect,
			RedirectURL: "https://healthy-failover.example.net/",
		},
	}

	redirectURL := v4ActiveRedirectURL(resolution, "8.8.8.8")
	if redirectURL != "https://healthy-failover.example.net/" {
		t.Fatalf("v4ActiveRedirectURL() = %q, want degraded runtime redirect URL", redirectURL)
	}
	if mode := v4ActiveRuntimeMode(resolution, redirectURL); mode != v4model.ModeDegradedRedirect {
		t.Fatalf("v4ActiveRuntimeMode() = %q, want %q", mode, v4model.ModeDegradedRedirect)
	}
}
