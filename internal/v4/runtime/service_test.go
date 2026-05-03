package runtime

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"gw-ipinfo-nginx/internal/config"
	"gw-ipinfo-nginx/internal/localdisk"
	"gw-ipinfo-nginx/internal/storage"
	v4model "gw-ipinfo-nginx/internal/v4/model"
	"gw-ipinfo-nginx/internal/v4/repository"
)

func TestNormalizeStateForHostResetsStaleSnapshotState(t *testing.T) {
	host := v4model.SnapshotHost{
		Host: "game.freefun.live",
		Probe: v4model.ProbeSpec{
			Enabled: true,
		},
	}
	state := v4model.HostRuntimeState{
		ID:                  "game.freefun.live",
		Host:                "game.freefun.live",
		SnapshotVersion:     "2026-04-13T10:00:00Z",
		SnapshotFingerprint: "old-fingerprint",
		Mode:                v4model.ModeDegradedRedirect,
		RedirectURL:         "https://old.example.com",
		LastProbeTargets:    []string{"https://old.example.com"},
		LastProbeError:      "old error",
	}

	normalized := normalizeStateForHost(host, state, "2026-04-14T10:00:00Z", "new-fingerprint")
	if normalized.Mode != v4model.ModePassthrough {
		t.Fatalf("normalizeStateForHost() mode = %q, want %q", normalized.Mode, v4model.ModePassthrough)
	}
	if normalized.RedirectURL != "" {
		t.Fatalf("normalizeStateForHost() redirect_url = %q, want empty", normalized.RedirectURL)
	}
	if normalized.SnapshotVersion != "2026-04-14T10:00:00Z" {
		t.Fatalf("normalizeStateForHost() snapshot_version = %q", normalized.SnapshotVersion)
	}
	if normalized.SnapshotFingerprint != "new-fingerprint" {
		t.Fatalf("normalizeStateForHost() snapshot_fingerprint = %q", normalized.SnapshotFingerprint)
	}
}

func TestNormalizeStateForHostPreservesCurrentSnapshotState(t *testing.T) {
	host := v4model.SnapshotHost{
		Host: "spin.gamefun.live",
		Probe: v4model.ProbeSpec{
			Enabled: true,
		},
	}
	state := v4model.HostRuntimeState{
		ID:                  "spin.gamefun.live",
		Host:                "spin.gamefun.live",
		SnapshotVersion:     "2026-04-14T10:00:00Z",
		SnapshotFingerprint: "same-fingerprint",
		Mode:                v4model.ModeDegradedRedirect,
		RedirectURL:         "https://redirect.example.com",
		LastProbeTargets:    []string{"https://target.example.com"},
	}

	normalized := normalizeStateForHost(host, state, "2026-04-14T10:00:00Z", "same-fingerprint")
	if normalized.Mode != v4model.ModeDegradedRedirect {
		t.Fatalf("normalizeStateForHost() mode = %q, want %q", normalized.Mode, v4model.ModeDegradedRedirect)
	}
	if normalized.RedirectURL != "https://redirect.example.com" {
		t.Fatalf("normalizeStateForHost() redirect_url = %q", normalized.RedirectURL)
	}
}

func TestRedirectAccessTrackingEnabledForDirectRedirect(t *testing.T) {
	host := v4model.SnapshotHost{
		Host: "promo.example.com",
		Probe: v4model.ProbeSpec{
			Enabled:               true,
			DirectRedirectEnabled: true,
		},
	}
	state := v4model.HostRuntimeState{
		Host: "promo.example.com",
		Mode: v4model.ModePassthrough,
	}

	if !redirectAccessTrackingEnabled(host, state) {
		t.Fatal("redirectAccessTrackingEnabled() = false, want true for direct redirect")
	}
}

func TestApplyProbeUpdateClearsFaultDetailsAfterRecovered(t *testing.T) {
	repo, closeRepo := newLocalRuntimeStateRepository(t)
	defer closeRepo()

	host := "game.freefun.live"
	service := NewService(config.V4Config{}, config.RouteSetFileConfig{}, "", nil, nil, repo, nil, "test-instance", time.Now())
	service.snapshotVersion = "2026-04-14T10:00:00Z"
	service.fingerprint = "same-fingerprint"
	service.statesByHost[host] = v4model.HostRuntimeState{
		ID:                  host,
		Host:                host,
		SnapshotVersion:     service.snapshotVersion,
		SnapshotFingerprint: service.fingerprint,
		Mode:                v4model.ModeDegradedRedirect,
		FaultActive:         true,
		FaultCount:          1,
		SwitchSuccessCount:  1,
		RedirectURL:         "https://fallback.example.net/",
		LastProbeTargets:    []string{"https://apps.apple.com/app/old/id123"},
		LastFailedTargets:   []string{"https://apps.apple.com/app/old/id123"},
		LastProbeError:      "https://apps.apple.com/app/old/id123 returned unhealthy status 404",
		LastFaultReason:     "https://apps.apple.com/app/old/id123 returned unhealthy status 404",
		HealthyCount:        1,
	}

	state, changed, recovered, err := service.ApplyProbeUpdate(context.Background(), ProbeUpdate{
		Host:         host,
		Healthy:      true,
		SourceURL:    "https://game.freefun.live/",
		ProbeTargets: []string{"https://apps.apple.com/app/new/id456"},
		ProbeAt:      time.Now(),
		Spec: v4model.ProbeSpec{
			Enabled:          true,
			HealthyThreshold: 2,
		},
	})
	if err != nil {
		t.Fatalf("ApplyProbeUpdate() error = %v", err)
	}
	if !changed || !recovered {
		t.Fatalf("ApplyProbeUpdate() changed/recovered = %t/%t, want true/true", changed, recovered)
	}
	if state.Mode != v4model.ModePassthrough {
		t.Fatalf("state.Mode = %q, want %q", state.Mode, v4model.ModePassthrough)
	}
	if state.LastFaultReason != "" {
		t.Fatalf("state.LastFaultReason = %q, want empty", state.LastFaultReason)
	}
	if state.LastProbeError != "" {
		t.Fatalf("state.LastProbeError = %q, want empty", state.LastProbeError)
	}
	if len(state.LastFailedTargets) != 0 {
		t.Fatalf("state.LastFailedTargets = %#v, want empty", state.LastFailedTargets)
	}
	if state.FaultCount != 1 {
		t.Fatalf("state.FaultCount = %d, want historical count preserved", state.FaultCount)
	}
}

func newLocalRuntimeStateRepository(t *testing.T) (*repository.RuntimeStateRepository, func()) {
	t.Helper()
	store, err := localdisk.Open(filepath.Join(t.TempDir(), "runtime-states.db"))
	if err != nil {
		t.Fatalf("localdisk.Open() error = %v", err)
	}
	controller := storage.NewController(config.StorageConfig{
		LocalPath:          filepath.Join(t.TempDir(), "gw.db"),
		ReplayInterval:     time.Second,
		MongoProbeInterval: time.Second,
		ReplayBatchSize:    10,
		ReplayWorkers:      1,
	}, config.MongoConfig{}, store, nil)
	controller.SetMongoClient(nil)
	return repository.NewRuntimeStateRepository(controller), func() { _ = store.Close() }
}
