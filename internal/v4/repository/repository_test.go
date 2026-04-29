package repository

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"gw-ipinfo-nginx/internal/config"
	"gw-ipinfo-nginx/internal/localdisk"
	"gw-ipinfo-nginx/internal/storage"
	v4model "gw-ipinfo-nginx/internal/v4/model"
)

func TestSelectSnapshotHostsUsesSnapshotVersionOnly(t *testing.T) {
	snapshot := v4model.Snapshot{Version: "2026-04-14T10:00:00Z"}
	hostsMap := map[string]v4model.SnapshotHost{
		"game.freefun.live": {
			Host:       "game.freefun.live",
			SnapshotID: "2026-04-14T10:00:00Z",
		},
		"spin.gamefun.live": {
			Host:       "spin.gamefun.live",
			SnapshotID: "2026-04-13T10:00:00Z",
		},
	}

	hosts := selectSnapshotHosts(snapshot, hostsMap)
	if len(hosts) != 1 {
		t.Fatalf("selectSnapshotHosts() len = %d, want 1", len(hosts))
	}
	if hosts[0].Host != "game.freefun.live" {
		t.Fatalf("selectSnapshotHosts() host = %q, want %q", hosts[0].Host, "game.freefun.live")
	}
}

func TestValidateLoadedSnapshotRejectsFingerprintMismatch(t *testing.T) {
	repo := &SnapshotRepository{}
	hosts := []v4model.SnapshotHost{
		{
			Host:             "game.freefun.live",
			BackendService:   "luodiye",
			BackendHost:      "game.freefun.live",
			IPEnrichmentMode: "full",
			Probe: v4model.ProbeSpec{
				Enabled: true,
				Mode:    "local_js",
			},
			SecurityChecksEnabled: true,
		},
	}
	snapshot := v4model.Snapshot{
		ID:          "last_good",
		Version:     "2026-04-14T10:00:00Z",
		Fingerprint: "stale-fingerprint",
		HostCount:   1,
	}

	valid, err := repo.validateLoadedSnapshot("mongo", snapshot, hosts)
	if valid {
		t.Fatalf("validateLoadedSnapshot() valid = true, want false")
	}
	if err == nil {
		t.Fatal("validateLoadedSnapshot() error = nil, want mismatch error")
	}
}

func TestEventNotificationSuppressionStartsAfterSent(t *testing.T) {
	repo, closeRepo := newLocalEventRepository(t)
	defer closeRepo()

	ctx := context.Background()
	first, err := repo.Emit(ctx, v4model.Event{
		Type:        v4model.EventTrafficSwitchedToRedirect,
		Host:        "game.example.com",
		Fingerprint: "traffic_switched_to_redirect:game.example.com:https://fallback.example.com/",
		Level:       "warning",
		SilentUntil: time.Now().UTC().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("Emit(first) error = %v", err)
	}
	allowed, reason, err := repo.ShouldNotify(ctx, first, 15*time.Minute)
	if err != nil || !allowed || reason != "" {
		t.Fatalf("ShouldNotify(first) = (%t, %q, %v), want allowed", allowed, reason, err)
	}

	second, err := repo.Emit(ctx, v4model.Event{
		Type:        v4model.EventTrafficSwitchedToRedirect,
		Host:        "game.example.com",
		Fingerprint: first.Fingerprint,
		Level:       "warning",
		SilentUntil: time.Now().UTC().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("Emit(second) error = %v", err)
	}
	allowed, reason, err = repo.ShouldNotify(ctx, second, 15*time.Minute)
	if err != nil || !allowed || reason != "" {
		t.Fatalf("ShouldNotify(second before sent) = (%t, %q, %v), want allowed", allowed, reason, err)
	}

	if err := repo.MarkNotificationSent(ctx, first); err != nil {
		t.Fatalf("MarkNotificationSent() error = %v", err)
	}
	allowed, reason, err = repo.ShouldNotify(ctx, second, 15*time.Minute)
	if err != nil || allowed || reason == "" {
		t.Fatalf("ShouldNotify(second after sent) = (%t, %q, %v), want suppressed", allowed, reason, err)
	}

	events, err := repo.ListRecent(ctx, 10)
	if err != nil {
		t.Fatalf("ListRecent() error = %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("ListRecent() len = %d, want 2", len(events))
	}
}

func TestEventNotificationFailureDoesNotSuppressNextEvent(t *testing.T) {
	repo, closeRepo := newLocalEventRepository(t)
	defer closeRepo()

	ctx := context.Background()
	event, err := repo.Emit(ctx, v4model.Event{
		Type:        v4model.EventTrafficSwitchedToRedirect,
		Host:        "game.example.com",
		Fingerprint: "traffic_switched_to_redirect:game.example.com:https://fallback.example.com/",
		Level:       "warning",
		SilentUntil: time.Now().UTC().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("Emit(event) error = %v", err)
	}
	if err := repo.MarkNotificationFailed(ctx, event, errors.New("telegram unavailable")); err != nil {
		t.Fatalf("MarkNotificationFailed() error = %v", err)
	}

	next, err := repo.Emit(ctx, v4model.Event{
		Type:        v4model.EventTrafficSwitchedToRedirect,
		Host:        "game.example.com",
		Fingerprint: event.Fingerprint,
		Level:       "warning",
		SilentUntil: time.Now().UTC().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("Emit(next) error = %v", err)
	}
	allowed, reason, err := repo.ShouldNotify(ctx, next, 15*time.Minute)
	if err != nil || !allowed || reason != "" {
		t.Fatalf("ShouldNotify(next after failed send) = (%t, %q, %v), want allowed", allowed, reason, err)
	}
}

func newLocalEventRepository(t *testing.T) (*EventRepository, func()) {
	t.Helper()
	store, err := localdisk.Open(filepath.Join(t.TempDir(), "v4-events.db"))
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
	return NewEventRepository(controller, nil), func() { _ = store.Close() }
}
