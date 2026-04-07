package alerts

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"gw-ipinfo-nginx/internal/config"
	"gw-ipinfo-nginx/internal/localdisk"
	"gw-ipinfo-nginx/internal/storage"
)

func TestResilientRepositoryFallsBackToLocal(t *testing.T) {
	store, err := localdisk.Open(filepath.Join(t.TempDir(), "alerts.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	cfg := &config.Config{}
	cfg.Cache.MongoCollections.AlertOutbox = "alerts_outbox"
	cfg.Cache.MongoCollections.AlertDedupe = "alerts_dedupe"
	cfg.Alerts.Dedupe.Window = time.Minute
	controller := storage.NewController(config.StorageConfig{
		LocalPath:          filepath.Join(t.TempDir(), "gw.db"),
		ReplayInterval:     time.Second,
		MongoProbeInterval: time.Second,
		ReplayBatchSize:    10,
		ReplayWorkers:      1,
	}, config.MongoConfig{}, store, nil)
	controller.SetMongoClient(nil)

	repo := NewResilientRepository(cfg, controller, nil)
	payload := Payload{
		Type:        "allowed_with_risk",
		NotifyType:  "allowed_with_risk",
		ClientIP:    "1.1.1.1",
		ServiceName: "default",
		Reason:      "allow_privacy_vpn",
		Timestamp:   time.Now().UTC(),
	}
	enqueued, err := repo.Enqueue(context.Background(), payload.Type, payload, time.Minute)
	if err != nil || !enqueued {
		t.Fatalf("Enqueue() = (%t, %v), want queued locally", enqueued, err)
	}

	messages, err := repo.Claim(context.Background(), "worker-1", 10, 3, time.Minute)
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	if len(messages) != 1 {
		t.Fatalf("Claim() len = %d, want 1", len(messages))
	}
	if err := repo.MarkSent(context.Background(), messages[0].ID); err != nil {
		t.Fatalf("MarkSent() error = %v", err)
	}
}
