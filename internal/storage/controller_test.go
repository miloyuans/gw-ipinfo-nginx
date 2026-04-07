package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"gw-ipinfo-nginx/internal/config"
	"gw-ipinfo-nginx/internal/localdisk"
	mongostore "gw-ipinfo-nginx/internal/mongo"
)

type fakeReplayer struct {
	called int
}

func (f *fakeReplayer) Name() string { return "fake" }

func (f *fakeReplayer) Replay(_ context.Context, _ *mongostore.Client, _ int) error {
	f.called++
	return nil
}

func TestControllerHandleMongoErrorAndRecoverReplay(t *testing.T) {
	store, err := localdisk.Open(filepath.Join(t.TempDir(), "storage.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	controller := NewController(config.StorageConfig{
		LocalPath:          filepath.Join(t.TempDir(), "gw.db"),
		ReplayInterval:     time.Second,
		MongoProbeInterval: time.Second,
		ReplayBatchSize:    10,
		ReplayWorkers:      1,
	}, config.MongoConfig{
		ConnectTimeout:   time.Second,
		OperationTimeout: time.Second,
	}, store, nil)

	replayer := &fakeReplayer{}
	controller.RegisterReplayer(replayer)
	controller.HandleMongoError(context.DeadlineExceeded)
	if mode := controller.Mode(); mode != ModeLocal {
		t.Fatalf("Mode() after degrade = %s, want %s", mode, ModeLocal)
	}

	controller.connector = func(ctx context.Context, cfg config.MongoConfig) (*mongostore.Client, error) {
		return &mongostore.Client{}, nil
	}
	controller.ping = func(ctx context.Context, client *mongostore.Client) error { return nil }

	if err := controller.recoverAndReplay(context.Background()); err != nil {
		t.Fatalf("recoverAndReplay() error = %v", err)
	}
	if mode := controller.Mode(); mode != ModeHybrid {
		t.Fatalf("Mode() after recovery = %s, want %s", mode, ModeHybrid)
	}
	if replayer.called != 1 {
		t.Fatalf("Replay() called %d times, want 1", replayer.called)
	}
}
