package alerts

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"gw-ipinfo-nginx/internal/config"
	"gw-ipinfo-nginx/internal/localdisk"
	mongostore "gw-ipinfo-nginx/internal/mongo"
	"gw-ipinfo-nginx/internal/storage"
)

type ResilientRepository struct {
	cfg        *config.Config
	controller *storage.Controller
	logger     *slog.Logger
	local      *LocalRepository
	mu         sync.Mutex
	mongo      *Repository
}

func NewResilientRepository(cfg *config.Config, controller *storage.Controller, logger *slog.Logger) *ResilientRepository {
	repo := &ResilientRepository{
		cfg:        cfg,
		controller: controller,
		logger:     logger,
		local:      NewLocalRepository(controller.Local()),
	}
	controller.RegisterReplayer(repo)
	return repo
}

func (r *ResilientRepository) Name() string {
	return "alerts_outbox"
}

func (r *ResilientRepository) Enqueue(ctx context.Context, messageType string, payload Payload, dedupeWindow time.Duration) (bool, error) {
	if mongoRepo := r.mongoRepo(); mongoRepo != nil && r.controller.Mode() != storage.ModeLocal {
		enqueued, err := mongoRepo.Enqueue(ctx, messageType, payload, dedupeWindow)
		if err == nil {
			return enqueued, nil
		}
		r.controller.HandleMongoError(err)
	}
	return r.local.Enqueue(ctx, messageType, payload, dedupeWindow)
}

func (r *ResilientRepository) Claim(ctx context.Context, workerID string, batchSize, maxAttempts int, lease time.Duration) ([]OutboxMessage, error) {
	if mongoRepo := r.mongoRepo(); mongoRepo != nil && r.controller.Mode() != storage.ModeLocal {
		messages, err := mongoRepo.Claim(ctx, workerID, batchSize, maxAttempts, lease)
		if err == nil {
			return messages, nil
		}
		r.controller.HandleMongoError(err)
	}
	return r.local.Claim(ctx, workerID, batchSize, maxAttempts, lease)
}

func (r *ResilientRepository) MarkSent(ctx context.Context, id string) error {
	if mongoRepo := r.mongoRepo(); mongoRepo != nil && r.controller.Mode() != storage.ModeLocal {
		if err := mongoRepo.MarkSent(ctx, id); err == nil {
			return nil
		} else {
			r.controller.HandleMongoError(err)
		}
	}
	return r.local.MarkSent(ctx, id)
}

func (r *ResilientRepository) MarkRetry(ctx context.Context, id string, attempts int, nextAttempt time.Time, lastError string, dead bool) error {
	if mongoRepo := r.mongoRepo(); mongoRepo != nil && r.controller.Mode() != storage.ModeLocal {
		if err := mongoRepo.MarkRetry(ctx, id, attempts, nextAttempt, lastError, dead); err == nil {
			return nil
		} else {
			r.controller.HandleMongoError(err)
		}
	}
	return r.local.MarkRetry(ctx, id, attempts, nextAttempt, lastError, dead)
}

func (r *ResilientRepository) Replay(ctx context.Context, client *mongostore.Client, batchSize int) (int, error) {
	keys, err := r.local.DirtyKeys(ctx, batchSize)
	if err != nil {
		return 0, err
	}

	if len(keys) == 0 {
		return 0, nil
	}

	mongoRepo := NewRepository(client, r.cfg.Cache.MongoCollections.AlertOutbox, r.cfg.Cache.MongoCollections.AlertDedupe)
	if err := mongoRepo.InitIndexes(ctx); err != nil {
		return 0, err
	}

	replayed := 0

	for _, key := range keys {
		message, found, err := r.local.Get(ctx, key)
		if err != nil {
			return replayed, err
		}

		if !found {
			_ = r.controller.Local().ClearDirty(ctx, localdisk.BucketAlertsDirty, key)
			continue
		}

		if err := mongoRepo.Import(ctx, message, r.cfg.Alerts.Dedupe.Window); err != nil {
			return replayed, err
		}

		if err := r.local.Clear(ctx, key); err != nil && !errors.Is(err, localdisk.ErrNotFound) {
			return replayed, err
		}

		if err := r.controller.Local().ClearDirty(ctx, localdisk.BucketAlertsDirty, key); err != nil {
			return replayed, err
		}

		replayed++
	}

	return replayed, nil
}

func (r *ResilientRepository) mongoRepo() *Repository {
	client := r.controller.Client()
	if client == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.mongo == nil || r.mongo.client != client {
		r.mongo = NewRepository(client, r.cfg.Cache.MongoCollections.AlertOutbox, r.cfg.Cache.MongoCollections.AlertDedupe)
		if err := r.mongo.InitIndexes(context.Background()); err != nil && r.logger != nil {
			r.logger.Warn("alerts_init_indexes_failed", "event", "alerts_init_indexes_failed", "error", err)
		}
	}
	return r.mongo
}
