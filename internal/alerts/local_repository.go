package alerts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"gw-ipinfo-nginx/internal/localdisk"

	bolt "go.etcd.io/bbolt"
)

type dedupeRecord struct {
	ExpiresAt time.Time `json:"expires_at"`
}

type LocalRepository struct {
	store *localdisk.Store
}

func NewLocalRepository(store *localdisk.Store) *LocalRepository {
	return &LocalRepository{store: store}
}

func (r *LocalRepository) Enqueue(ctx context.Context, messageType string, payload Payload, dedupeWindow time.Duration) (bool, error) {
	now := time.Now().UTC()
	key := DedupeKey(payload, dedupeWindow)
	dedupeKey := "alert_dedupe:" + key
	message := OutboxMessage{
		ID:            newMessageID(),
		Type:          messageType,
		NotifyType:    payload.NotifyType,
		Severity:      payload.Severity,
		Status:        StatusPending,
		DedupeKey:     key,
		Payload:       payload,
		NextAttemptAt: now,
		NextRetryAt:   now,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	returnValue := false
	err := r.store.Update(ctx, func(tx *bolt.Tx) error {
		metaBucket := tx.Bucket([]byte(localdisk.BucketMetadata))
		outboxBucket := tx.Bucket([]byte(localdisk.BucketAlertsOutbox))
		dirtyBucket := tx.Bucket([]byte(localdisk.BucketAlertsDirty))

		if raw := metaBucket.Get([]byte(dedupeKey)); raw != nil {
			var existing dedupeRecord
			if err := json.Unmarshal(raw, &existing); err == nil && existing.ExpiresAt.After(now) {
				returnValue = false
				return nil
			}
		}

		dedupeRaw, err := json.Marshal(dedupeRecord{ExpiresAt: now.Add(dedupeWindow)})
		if err != nil {
			return err
		}
		messageRaw, err := json.Marshal(message)
		if err != nil {
			return err
		}
		if err := metaBucket.Put([]byte(dedupeKey), dedupeRaw); err != nil {
			return err
		}
		if err := outboxBucket.Put([]byte(message.ID), messageRaw); err != nil {
			return err
		}
		if err := dirtyBucket.Put([]byte(message.ID), []byte(now.Format(time.RFC3339Nano))); err != nil {
			return err
		}
		returnValue = true
		return nil
	})
	return returnValue, err
}

func (r *LocalRepository) Claim(ctx context.Context, workerID string, batchSize, maxAttempts int, lease time.Duration) ([]OutboxMessage, error) {
	now := time.Now().UTC()
	messages := make([]OutboxMessage, 0, batchSize)
	err := r.store.Update(ctx, func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(localdisk.BucketAlertsOutbox))
		dirty := tx.Bucket([]byte(localdisk.BucketAlertsDirty))
		cursor := bucket.Cursor()
		for key, value := cursor.First(); key != nil && len(messages) < batchSize; key, value = cursor.Next() {
			var message OutboxMessage
			if err := json.Unmarshal(value, &message); err != nil {
				continue
			}
			if message.Status == StatusSent || message.Status == StatusDead {
				continue
			}
			if message.Attempts >= maxAttempts {
				continue
			}
			if message.NextAttemptAt.After(now) {
				continue
			}
			if message.LeaseExpiresAt != nil && message.LeaseExpiresAt.After(now) {
				continue
			}
			leaseUntil := now.Add(lease)
			message.Status = StatusProcessing
			message.ClaimedBy = workerID
			message.LeaseExpiresAt = &leaseUntil
			message.UpdatedAt = now
			raw, err := json.Marshal(message)
			if err != nil {
				return err
			}
			if err := bucket.Put(key, raw); err != nil {
				return err
			}
			if err := dirty.Put(key, []byte(now.Format(time.RFC3339Nano))); err != nil {
				return err
			}
			messages = append(messages, message)
		}
		return nil
	})
	return messages, err
}

func (r *LocalRepository) MarkSent(ctx context.Context, id string) error {
	return r.store.DeleteWithDirty(ctx, localdisk.BucketAlertsOutbox, localdisk.BucketAlertsDirty, id)
}

func (r *LocalRepository) MarkRetry(ctx context.Context, id string, attempts int, nextAttempt time.Time, lastError string, dead bool) error {
	now := time.Now().UTC()
	return r.store.Update(ctx, func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(localdisk.BucketAlertsOutbox))
		dirty := tx.Bucket([]byte(localdisk.BucketAlertsDirty))
		raw := bucket.Get([]byte(id))
		if raw == nil {
			return localdisk.ErrNotFound
		}
		var message OutboxMessage
		if err := json.Unmarshal(raw, &message); err != nil {
			return err
		}
		message.Attempts = attempts
		message.RetryCount = attempts
		message.NextAttemptAt = nextAttempt
		message.NextRetryAt = nextAttempt
		message.LastError = lastError
		message.UpdatedAt = now
		message.LeaseExpiresAt = nil
		message.Status = StatusPending
		if dead {
			message.Status = StatusDead
		}
		updated, err := json.Marshal(message)
		if err != nil {
			return err
		}
		if err := bucket.Put([]byte(id), updated); err != nil {
			return err
		}
		return dirty.Put([]byte(id), []byte(now.Format(time.RFC3339Nano)))
	})
}

func (r *LocalRepository) Get(ctx context.Context, id string) (OutboxMessage, bool, error) {
	var message OutboxMessage
	err := r.store.GetJSON(ctx, localdisk.BucketAlertsOutbox, id, &message)
	if err == nil {
		return message, true, nil
	}
	if errors.Is(err, localdisk.ErrNotFound) {
		return OutboxMessage{}, false, nil
	}
	return OutboxMessage{}, false, err
}

func (r *LocalRepository) DirtyKeys(ctx context.Context, limit int) ([]string, error) {
	return r.store.DirtyKeys(ctx, localdisk.BucketAlertsDirty, limit)
}

func (r *LocalRepository) Clear(ctx context.Context, id string) error {
	return r.store.DeleteWithDirty(ctx, localdisk.BucketAlertsOutbox, localdisk.BucketAlertsDirty, id)
}

func (r *LocalRepository) Import(ctx context.Context, message OutboxMessage) error {
	if message.ID == "" {
		return fmt.Errorf("local import missing id")
	}
	return r.store.PutJSONDirty(ctx, localdisk.BucketAlertsOutbox, localdisk.BucketAlertsDirty, message.ID, message)
}
