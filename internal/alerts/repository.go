package alerts

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	mongostore "gw-ipinfo-nginx/internal/mongo"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	StatusPending    = "pending"
	StatusProcessing = "processing"
	StatusSent       = "sent"
	StatusDead       = "dead"
)

type QueueRepository interface {
	Enqueue(ctx context.Context, messageType string, payload Payload, dedupeWindow time.Duration) (bool, error)
	Claim(ctx context.Context, workerID string, batchSize, maxAttempts int, lease time.Duration) ([]OutboxMessage, error)
	MarkSent(ctx context.Context, id string) error
	MarkRetry(ctx context.Context, id string, attempts int, nextAttempt time.Time, lastError string, dead bool) error
}

type OutboxMessage struct {
	ID             string     `bson:"_id" json:"id"`
	Type           string     `bson:"type" json:"type"`
	NotifyType     string     `bson:"notify_type" json:"notify_type"`
	Severity       string     `bson:"severity" json:"severity"`
	Status         string     `bson:"status" json:"status"`
	DedupeKey      string     `bson:"dedupe_key" json:"dedupe_key"`
	Payload        Payload    `bson:"payload" json:"payload"`
	Attempts       int        `bson:"attempts" json:"attempts"`
	RetryCount     int        `bson:"retry_count" json:"retry_count"`
	NextAttemptAt  time.Time  `bson:"next_attempt_at" json:"next_attempt_at"`
	NextRetryAt    time.Time  `bson:"next_retry_at" json:"next_retry_at"`
	LeaseExpiresAt *time.Time `bson:"lease_expires_at,omitempty" json:"lease_expires_at,omitempty"`
	ClaimedBy      string     `bson:"claimed_by,omitempty" json:"claimed_by,omitempty"`
	LastError      string     `bson:"last_error,omitempty" json:"last_error,omitempty"`
	CreatedAt      time.Time  `bson:"created_at" json:"created_at"`
	UpdatedAt      time.Time  `bson:"updated_at" json:"updated_at"`
	SentAt         *time.Time `bson:"sent_at,omitempty" json:"sent_at,omitempty"`
}

type Repository struct {
	client *mongostore.Client
	outbox *mongo.Collection
	dedupe *mongo.Collection
}

func NewRepository(client *mongostore.Client, outboxCollection, dedupeCollection string) *Repository {
	return &Repository{
		client: client,
		outbox: client.Database().Collection(outboxCollection),
		dedupe: client.Database().Collection(dedupeCollection),
	}
}

func (r *Repository) InitIndexes(ctx context.Context) error {
	child, cancel := r.client.WithTimeout(ctx)
	defer cancel()

	outboxIndexes := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "status", Value: 1}, {Key: "next_attempt_at", Value: 1}, {Key: "lease_expires_at", Value: 1}},
			Options: options.Index().SetName("claim_scan"),
		},
		{
			Keys:    bson.D{{Key: "dedupe_key", Value: 1}},
			Options: options.Index().SetName("dedupe_lookup"),
		},
	}
	if _, err := r.outbox.Indexes().CreateMany(child, outboxIndexes); err != nil {
		return fmt.Errorf("create outbox indexes: %w", err)
	}

	dedupeIndexes := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "expires_at", Value: 1}},
			Options: options.Index().SetExpireAfterSeconds(0).SetName("ttl_dedupe"),
		},
	}
	if _, err := r.dedupe.Indexes().CreateMany(child, dedupeIndexes); err != nil {
		return fmt.Errorf("create dedupe indexes: %w", err)
	}
	return nil
}

func (r *Repository) Enqueue(ctx context.Context, messageType string, payload Payload, dedupeWindow time.Duration) (bool, error) {
	now := time.Now().UTC()
	key := DedupeKey(payload, dedupeWindow)

	child, cancel := r.client.WithTimeout(ctx)
	defer cancel()

	_, err := r.dedupe.InsertOne(child, bson.M{
		"_id":        key,
		"type":       messageType,
		"expires_at": now.Add(dedupeWindow),
		"created_at": now,
	})
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return false, nil
		}
		return false, fmt.Errorf("insert dedupe key: %w", err)
	}

	message := OutboxMessage{
		ID:            newMessageID(),
		Type:          messageType,
		NotifyType:    payload.NotifyType,
		Severity:      payload.Severity,
		Status:        StatusPending,
		DedupeKey:     key,
		Payload:       payload,
		Attempts:      0,
		RetryCount:    0,
		NextAttemptAt: now,
		NextRetryAt:   now,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if _, err := r.outbox.InsertOne(child, message); err != nil {
		_, _ = r.dedupe.DeleteOne(child, bson.M{"_id": key})
		return false, fmt.Errorf("insert outbox message: %w", err)
	}
	return true, nil
}

func (r *Repository) Claim(ctx context.Context, workerID string, batchSize, maxAttempts int, lease time.Duration) ([]OutboxMessage, error) {
	now := time.Now().UTC()
	messages := make([]OutboxMessage, 0, batchSize)

	for idx := 0; idx < batchSize; idx++ {
		child, cancel := r.client.WithTimeout(ctx)
		var message OutboxMessage
		err := r.outbox.FindOneAndUpdate(
			child,
			bson.M{
				"status": bson.M{"$in": bson.A{StatusPending, StatusProcessing}},
				"next_attempt_at": bson.M{"$lte": now},
				"attempts": bson.M{"$lt": maxAttempts},
				"$or": bson.A{
					bson.M{"lease_expires_at": bson.M{"$exists": false}},
					bson.M{"lease_expires_at": nil},
					bson.M{"lease_expires_at": bson.M{"$lte": now}},
				},
			},
			bson.M{
				"$set": bson.M{
					"status":           StatusProcessing,
					"claimed_by":       workerID,
					"lease_expires_at": now.Add(lease),
					"updated_at":       now,
				},
			},
			options.FindOneAndUpdate().SetReturnDocument(options.After).SetSort(bson.D{{Key: "next_attempt_at", Value: 1}, {Key: "created_at", Value: 1}}),
		).Decode(&message)
		cancel()
		if err != nil {
			if errors.Is(err, mongo.ErrNoDocuments) {
				break
			}
			return nil, fmt.Errorf("claim outbox message: %w", err)
		}
		messages = append(messages, message)
	}

	return messages, nil
}

func (r *Repository) MarkSent(ctx context.Context, id string) error {
	now := time.Now().UTC()
	child, cancel := r.client.WithTimeout(ctx)
	defer cancel()

	_, err := r.outbox.UpdateByID(child, id, bson.M{
		"$set": bson.M{
			"status":           StatusSent,
			"sent_at":          now,
			"updated_at":       now,
			"next_attempt_at":  now,
			"next_retry_at":    now,
			"lease_expires_at": nil,
		},
	})
	if err != nil {
		return fmt.Errorf("mark outbox sent: %w", err)
	}
	return nil
}

func (r *Repository) MarkRetry(ctx context.Context, id string, attempts int, nextAttempt time.Time, lastError string, dead bool) error {
	now := time.Now().UTC()
	status := StatusPending
	if dead {
		status = StatusDead
	}

	child, cancel := r.client.WithTimeout(ctx)
	defer cancel()

	_, err := r.outbox.UpdateByID(child, id, bson.M{
		"$set": bson.M{
			"status":           status,
			"attempts":         attempts,
			"retry_count":      attempts,
			"next_attempt_at":  nextAttempt,
			"next_retry_at":    nextAttempt,
			"last_error":       lastError,
			"updated_at":       now,
			"lease_expires_at": nil,
		},
	})
	if err != nil {
		return fmt.Errorf("mark outbox retry: %w", err)
	}
	return nil
}

func (r *Repository) Import(ctx context.Context, message OutboxMessage, dedupeWindow time.Duration) error {
	now := time.Now().UTC()
	child, cancel := r.client.WithTimeout(ctx)
	defer cancel()

	_, err := r.dedupe.UpdateByID(child, message.DedupeKey, bson.M{
		"$set": bson.M{
			"type":       message.Type,
			"expires_at": now.Add(dedupeWindow),
			"created_at": message.CreatedAt,
		},
	}, options.Update().SetUpsert(true))
	if err != nil {
		return fmt.Errorf("upsert alert dedupe: %w", err)
	}

	_, err = r.outbox.UpdateByID(child, message.ID, bson.M{
		"$set": bson.M{
			"type":             message.Type,
			"notify_type":      message.NotifyType,
			"severity":         message.Severity,
			"status":           message.Status,
			"dedupe_key":       message.DedupeKey,
			"payload":          message.Payload,
			"attempts":         message.Attempts,
			"retry_count":      message.RetryCount,
			"next_attempt_at":  message.NextAttemptAt,
			"next_retry_at":    message.NextRetryAt,
			"lease_expires_at": message.LeaseExpiresAt,
			"claimed_by":       message.ClaimedBy,
			"last_error":       message.LastError,
			"created_at":       message.CreatedAt,
			"updated_at":       message.UpdatedAt,
			"sent_at":          message.SentAt,
		},
	}, options.Update().SetUpsert(true))
	if err != nil {
		return fmt.Errorf("import outbox message: %w", err)
	}
	return nil
}

func newMessageID() string {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Sprintf("msg-%d", time.Now().UTC().UnixNano())
	}
	return hex.EncodeToString(raw[:])
}
