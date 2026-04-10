package alerts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	mongostore "gw-ipinfo-nginx/internal/mongo"
	"gw-ipinfo-nginx/internal/storage"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const commandBotLeaseCollection = "telegram_command_bot_state"

type commandBotLease struct {
	LeaseName string    `json:"lease_name" bson:"_id"`
	OwnerID   string    `json:"owner_id" bson:"owner_id"`
	Offset    int       `json:"offset" bson:"offset"`
	UpdatedAt time.Time `json:"updated_at" bson:"updated_at"`
	ExpiresAt time.Time `json:"expires_at" bson:"expires_at"`
}

type commandBotStateStore struct {
	controller *storage.Controller
	filePath   string
	leaseName  string
}

func newCommandBotStateStore(controller *storage.Controller, filePath, leaseName string) *commandBotStateStore {
	return &commandBotStateStore{
		controller: controller,
		filePath:   filepath.Clean(filePath),
		leaseName:  leaseName,
	}
}

func (s *commandBotStateStore) TryAcquire(ctx context.Context, ownerID string, now time.Time, ttl time.Duration) (commandBotLease, bool, error) {
	if client := s.mongoClient(); client != nil {
		return s.tryAcquireMongo(ctx, client, ownerID, now, ttl)
	}
	return s.tryAcquireFile(ownerID, now, ttl)
}

func (s *commandBotStateStore) Refresh(ctx context.Context, ownerID string, offset int, now time.Time, ttl time.Duration) (bool, error) {
	if client := s.mongoClient(); client != nil {
		return s.refreshMongo(ctx, client, ownerID, offset, now, ttl)
	}
	return s.refreshFile(ownerID, offset, now, ttl)
}

func (s *commandBotStateStore) Release(ctx context.Context, ownerID string) error {
	if client := s.mongoClient(); client != nil {
		return s.releaseMongo(ctx, client, ownerID)
	}
	return s.releaseFile(ownerID)
}

func (s *commandBotStateStore) mongoClient() *mongostore.Client {
	if s == nil || s.controller == nil || s.controller.Mode() == storage.ModeLocal {
		return nil
	}
	return s.controller.Client()
}

func (s *commandBotStateStore) tryAcquireMongo(ctx context.Context, client *mongostore.Client, ownerID string, now time.Time, ttl time.Duration) (commandBotLease, bool, error) {
	collection := client.Database().Collection(commandBotLeaseCollection)
	child, cancel := client.WithTimeout(ctx)
	defer cancel()

	filter := bson.M{
		"_id": s.leaseName,
		"$or": []bson.M{
			{"owner_id": ownerID},
			{"expires_at": bson.M{"$lte": now}},
		},
	}
	update := bson.M{
		"$set": bson.M{
			"owner_id":   ownerID,
			"updated_at": now,
			"expires_at": now.Add(ttl),
		},
		"$setOnInsert": bson.M{
			"offset": 0,
		},
	}

	result := collection.FindOneAndUpdate(
		child,
		filter,
		update,
		options.FindOneAndUpdate().SetUpsert(true).SetReturnDocument(options.After),
	)

	var lease commandBotLease
	if err := result.Decode(&lease); err == nil {
		return lease, true, nil
	} else if mongo.IsDuplicateKeyError(err) {
		existing, readErr := s.readMongo(ctx, client)
		if readErr != nil {
			if s.controller != nil {
				s.controller.HandleMongoError(readErr)
			}
			return commandBotLease{}, false, readErr
		}
		return existing, false, nil
	} else if !errors.Is(err, mongo.ErrNoDocuments) {
		if s.controller != nil {
			s.controller.HandleMongoError(err)
		}
		return commandBotLease{}, false, err
	}

	existing, err := s.readMongo(ctx, client)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return commandBotLease{}, false, nil
		}
		if s.controller != nil {
			s.controller.HandleMongoError(err)
		}
		return commandBotLease{}, false, err
	}
	if existing.OwnerID == ownerID || existing.ExpiresAt.Before(now) || existing.ExpiresAt.Equal(now) {
		return existing, true, nil
	}
	return existing, false, nil
}

func (s *commandBotStateStore) refreshMongo(ctx context.Context, client *mongostore.Client, ownerID string, offset int, now time.Time, ttl time.Duration) (bool, error) {
	collection := client.Database().Collection(commandBotLeaseCollection)
	child, cancel := client.WithTimeout(ctx)
	defer cancel()

	result, err := collection.UpdateOne(child, bson.M{
		"_id":      s.leaseName,
		"owner_id": ownerID,
	}, bson.M{
		"$set": bson.M{
			"offset":     offset,
			"updated_at": now,
			"expires_at": now.Add(ttl),
		},
	})
	if err != nil {
		if s.controller != nil {
			s.controller.HandleMongoError(err)
		}
		return false, err
	}
	return result.MatchedCount > 0, nil
}

func (s *commandBotStateStore) releaseMongo(ctx context.Context, client *mongostore.Client, ownerID string) error {
	collection := client.Database().Collection(commandBotLeaseCollection)
	child, cancel := client.WithTimeout(ctx)
	defer cancel()

	_, err := collection.UpdateOne(child, bson.M{
		"_id":      s.leaseName,
		"owner_id": ownerID,
	}, bson.M{
		"$set": bson.M{
			"updated_at": time.Now().UTC(),
			"expires_at": time.Unix(0, 0).UTC(),
		},
	})
	if err != nil && s.controller != nil {
		s.controller.HandleMongoError(err)
	}
	return err
}

func (s *commandBotStateStore) readMongo(ctx context.Context, client *mongostore.Client) (commandBotLease, error) {
	child, cancel := client.WithTimeout(ctx)
	defer cancel()

	var lease commandBotLease
	err := client.Database().Collection(commandBotLeaseCollection).FindOne(child, bson.M{"_id": s.leaseName}).Decode(&lease)
	return lease, err
}

func (s *commandBotStateStore) tryAcquireFile(ownerID string, now time.Time, ttl time.Duration) (commandBotLease, bool, error) {
	var (
		lease    commandBotLease
		acquired bool
	)
	err := s.withFileLock(ttl, func() error {
		current, readErr := s.readFile()
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			return readErr
		}
		if current.OwnerID != "" && current.OwnerID != ownerID && current.ExpiresAt.After(now) {
			lease = current
			acquired = false
			return nil
		}
		current.LeaseName = s.leaseName
		current.OwnerID = ownerID
		current.UpdatedAt = now
		current.ExpiresAt = now.Add(ttl)
		if writeErr := s.writeFile(current); writeErr != nil {
			return writeErr
		}
		lease = current
		acquired = true
		return nil
	})
	if err != nil {
		return commandBotLease{}, false, err
	}
	return lease, acquired, nil
}

func (s *commandBotStateStore) refreshFile(ownerID string, offset int, now time.Time, ttl time.Duration) (bool, error) {
	var refreshed bool
	err := s.withFileLock(ttl, func() error {
		current, readErr := s.readFile()
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			return readErr
		}
		if current.OwnerID != "" && current.OwnerID != ownerID && current.ExpiresAt.After(now) {
			refreshed = false
			return nil
		}
		current.LeaseName = s.leaseName
		current.OwnerID = ownerID
		current.Offset = offset
		current.UpdatedAt = now
		current.ExpiresAt = now.Add(ttl)
		if writeErr := s.writeFile(current); writeErr != nil {
			return writeErr
		}
		refreshed = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return refreshed, nil
}

func (s *commandBotStateStore) releaseFile(ownerID string) error {
	return s.withFileLock(5*time.Second, func() error {
		current, err := s.readFile()
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		if current.OwnerID != ownerID {
			return nil
		}
		current.UpdatedAt = time.Now().UTC()
		current.ExpiresAt = time.Unix(0, 0).UTC()
		return s.writeFile(current)
	})
}

func (s *commandBotStateStore) readFile() (commandBotLease, error) {
	raw, err := os.ReadFile(s.filePath)
	if err != nil {
		return commandBotLease{}, err
	}
	var lease commandBotLease
	if err := json.Unmarshal(raw, &lease); err != nil {
		return commandBotLease{}, fmt.Errorf("unmarshal command bot lease file: %w", err)
	}
	return lease, nil
}

func (s *commandBotStateStore) writeFile(lease commandBotLease) error {
	if err := os.MkdirAll(filepath.Dir(s.filePath), 0o755); err != nil {
		return fmt.Errorf("mkdir command bot lease dir: %w", err)
	}
	raw, err := json.Marshal(lease)
	if err != nil {
		return fmt.Errorf("marshal command bot lease file: %w", err)
	}
	tmpPath := s.filePath + ".tmp"
	if err := os.WriteFile(tmpPath, raw, 0o644); err != nil {
		return fmt.Errorf("write command bot lease tmp file: %w", err)
	}
	if err := os.Rename(tmpPath, s.filePath); err != nil {
		return fmt.Errorf("rename command bot lease file: %w", err)
	}
	return nil
}

func (s *commandBotStateStore) withFileLock(ttl time.Duration, fn func() error) error {
	if err := os.MkdirAll(filepath.Dir(s.filePath), 0o755); err != nil {
		return fmt.Errorf("mkdir command bot lease dir: %w", err)
	}
	lockPath := s.filePath + ".lock"
	deadline := time.Now().Add(minDuration(ttl/2, 5*time.Second))
	if deadline.Before(time.Now().Add(250 * time.Millisecond)) {
		deadline = time.Now().Add(250 * time.Millisecond)
	}

	for {
		if err := os.Mkdir(lockPath, 0o755); err == nil {
			defer func() { _ = os.Remove(lockPath) }()
			return fn()
		} else if !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("acquire command bot lease lock: %w", err)
		}

		info, statErr := os.Stat(lockPath)
		if statErr == nil && time.Since(info.ModTime()) > ttl {
			_ = os.Remove(lockPath)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("acquire command bot lease lock: timeout")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func minDuration(left, right time.Duration) time.Duration {
	if left <= 0 {
		return right
	}
	if left < right {
		return left
	}
	return right
}
