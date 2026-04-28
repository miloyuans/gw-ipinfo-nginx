package snapshot

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
	v4model "gw-ipinfo-nginx/internal/v4/model"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type syncLeaseStore struct {
	controller *storage.Controller
	filePath   string
	leaseName  string
}

func newSyncLeaseStore(controller *storage.Controller, filePath, leaseName string) *syncLeaseStore {
	return &syncLeaseStore{
		controller: controller,
		filePath:   filepath.Clean(filePath),
		leaseName:  leaseName,
	}
}

func (s *syncLeaseStore) TryAcquire(ctx context.Context, ownerID string, now time.Time, ttl time.Duration) (v4model.SyncState, bool, error) {
	if client := s.mongoClient(); client != nil {
		return s.tryAcquireMongo(ctx, client, ownerID, now, ttl)
	}
	return s.tryAcquireFile(ownerID, now, ttl)
}

func (s *syncLeaseStore) Refresh(ctx context.Context, ownerID string, now time.Time, ttl time.Duration) (bool, error) {
	if client := s.mongoClient(); client != nil {
		return s.refreshMongo(ctx, client, ownerID, now, ttl)
	}
	return s.refreshFile(ownerID, now, ttl)
}

func (s *syncLeaseStore) Release(ctx context.Context, ownerID string) error {
	if client := s.mongoClient(); client != nil {
		return s.releaseMongo(ctx, client, ownerID)
	}
	return s.releaseFile(ownerID)
}

func (s *syncLeaseStore) mongoClient() *mongostore.Client {
	if s == nil || s.controller == nil || s.controller.Mode() == storage.ModeLocal {
		return nil
	}
	return s.controller.Client()
}

func (s *syncLeaseStore) tryAcquireMongo(ctx context.Context, client *mongostore.Client, ownerID string, now time.Time, ttl time.Duration) (v4model.SyncState, bool, error) {
	if client == nil {
		return v4model.SyncState{}, false, errors.New("nil mongo client for v4 snapshot lease")
	}
	collection := client.Database().Collection(v4model.CollectionSnapshots)
	child, cancel := client.WithTimeout(ctx)
	defer cancel()

	filter := bson.M{
		"_id": v4model.SyncStateID,
		"$or": []bson.M{
			{"lease_owner": ownerID},
			{"lease_expires_at": bson.M{"$lte": now}},
			{"lease_owner": ""},
		},
	}
	update := bson.M{
		"$set": bson.M{
			"lease_name":       s.leaseName,
			"lease_owner":      ownerID,
			"lease_expires_at": now.Add(ttl),
			"updated_at":       now,
		},
		"$setOnInsert": bson.M{
			"last_status": "idle",
		},
	}

	result := collection.FindOneAndUpdate(
		child,
		filter,
		update,
		options.FindOneAndUpdate().SetUpsert(true).SetReturnDocument(options.After),
	)

	var state v4model.SyncState
	if err := result.Decode(&state); err == nil {
		return state, true, nil
	} else if mongo.IsDuplicateKeyError(err) {
		current, readErr := s.readMongo(ctx, client)
		if readErr != nil {
			if s.controller != nil {
				s.controller.HandleMongoError(readErr)
			}
			return v4model.SyncState{}, false, readErr
		}
		return current, false, nil
	} else if !errors.Is(err, mongo.ErrNoDocuments) {
		if s.controller != nil {
			s.controller.HandleMongoError(err)
		}
		return v4model.SyncState{}, false, err
	}

	current, err := s.readMongo(ctx, client)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return v4model.SyncState{}, false, nil
		}
		if s.controller != nil {
			s.controller.HandleMongoError(err)
		}
		return v4model.SyncState{}, false, err
	}
	return current, current.LeaseOwner == ownerID, nil
}

func (s *syncLeaseStore) refreshMongo(ctx context.Context, client *mongostore.Client, ownerID string, now time.Time, ttl time.Duration) (bool, error) {
	if client == nil {
		return false, errors.New("nil mongo client for v4 snapshot lease")
	}
	collection := client.Database().Collection(v4model.CollectionSnapshots)
	child, cancel := client.WithTimeout(ctx)
	defer cancel()

	result, err := collection.UpdateOne(child, bson.M{
		"_id":         v4model.SyncStateID,
		"lease_owner": ownerID,
	}, bson.M{
		"$set": bson.M{
			"lease_name":       s.leaseName,
			"lease_expires_at": now.Add(ttl),
			"updated_at":       now,
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

func (s *syncLeaseStore) releaseMongo(ctx context.Context, client *mongostore.Client, ownerID string) error {
	if client == nil {
		return nil
	}
	collection := client.Database().Collection(v4model.CollectionSnapshots)
	child, cancel := client.WithTimeout(ctx)
	defer cancel()

	_, err := collection.UpdateOne(child, bson.M{
		"_id":         v4model.SyncStateID,
		"lease_owner": ownerID,
	}, bson.M{
		"$set": bson.M{
			"lease_expires_at": time.Unix(0, 0).UTC(),
			"updated_at":       time.Now().UTC(),
		},
	})
	if err != nil && s.controller != nil {
		s.controller.HandleMongoError(err)
	}
	return err
}

func (s *syncLeaseStore) readMongo(ctx context.Context, client *mongostore.Client) (v4model.SyncState, error) {
	if client == nil {
		return v4model.SyncState{}, errors.New("nil mongo client for v4 snapshot lease")
	}
	child, cancel := client.WithTimeout(ctx)
	defer cancel()

	var state v4model.SyncState
	err := client.Database().Collection(v4model.CollectionSnapshots).FindOne(child, bson.M{"_id": v4model.SyncStateID}).Decode(&state)
	return state, err
}

func (s *syncLeaseStore) tryAcquireFile(ownerID string, now time.Time, ttl time.Duration) (v4model.SyncState, bool, error) {
	var (
		state    v4model.SyncState
		acquired bool
	)
	err := s.withFileLock(ttl, func() error {
		current, readErr := s.readFile()
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			return readErr
		}
		if current.LeaseOwner != "" && current.LeaseOwner != ownerID && current.LeaseExpiresAt.After(now) {
			state = current
			acquired = false
			return nil
		}
		current.ID = v4model.SyncStateID
		current.LeaseName = s.leaseName
		current.LeaseOwner = ownerID
		current.LeaseExpiresAt = now.Add(ttl)
		current.UpdatedAt = now
		if current.LastStatus == "" {
			current.LastStatus = "idle"
		}
		if err := s.writeFile(current); err != nil {
			return err
		}
		state = current
		acquired = true
		return nil
	})
	if err != nil {
		return v4model.SyncState{}, false, err
	}
	return state, acquired, nil
}

func (s *syncLeaseStore) refreshFile(ownerID string, now time.Time, ttl time.Duration) (bool, error) {
	var refreshed bool
	err := s.withFileLock(ttl, func() error {
		current, readErr := s.readFile()
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			return readErr
		}
		if current.LeaseOwner != "" && current.LeaseOwner != ownerID && current.LeaseExpiresAt.After(now) {
			refreshed = false
			return nil
		}
		current.ID = v4model.SyncStateID
		current.LeaseName = s.leaseName
		current.LeaseOwner = ownerID
		current.LeaseExpiresAt = now.Add(ttl)
		current.UpdatedAt = now
		if current.LastStatus == "" {
			current.LastStatus = "idle"
		}
		if err := s.writeFile(current); err != nil {
			return err
		}
		refreshed = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return refreshed, nil
}

func (s *syncLeaseStore) releaseFile(ownerID string) error {
	return s.withFileLock(5*time.Second, func() error {
		current, err := s.readFile()
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		if current.LeaseOwner != ownerID {
			return nil
		}
		current.LeaseExpiresAt = time.Unix(0, 0).UTC()
		current.UpdatedAt = time.Now().UTC()
		return s.writeFile(current)
	})
}

func (s *syncLeaseStore) readFile() (v4model.SyncState, error) {
	raw, err := os.ReadFile(s.filePath)
	if err != nil {
		return v4model.SyncState{}, err
	}
	var state v4model.SyncState
	if err := json.Unmarshal(raw, &state); err != nil {
		return v4model.SyncState{}, fmt.Errorf("unmarshal v4 sync state file: %w", err)
	}
	return state, nil
}

func (s *syncLeaseStore) writeFile(state v4model.SyncState) error {
	if err := os.MkdirAll(filepath.Dir(s.filePath), 0o755); err != nil {
		return fmt.Errorf("mkdir v4 sync state dir: %w", err)
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal v4 sync state file: %w", err)
	}
	tmpPath := s.filePath + ".tmp"
	if err := os.WriteFile(tmpPath, raw, 0o644); err != nil {
		return fmt.Errorf("write v4 sync state tmp file: %w", err)
	}
	if err := os.Rename(tmpPath, s.filePath); err != nil {
		return fmt.Errorf("rename v4 sync state file: %w", err)
	}
	return nil
}

func (s *syncLeaseStore) withFileLock(ttl time.Duration, fn func() error) error {
	if err := os.MkdirAll(filepath.Dir(s.filePath), 0o755); err != nil {
		return fmt.Errorf("mkdir v4 sync state dir: %w", err)
	}
	lockPath := s.filePath + ".lock"
	deadline := time.Now().Add(minSnapshotDuration(ttl/2, 5*time.Second))
	if deadline.Before(time.Now().Add(250 * time.Millisecond)) {
		deadline = time.Now().Add(250 * time.Millisecond)
	}

	for {
		if err := os.Mkdir(lockPath, 0o755); err == nil {
			defer func() { _ = os.Remove(lockPath) }()
			return fn()
		} else if !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("acquire v4 sync state lock: %w", err)
		}

		info, statErr := os.Stat(lockPath)
		if statErr == nil && time.Since(info.ModTime()) > ttl {
			_ = os.Remove(lockPath)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("acquire v4 sync state lock: timeout")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func minSnapshotDuration(left, right time.Duration) time.Duration {
	if left <= 0 {
		return right
	}
	if left < right {
		return left
	}
	return right
}
