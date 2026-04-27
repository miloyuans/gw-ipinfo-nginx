package reporting

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	mongostore "gw-ipinfo-nginx/internal/mongo"
	"gw-ipinfo-nginx/internal/storage"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type reportSchedulerLease struct {
	LeaseName string    `json:"lease_name" bson:"_id"`
	OwnerID   string    `json:"owner_id" bson:"owner_id"`
	UpdatedAt time.Time `json:"updated_at" bson:"updated_at"`
	ExpiresAt time.Time `json:"expires_at" bson:"expires_at"`
}

type reportLeaseStore struct {
	controller     *storage.Controller
	filePath       string
	collectionName string
	leaseName      string
}

func newReportLeaseStore(controller *storage.Controller, filePath, collectionName, leaseName string) *reportLeaseStore {
	return &reportLeaseStore{
		controller:     controller,
		filePath:       filepath.Clean(filePath),
		collectionName: stringsTrimSpaceOrDefault(collectionName, "daily_reports"),
		leaseName:      leaseName,
	}
}

func (s *reportLeaseStore) TryAcquire(ctx context.Context, ownerID string, now time.Time, ttl time.Duration) (reportSchedulerLease, bool, error) {
	if client := s.mongoClient(); client != nil {
		return s.tryAcquireMongo(ctx, client, ownerID, now, ttl)
	}
	return reportSchedulerLease{}, false, errors.New("mongo unavailable for report scheduler lease")
}

func (s *reportLeaseStore) Refresh(ctx context.Context, ownerID string, now time.Time, ttl time.Duration) (bool, error) {
	if client := s.mongoClient(); client != nil {
		return s.refreshMongo(ctx, client, ownerID, now, ttl)
	}
	return false, errors.New("mongo unavailable for report scheduler lease")
}

func (s *reportLeaseStore) Release(ctx context.Context, ownerID string) error {
	if client := s.mongoClient(); client != nil {
		return s.releaseMongo(ctx, client, ownerID)
	}
	return nil
}

func (s *reportLeaseStore) mongoClient() *mongostore.Client {
	if s == nil || s.controller == nil {
		return nil
	}
	return s.controller.Client()
}

func (s *reportLeaseStore) tryAcquireMongo(ctx context.Context, client *mongostore.Client, ownerID string, now time.Time, ttl time.Duration) (reportSchedulerLease, bool, error) {
	collection := client.Database().Collection(s.collectionName)
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
			"kind":       "report_scheduler_lease",
			"day":        "",
			"owner_id":   ownerID,
			"updated_at": now,
			"expires_at": now.Add(ttl),
		},
	}

	result := collection.FindOneAndUpdate(
		child,
		filter,
		update,
		options.FindOneAndUpdate().SetUpsert(true).SetReturnDocument(options.After),
	)

	var lease reportSchedulerLease
	if err := result.Decode(&lease); err == nil {
		return lease, true, nil
	} else if mongo.IsDuplicateKeyError(err) {
		existing, readErr := s.readMongo(ctx, client)
		if readErr != nil {
			if s.controller != nil {
				s.controller.HandleMongoError(readErr)
			}
			return reportSchedulerLease{}, false, readErr
		}
		return existing, false, nil
	} else if !errors.Is(err, mongo.ErrNoDocuments) {
		if s.controller != nil {
			s.controller.HandleMongoError(err)
		}
		return reportSchedulerLease{}, false, err
	}

	existing, err := s.readMongo(ctx, client)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return reportSchedulerLease{}, false, nil
		}
		if s.controller != nil {
			s.controller.HandleMongoError(err)
		}
		return reportSchedulerLease{}, false, err
	}
	if existing.OwnerID == ownerID || !existing.ExpiresAt.After(now) {
		return existing, true, nil
	}
	return existing, false, nil
}

func (s *reportLeaseStore) refreshMongo(ctx context.Context, client *mongostore.Client, ownerID string, now time.Time, ttl time.Duration) (bool, error) {
	collection := client.Database().Collection(s.collectionName)
	child, cancel := client.WithTimeout(ctx)
	defer cancel()

	result, err := collection.UpdateOne(child, bson.M{
		"_id":      s.leaseName,
		"owner_id": ownerID,
	}, bson.M{
		"$set": bson.M{
			"kind":       "report_scheduler_lease",
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

func (s *reportLeaseStore) releaseMongo(ctx context.Context, client *mongostore.Client, ownerID string) error {
	collection := client.Database().Collection(s.collectionName)
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

func (s *reportLeaseStore) readMongo(ctx context.Context, client *mongostore.Client) (reportSchedulerLease, error) {
	child, cancel := client.WithTimeout(ctx)
	defer cancel()

	var lease reportSchedulerLease
	err := client.Database().Collection(s.collectionName).FindOne(child, bson.M{"_id": s.leaseName}).Decode(&lease)
	return lease, err
}

func (s *reportLeaseStore) tryAcquireFile(ownerID string, now time.Time, ttl time.Duration) (reportSchedulerLease, bool, error) {
	var (
		lease    reportSchedulerLease
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
		return reportSchedulerLease{}, false, err
	}
	return lease, acquired, nil
}

func (s *reportLeaseStore) refreshFile(ownerID string, now time.Time, ttl time.Duration) (bool, error) {
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

func (s *reportLeaseStore) releaseFile(ownerID string) error {
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

func (s *reportLeaseStore) readFile() (reportSchedulerLease, error) {
	raw, err := os.ReadFile(s.filePath)
	if err != nil {
		return reportSchedulerLease{}, err
	}
	var lease reportSchedulerLease
	if err := json.Unmarshal(raw, &lease); err != nil {
		return reportSchedulerLease{}, fmt.Errorf("unmarshal report scheduler lease file: %w", err)
	}
	return lease, nil
}

func (s *reportLeaseStore) writeFile(lease reportSchedulerLease) error {
	if err := os.MkdirAll(filepath.Dir(s.filePath), 0o755); err != nil {
		return fmt.Errorf("mkdir report scheduler lease dir: %w", err)
	}
	raw, err := json.Marshal(lease)
	if err != nil {
		return fmt.Errorf("marshal report scheduler lease file: %w", err)
	}
	tmpPath := s.filePath + ".tmp"
	if err := os.WriteFile(tmpPath, raw, 0o644); err != nil {
		return fmt.Errorf("write report scheduler lease tmp file: %w", err)
	}
	if err := os.Rename(tmpPath, s.filePath); err != nil {
		return fmt.Errorf("rename report scheduler lease file: %w", err)
	}
	return nil
}

func (s *reportLeaseStore) withFileLock(ttl time.Duration, fn func() error) error {
	if err := os.MkdirAll(filepath.Dir(s.filePath), 0o755); err != nil {
		return fmt.Errorf("mkdir report scheduler lease dir: %w", err)
	}
	lockPath := s.filePath + ".lock"
	deadline := time.Now().Add(minReportDuration(ttl/2, 5*time.Second))
	if deadline.Before(time.Now().Add(250 * time.Millisecond)) {
		deadline = time.Now().Add(250 * time.Millisecond)
	}
	for {
		if err := os.Mkdir(lockPath, 0o755); err == nil {
			defer func() { _ = os.Remove(lockPath) }()
			return fn()
		} else if !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("acquire report scheduler lease lock: %w", err)
		}

		info, statErr := os.Stat(lockPath)
		if statErr == nil && time.Since(info.ModTime()) > ttl {
			_ = os.Remove(lockPath)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("acquire report scheduler lease lock: timeout")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func minReportDuration(left, right time.Duration) time.Duration {
	if left <= 0 {
		return right
	}
	if left < right {
		return left
	}
	return right
}

func stringsTrimSpaceOrDefault(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}
