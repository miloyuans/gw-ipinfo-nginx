package localdisk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gw-ipinfo-nginx/internal/runtimex"

	bolt "go.etcd.io/bbolt"
)

const (
	BucketIPCache         = "ip_cache"
	BucketIPCacheDirty    = "ip_cache_dirty"
	BucketDecisionCache   = "decision_cache"
	BucketDecisionDirty   = "decision_cache_dirty"
	BucketAlertsOutbox    = "alerts_outbox"
	BucketAlertsDirty     = "alerts_outbox_dirty"
	BucketReportRecords   = "report_records"
	BucketReportDirty     = "report_records_dirty"
	BucketMetadata        = "metadata"
)

var ErrNotFound = errors.New("localdisk: not found")

type Store struct {
	db              *bolt.DB
	path            string
	peerPattern     string
	peerOpenTimeout time.Duration
}

func Open(path string) (*Store, error) {
	return openWithTimeout(path, 5*time.Second)
}

func openWithTimeout(path string, timeout time.Duration) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create localdisk dir: %w", err)
	}

	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: timeout})
	if err != nil {
		if errors.Is(err, bolt.ErrTimeout) {
			return nil, fmt.Errorf("open localdisk db: timeout (local storage file is locked, usually because multiple pods/processes are opening the same file: %s)", path)
		}
		return nil, fmt.Errorf("open localdisk db: %w", err)
	}

	store := &Store{
		db:              db,
		path:            filepath.Clean(path),
		peerPattern:     peerPatternForPath(path),
		peerOpenTimeout: 200 * time.Millisecond,
	}
	if err := store.init(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) init() error {
	return s.db.Update(func(tx *bolt.Tx) error {
		buckets := []string{
			BucketIPCache,
			BucketIPCacheDirty,
			BucketDecisionCache,
			BucketDecisionDirty,
			BucketAlertsOutbox,
			BucketAlertsDirty,
			BucketReportRecords,
			BucketReportDirty,
			BucketMetadata,
		}
		for _, name := range buckets {
			if _, err := tx.CreateBucketIfNotExists([]byte(name)); err != nil {
				return fmt.Errorf("create bucket %s: %w", name, err)
			}
		}
		return nil
	})
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) View(ctx context.Context, fn func(tx *bolt.Tx) error) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return s.db.View(fn)
}

func (s *Store) Update(ctx context.Context, fn func(tx *bolt.Tx) error) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return s.db.Update(fn)
}

func (s *Store) PutJSON(ctx context.Context, bucket, key string, value any) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal localdisk value: %w", err)
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucket)).Put([]byte(key), data)
	})
}

func (s *Store) PutJSONDirty(ctx context.Context, bucket, dirtyBucket, key string, value any) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal localdisk value: %w", err)
	}

	now := []byte(time.Now().UTC().Format(time.RFC3339Nano))
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket([]byte(bucket)).Put([]byte(key), data); err != nil {
			return err
		}
		return tx.Bucket([]byte(dirtyBucket)).Put([]byte(key), now)
	})
}

func (s *Store) GetJSON(ctx context.Context, bucket, key string, dst any) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	err := s.db.View(func(tx *bolt.Tx) error {
		value := tx.Bucket([]byte(bucket)).Get([]byte(key))
		if value == nil {
			return ErrNotFound
		}
		return json.Unmarshal(value, dst)
	})
	if err == nil || !errors.Is(err, ErrNotFound) {
		return err
	}
	return s.getJSONFromPeers(ctx, bucket, key, dst)
}

func (s *Store) Delete(ctx context.Context, bucket, key string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucket)).Delete([]byte(key))
	})
}

func (s *Store) DeleteWithDirty(ctx context.Context, bucket, dirtyBucket, key string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket([]byte(bucket)).Delete([]byte(key)); err != nil {
			return err
		}
		return tx.Bucket([]byte(dirtyBucket)).Delete([]byte(key))
	})
}

func (s *Store) ClearDirty(ctx context.Context, dirtyBucket, key string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(dirtyBucket)).Delete([]byte(key))
	})
}

func (s *Store) DirtyKeys(ctx context.Context, dirtyBucket string, limit int) ([]string, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	keys := make([]string, 0, limit)
	err := s.db.View(func(tx *bolt.Tx) error {
		cursor := tx.Bucket([]byte(dirtyBucket)).Cursor()
		for key, _ := cursor.First(); key != nil; key, _ = cursor.Next() {
			keys = append(keys, string(key))
			if limit > 0 && len(keys) >= limit {
				break
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return keys, nil
}

func (s *Store) ForEachJSON(ctx context.Context, bucket string, fn func(key string, raw []byte) error) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	if err := s.db.View(func(tx *bolt.Tx) error {
		cursor := tx.Bucket([]byte(bucket)).Cursor()
		for key, value := cursor.First(); key != nil; key, value = cursor.Next() {
			if err := fn(string(key), append([]byte(nil), value...)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	return s.forEachPeerJSON(ctx, bucket, fn)
}

func (s *Store) getJSONFromPeers(ctx context.Context, bucket, key string, dst any) error {
	paths, err := s.peerPaths()
	if err != nil {
		return err
	}

	var firstErr error
	for _, peerPath := range paths {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		peerDB, err := bolt.Open(peerPath, 0o600, &bolt.Options{Timeout: s.peerOpenTimeout, ReadOnly: true})
		if err != nil {
			if firstErr == nil && !errors.Is(err, bolt.ErrTimeout) {
				firstErr = err
			}
			continue
		}

		viewErr := peerDB.View(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(bucket))
			if b == nil {
				return ErrNotFound
			}
			value := b.Get([]byte(key))
			if value == nil {
				return ErrNotFound
			}
			return json.Unmarshal(value, dst)
		})
		_ = peerDB.Close()

		if viewErr == nil {
			return nil
		}
		if !errors.Is(viewErr, ErrNotFound) && firstErr == nil {
			firstErr = viewErr
		}
	}

	if firstErr != nil {
		return firstErr
	}
	return ErrNotFound
}

func (s *Store) ForKeyJSON(ctx context.Context, bucket, key string, fn func(raw []byte) error) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	if err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return nil
		}
		value := b.Get([]byte(key))
		if value == nil {
			return nil
		}
		return fn(append([]byte(nil), value...))
	}); err != nil {
		return err
	}

	paths, err := s.peerPaths()
	if err != nil {
		return err
	}

	for _, peerPath := range paths {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		peerDB, err := bolt.Open(peerPath, 0o600, &bolt.Options{Timeout: s.peerOpenTimeout, ReadOnly: true})
		if err != nil {
			continue
		}
		viewErr := peerDB.View(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(bucket))
			if b == nil {
				return nil
			}
			value := b.Get([]byte(key))
			if value == nil {
				return nil
			}
			return fn(append([]byte(nil), value...))
		})
		_ = peerDB.Close()
		if viewErr != nil {
			return viewErr
		}
	}
	return nil
}

func (s *Store) forEachPeerJSON(ctx context.Context, bucket string, fn func(key string, raw []byte) error) error {
	paths, err := s.peerPaths()
	if err != nil {
		return err
	}

	for _, peerPath := range paths {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		peerDB, err := bolt.Open(peerPath, 0o600, &bolt.Options{Timeout: s.peerOpenTimeout, ReadOnly: true})
		if err != nil {
			continue
		}

		viewErr := peerDB.View(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(bucket))
			if b == nil {
				return nil
			}
			cursor := b.Cursor()
			for key, value := cursor.First(); key != nil; key, value = cursor.Next() {
				if err := fn(string(key), append([]byte(nil), value...)); err != nil {
					return err
				}
			}
			return nil
		})
		_ = peerDB.Close()

		if viewErr != nil {
			return viewErr
		}
	}
	return nil
}

func (s *Store) peerPaths() ([]string, error) {
	if s.peerPattern == "" {
		return nil, nil
	}

	paths, err := filepath.Glob(s.peerPattern)
	if err != nil {
		return nil, err
	}

	filtered := make([]string, 0, len(paths))
	for _, path := range paths {
		clean := filepath.Clean(path)
		if clean == s.path {
			continue
		}
		filtered = append(filtered, clean)
	}
	return filtered, nil
}

func peerPatternForPath(path string) string {
	scope := runtimex.WorkerScope()
	if scope == "" {
		return ""
	}

	clean := filepath.Clean(path)
	dir := filepath.Dir(clean)
	if filepath.Base(dir) != scope {
		return ""
	}
	return filepath.Join(filepath.Dir(dir), "*", filepath.Base(clean))
}
