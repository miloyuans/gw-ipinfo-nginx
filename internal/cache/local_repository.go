package cache

import (
	"context"
	"errors"
	"encoding/json"

	"gw-ipinfo-nginx/internal/ipctx"
	"gw-ipinfo-nginx/internal/localdisk"
)

type LocalRepository struct {
	store *localdisk.Store
}

func NewLocalRepository(store *localdisk.Store) *LocalRepository {
	return &LocalRepository{store: store}
}

func (r *LocalRepository) Get(ctx context.Context, ip string) (Entry, ipctx.CacheSource, bool, error) {
	var (
		entry Entry
		found bool
	)
	if err := r.store.ForKeyJSON(ctx, localdisk.BucketIPCache, ip, func(raw []byte) error {
		var candidate Entry
		if err := json.Unmarshal(raw, &candidate); err != nil {
			return err
		}
		if !found || candidate.UpdatedAt.After(entry.UpdatedAt) {
			entry = candidate
			found = true
		}
		return nil
	}); err != nil {
		if errors.Is(err, localdisk.ErrNotFound) {
			return Entry{}, ipctx.CacheSourceLocal, false, nil
		}
		return Entry{}, ipctx.CacheSourceLocal, false, err
	}
	if !found {
		return Entry{}, ipctx.CacheSourceLocal, false, nil
	}
	return entry, ipctx.CacheSourceLocal, true, nil
}

func (r *LocalRepository) UpsertDirty(ctx context.Context, ip string, entry Entry) error {
	return r.store.PutJSONDirty(ctx, localdisk.BucketIPCache, localdisk.BucketIPCacheDirty, ip, entry)
}
