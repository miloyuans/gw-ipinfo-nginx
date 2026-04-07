package cache

import (
	"context"
	"errors"

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
	var entry Entry
	if err := r.store.GetJSON(ctx, localdisk.BucketIPCache, ip, &entry); err != nil {
		if errors.Is(err, localdisk.ErrNotFound) {
			return Entry{}, ipctx.CacheSourceLocal, false, nil
		}
		return Entry{}, ipctx.CacheSourceLocal, false, err
	}
	return entry, ipctx.CacheSourceLocal, true, nil
}

func (r *LocalRepository) UpsertDirty(ctx context.Context, ip string, entry Entry) error {
	return r.store.PutJSONDirty(ctx, localdisk.BucketIPCache, localdisk.BucketIPCacheDirty, ip, entry)
}
