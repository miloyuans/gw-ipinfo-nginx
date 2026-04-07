package cache

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"gw-ipinfo-nginx/internal/config"
	"gw-ipinfo-nginx/internal/ipctx"
	"gw-ipinfo-nginx/internal/localdisk"
	mongostore "gw-ipinfo-nginx/internal/mongo"
	"gw-ipinfo-nginx/internal/storage"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type ResilientRepository struct {
	controller     *storage.Controller
	local          *LocalRepository
	collectionName string
	indexOnce      sync.Once
}

type mongoDocument struct {
	ID string `bson:"_id"`
	Entry `bson:",inline"`
}

func NewResilientRepository(cfg *config.Config, controller *storage.Controller) *ResilientRepository {
	return &ResilientRepository{
		controller:     controller,
		local:          NewLocalRepository(controller.Local()),
		collectionName: cfg.Cache.MongoCollections.IPCache,
	}
}

func (r *ResilientRepository) Name() string {
	return "ip_cache"
}

func (r *ResilientRepository) Get(ctx context.Context, ip string) (Entry, ipctx.CacheSource, bool, error) {
	if client := r.controller.Client(); client != nil && r.controller.Mode() != storage.ModeLocal {
		entry, found, err := r.getMongo(ctx, client, ip)
		if err == nil {
			return entry, ipctx.CacheSourceMongo, found, nil
		}
		r.controller.HandleMongoError(err)
	}
	return r.local.Get(ctx, ip)
}

func (r *ResilientRepository) Upsert(ctx context.Context, ip string, entry Entry) error {
	if client := r.controller.Client(); client != nil && r.controller.Mode() != storage.ModeLocal {
		if err := r.upsertMongo(ctx, client, ip, entry); err == nil {
			return nil
		} else {
			r.controller.HandleMongoError(err)
		}
	}
	return r.local.UpsertDirty(ctx, ip, entry)
}

func (r *ResilientRepository) Replay(ctx context.Context, client *mongostore.Client, batchSize int) error {
	keys, err := r.controller.Local().DirtyKeys(ctx, localdisk.BucketIPCacheDirty, batchSize)
	if err != nil {
		return err
	}

	for _, key := range keys {
		entry, _, found, err := r.local.Get(ctx, key)
		if err != nil {
			return err
		}
		if !found {
			_ = r.controller.Local().ClearDirty(ctx, localdisk.BucketIPCacheDirty, key)
			continue
		}

		if err := r.upsertMongo(ctx, client, key, entry); err != nil {
			return err
		}
		if err := r.controller.Local().ClearDirty(ctx, localdisk.BucketIPCacheDirty, key); err != nil {
			return err
		}
	}

	return nil
}

func (r *ResilientRepository) getMongo(ctx context.Context, client *mongostore.Client, ip string) (Entry, bool, error) {
	child, cancel := client.WithTimeout(ctx)
	defer cancel()

	var doc mongoDocument
	err := client.Database().Collection(r.collectionName).FindOne(child, bson.M{"_id": ip}).Decode(&doc)
	if err == nil {
		return doc.Entry, true, nil
	}
	if errors.Is(err, mongo.ErrNoDocuments) {
		return Entry{}, false, nil
	}
	return Entry{}, false, fmt.Errorf("find cached ip %s: %w", ip, err)
}

func (r *ResilientRepository) upsertMongo(ctx context.Context, client *mongostore.Client, ip string, entry Entry) error {
	child, cancel := client.WithTimeout(ctx)
	defer cancel()

	collection := client.Database().Collection(r.collectionName)
	r.indexOnce.Do(func() {
		index := mongo.IndexModel{
			Keys:    bson.D{{Key: "expires_at", Value: 1}},
			Options: options.Index().SetExpireAfterSeconds(0).SetName("ttl_expires_at"),
		}
		_, _ = collection.Indexes().CreateOne(child, index)
	})

	now := time.Now().UTC()
	update := bson.M{
		"$set": bson.M{
			"ip_context":          entry.IPContext,
			"failure":             entry.Failure,
			"geo_expires_at":      entry.GeoExpiresAt,
			"privacy_expires_at":  entry.PrivacyExpiresAt,
			"resproxy_expires_at": entry.ResProxyExpiresAt,
			"failure_expires_at":  entry.FailureExpiresAt,
			"expires_at":          entry.ExpiresAt,
			"updated_at":          now,
		},
		"$setOnInsert": bson.M{
			"created_at": now,
		},
	}
	_, err := collection.UpdateByID(child, ip, update, options.Update().SetUpsert(true))
	if err != nil {
		return fmt.Errorf("upsert cache entry %s: %w", ip, err)
	}
	return nil
}
