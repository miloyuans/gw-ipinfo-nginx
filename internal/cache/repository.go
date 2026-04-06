package cache

import (
	"context"
	"errors"
	"fmt"
	"time"

	mongostore "gw-ipinfo-nginx/internal/mongo"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Repository struct {
	client     *mongostore.Client
	collection *mongo.Collection
}

type document struct {
	ID string `bson:"_id"`
	Entry `bson:",inline"`
}

func NewRepository(client *mongostore.Client, collectionName string) *Repository {
	return &Repository{
		client:     client,
		collection: client.Database().Collection(collectionName),
	}
}

func (r *Repository) InitIndexes(ctx context.Context) error {
	child, cancel := r.client.WithTimeout(ctx)
	defer cancel()

	indexes := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "expires_at", Value: 1}},
			Options: options.Index().SetExpireAfterSeconds(0).SetName("ttl_expires_at"),
		},
	}

	_, err := r.collection.Indexes().CreateMany(child, indexes)
	if err != nil {
		return fmt.Errorf("create ip cache indexes: %w", err)
	}
	return nil
}

func (r *Repository) Get(ctx context.Context, ip string) (Entry, bool, error) {
	child, cancel := r.client.WithTimeout(ctx)
	defer cancel()

	var doc document
	err := r.collection.FindOne(child, bson.M{"_id": ip}).Decode(&doc)
	if err == nil {
		return doc.Entry, true, nil
	}
	if errors.Is(err, mongo.ErrNoDocuments) {
		return Entry{}, false, nil
	}
	return Entry{}, false, fmt.Errorf("find cached ip %s: %w", ip, err)
}

func (r *Repository) Upsert(ctx context.Context, ip string, entry Entry) error {
	child, cancel := r.client.WithTimeout(ctx)
	defer cancel()

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

	_, err := r.collection.UpdateByID(child, ip, update, options.Update().SetUpsert(true))
	if err != nil {
		return fmt.Errorf("upsert cache entry %s: %w", ip, err)
	}
	return nil
}
