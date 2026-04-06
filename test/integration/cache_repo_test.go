package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"gw-ipinfo-nginx/internal/cache"
	"gw-ipinfo-nginx/internal/config"
	"gw-ipinfo-nginx/internal/ipctx"
	mongostore "gw-ipinfo-nginx/internal/mongo"
)

func TestCacheRepositoryRoundTrip(t *testing.T) {
	mongoURI := os.Getenv("GW_MONGO_TEST_URI")
	if mongoURI == "" {
		t.Skip("set GW_MONGO_TEST_URI to run Mongo integration tests")
	}

	client, dbName := mustMongoClient(t, mongoURI)
	defer dropDatabase(t, client, dbName)

	repo := cache.NewRepository(client, "ip_risk_cache")
	if err := repo.InitIndexes(context.Background()); err != nil {
		t.Fatalf("InitIndexes() error = %v", err)
	}

	now := time.Now().UTC()
	entry := cache.Entry{
		IPContext: ipctx.Context{
			IP:          "1.1.1.1",
			CountryCode: "US",
			City:        "Seattle",
			LookupTime:  now,
		},
		GeoExpiresAt:      now.Add(time.Hour),
		PrivacyExpiresAt:  now.Add(time.Hour),
		ResProxyExpiresAt: now.Add(time.Hour),
		ExpiresAt:         now.Add(time.Hour),
		UpdatedAt:         now,
	}

	if err := repo.Upsert(context.Background(), "1.1.1.1", entry); err != nil {
		t.Fatalf("Upsert() error = %v", err)
	}

	got, found, err := repo.Get(context.Background(), "1.1.1.1")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !found {
		t.Fatal("Get() found = false, want true")
	}
	if got.IPContext.CountryCode != "US" || got.IPContext.City != "Seattle" {
		t.Fatalf("Get() = %#v, want US/Seattle", got)
	}
}

func mustMongoClient(t *testing.T, mongoURI string) (*mongostore.Client, string) {
	t.Helper()
	dbName := "gw_ipinfo_nginx_integration_" + time.Now().UTC().Format("20060102150405") + "_" + time.Now().UTC().Format("150405000")
	client, err := mongostore.Connect(context.Background(), config.MongoConfig{
		URI:              mongoURI,
		Database:         dbName,
		ConnectTimeout:   5 * time.Second,
		OperationTimeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	return client, dbName
}

func dropDatabase(t *testing.T, client *mongostore.Client, dbName string) {
	t.Helper()
	ctx, cancel := client.WithTimeout(context.Background())
	defer cancel()
	if err := client.Database().Drop(ctx); err != nil {
		t.Fatalf("Drop() error = %v", err)
	}
	if err := client.Disconnect(context.Background()); err != nil {
		t.Fatalf("Disconnect() error = %v", err)
	}
}
