package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"gw-ipinfo-nginx/internal/alerts"
	"gw-ipinfo-nginx/internal/config"
	mongostore "gw-ipinfo-nginx/internal/mongo"
)

func TestAlertsRepositoryEnqueueAndClaim(t *testing.T) {
	mongoURI := os.Getenv("GW_MONGO_TEST_URI")
	if mongoURI == "" {
		t.Skip("set GW_MONGO_TEST_URI to run Mongo integration tests")
	}

	client, dbName := mustAlertMongoClient(t, mongoURI)
	defer dropAlertDatabase(t, client, dbName)

	repo := alerts.NewRepository(client, "alerts_outbox", "alerts_dedupe")
	if err := repo.InitIndexes(context.Background()); err != nil {
		t.Fatalf("InitIndexes() error = %v", err)
	}

	payload := alerts.Payload{
		Type:        "allowed_with_risk",
		NotifyType:  "allowed_with_risk",
		Severity:    "warning",
		ClientIP:    "1.1.1.1",
		ServiceName: "default",
		Reason:      "allow_privacy_vpn",
		Timestamp:   time.Now().UTC(),
	}

	enqueued, err := repo.Enqueue(context.Background(), "allowed_with_risk", payload, 10*time.Minute)
	if err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	if !enqueued {
		t.Fatal("Enqueue() = false, want true")
	}

	messages, err := repo.Claim(context.Background(), "worker-1", 10, 3, 30*time.Second)
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	if len(messages) != 1 {
		t.Fatalf("Claim() len = %d, want 1", len(messages))
	}
	if messages[0].NotifyType != "allowed_with_risk" || messages[0].Severity != "warning" {
		t.Fatalf("Claim() message = %#v, want notify_type/severity populated", messages[0])
	}
}

func mustAlertMongoClient(t *testing.T, mongoURI string) (*mongostore.Client, string) {
	t.Helper()
	dbName := "gw_ipinfo_nginx_alerts_" + time.Now().UTC().Format("20060102150405") + "_" + time.Now().UTC().Format("150405000")
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

func dropAlertDatabase(t *testing.T, client *mongostore.Client, dbName string) {
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
