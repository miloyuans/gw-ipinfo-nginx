package reporting

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gw-ipinfo-nginx/internal/config"
	"gw-ipinfo-nginx/internal/ipctx"
	"gw-ipinfo-nginx/internal/localdisk"
	"gw-ipinfo-nginx/internal/storage"
)

func TestGenerateDailyProducesHTMLAndCSV(t *testing.T) {
	store, err := localdisk.Open(filepath.Join(t.TempDir(), "report.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	cfg := &config.Config{}
	cfg.Reports.TimeZone = "UTC"
	cfg.Reports.TopN = 5
	cfg.Reports.DailySendTime = "09:00"
	cfg.Reports.Lookback = 24 * time.Hour
	cfg.Reports.PollInterval = time.Minute
	cfg.Cache.MongoCollections.ReportEvents = "reports"
	cfg.Perf.StatsQueueSize = 128
	controller := storage.NewController(config.StorageConfig{
		LocalPath:          filepath.Join(t.TempDir(), "controller.db"),
		ReplayInterval:     time.Second,
		MongoProbeInterval: time.Second,
		ReplayBatchSize:    10,
		ReplayWorkers:      1,
	}, config.MongoConfig{}, store, nil)

	service, err := NewService(cfg, controller, nil, nil, nil, "worker-1")
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	day := time.Date(2026, 4, 7, 8, 0, 0, 0, time.UTC)
	if err := service.persist(context.Background(), Event{
		Timestamp:            day,
		ClientIP:             "1.1.1.1",
		ServiceName:          "default",
		Host:                 "example.com",
		Path:                 "/login",
		RequestURL:           "/login",
		UserAgentSummary:     "chrome",
		Allowed:              true,
		Result:               "allow",
		ReasonCode:           "allow_geo_privacy_clean",
		CountryCode:          "US",
		CountryName:          "United States",
		Region:               "California",
		City:                 "San Francisco",
		Privacy:              ipctx.PrivacyFlags{},
		ShortCircuitHit:      true,
		ShortCircuitDecision: "allow",
	}); err != nil {
		t.Fatalf("persist() error = %v", err)
	}

	htmlReport, csvReport, err := service.GenerateDaily(context.Background(), day)
	if err != nil {
		t.Fatalf("GenerateDaily() error = %v", err)
	}
	if !strings.Contains(string(htmlReport), "gw-ipinfo-nginx Daily Report 2026-04-07") {
		t.Fatalf("html report missing heading: %s", htmlReport)
	}
	if !strings.Contains(string(htmlReport), "example.com") || !strings.Contains(string(htmlReport), "San Francisco") {
		t.Fatalf("html report missing expected content: %s", htmlReport)
	}
	if !strings.Contains(string(csvReport), "1.1.1.1") || !strings.Contains(string(csvReport), "allow_geo_privacy_clean=1") {
		t.Fatalf("csv report missing expected content: %s", csvReport)
	}
}
