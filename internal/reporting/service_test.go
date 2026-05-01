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
	cfg.Reports.Title = "gw-ipinfo-nginx Daily Report"
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

	service, err := NewService(cfg, controller, nil, nil, nil, "worker-1", filepath.Join(t.TempDir(), "shared.db"))
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
	if !strings.Contains(string(htmlReport), "gw-ipinfo-nginx Daily Report") || !strings.Contains(string(htmlReport), "2026-04-07") {
		t.Fatalf("html report missing heading: %s", htmlReport)
	}
	if !strings.Contains(string(htmlReport), "example.com") || !strings.Contains(string(htmlReport), "San Francisco") {
		t.Fatalf("html report missing expected content: %s", htmlReport)
	}
	if !strings.Contains(string(csvReport), "1.1.1.1") || !strings.Contains(string(csvReport), "allow_geo_privacy_clean=1") {
		t.Fatalf("csv report missing expected content: %s", csvReport)
	}
}

func TestSummaryV4RedirectCounts(t *testing.T) {
	direct := Summary{
		RedirectCount: 2,
		AllowReasons: map[string]uint64{
			"allow_v4_direct_redirect": 2,
		},
	}
	if got := summaryV4DirectRedirectCount(direct); got != 2 {
		t.Fatalf("summaryV4DirectRedirectCount() = %d, want 2", got)
	}

	degraded := Summary{
		RedirectCount: 3,
		AllowReasons: map[string]uint64{
			"allow_v4_redirect_no_real_ip": 3,
		},
	}
	if got := summaryV4DegradedRedirectCount(degraded); got != 3 {
		t.Fatalf("summaryV4DegradedRedirectCount() = %d, want 3", got)
	}
}

func TestLoadRangeMergesLocalSummariesByHostAndIP(t *testing.T) {
	store, err := localdisk.Open(filepath.Join(t.TempDir(), "report.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	cfg := &config.Config{}
	cfg.Reports.TimeZone = "UTC"
	cfg.Reports.TopN = 5
	cfg.Cache.MongoCollections.ReportEvents = "reports"
	cfg.Perf.StatsQueueSize = 128
	controller := storage.NewController(config.StorageConfig{
		LocalPath:          filepath.Join(t.TempDir(), "controller.db"),
		ReplayInterval:     time.Second,
		MongoProbeInterval: time.Second,
		ReplayBatchSize:    10,
		ReplayWorkers:      1,
	}, config.MongoConfig{}, store, nil)

	service, err := NewService(cfg, controller, nil, nil, nil, "worker-1", filepath.Join(t.TempDir(), "shared.db"))
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	first := time.Date(2026, 4, 7, 8, 0, 0, 0, time.UTC)
	second := first.AddDate(0, 0, 1)
	for _, ts := range []time.Time{first, second} {
		if err := service.persist(context.Background(), Event{
			Timestamp:        ts,
			ClientIP:         "1.1.1.1",
			Host:             "example.com",
			Path:             "/login",
			UserAgentSummary: "chrome",
			Allowed:          true,
			ReasonCode:       "allow_geo_privacy_clean",
		}); err != nil {
			t.Fatalf("persist() error = %v", err)
		}
	}

	summaries, err := service.loadRange(context.Background(), first, second.Add(time.Hour))
	if err != nil {
		t.Fatalf("loadRange() error = %v", err)
	}
	if len(summaries) != 1 {
		t.Fatalf("loadRange() len = %d, want 1", len(summaries))
	}
	if summaries[0].AllowCount != 2 {
		t.Fatalf("merged AllowCount = %d, want 2", summaries[0].AllowCount)
	}
}
