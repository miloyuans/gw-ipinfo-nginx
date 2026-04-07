package shortcircuit

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"gw-ipinfo-nginx/internal/config"
	"gw-ipinfo-nginx/internal/ipctx"
	"gw-ipinfo-nginx/internal/localdisk"
	"gw-ipinfo-nginx/internal/policy"
	"gw-ipinfo-nginx/internal/storage"
)

func TestServiceShortCircuitAllowAndDeny(t *testing.T) {
	service := newTestService(t, 10*time.Hour)

	allowRecord := service.RememberDecision("1.1.1.1", "example.com", "/login", "Mozilla/5.0", policy.Decision{
		Allowed: true,
		Result:  "allow",
		Reason:  "allow_geo_privacy_clean",
	}, &ipctx.Context{CountryCode: "US", City: "New York"})
	if allowRecord.LastDecision != DecisionAllow {
		t.Fatalf("allow decision = %s, want allow", allowRecord.LastDecision)
	}

	hit, source, ok := service.Lookup(context.Background(), "1.1.1.1")
	if !ok || source != SourceL1 {
		t.Fatalf("Lookup() = (%v, %s, %t), want L1 hit", hit, source, ok)
	}
	hit = service.RememberShortCircuitHit(hit)
	if hit.ShortCircuitAllowCount != 1 {
		t.Fatalf("ShortCircuitAllowCount = %d, want 1", hit.ShortCircuitAllowCount)
	}
	if decision := service.Decision(hit); !decision.Allowed || decision.Reason != "allow_geo_privacy_clean" {
		t.Fatalf("Decision() = %#v, want allowed cached decision", decision)
	}

	denyRecord := service.RememberDecision("2.2.2.2", "example.com", "/admin", "Mozilla/5.0", policy.Decision{
		Allowed: false,
		Result:  "deny",
		Reason:  "deny_privacy_vpn",
	}, &ipctx.Context{Privacy: ipctx.PrivacyFlags{VPN: true}})
	if denyRecord.LastDecision != DecisionDeny {
		t.Fatalf("deny decision = %s, want deny", denyRecord.LastDecision)
	}
	denyHit, _, ok := service.Lookup(context.Background(), "2.2.2.2")
	if !ok {
		t.Fatal("Lookup() deny record = miss, want hit")
	}
	denyHit = service.RememberShortCircuitHit(denyHit)
	if denyHit.ShortCircuitDenyCount != 1 {
		t.Fatalf("ShortCircuitDenyCount = %d, want 1", denyHit.ShortCircuitDenyCount)
	}
	if decision := service.Decision(denyHit); decision.Allowed || decision.Reason != "deny_privacy_vpn" {
		t.Fatalf("Decision() = %#v, want denied cached decision", decision)
	}
}

func TestServiceTTLExpiry(t *testing.T) {
	service := newTestService(t, 50*time.Millisecond)
	service.RememberDecision("1.1.1.1", "example.com", "/", "Mozilla/5.0", policy.Decision{
		Allowed: true,
		Result:  "allow",
		Reason:  "allow_geo_privacy_clean",
	}, nil)

	time.Sleep(80 * time.Millisecond)

	if _, _, ok := service.Lookup(context.Background(), "1.1.1.1"); ok {
		t.Fatal("Lookup() after TTL = hit, want miss")
	}
}

func TestServiceConcurrentLookup(t *testing.T) {
	service := newTestService(t, time.Hour)
	service.RememberDecision("1.1.1.1", "example.com", "/", "Mozilla/5.0", policy.Decision{
		Allowed: true,
		Result:  "allow",
		Reason:  "allow_geo_privacy_clean",
	}, nil)

	var wg sync.WaitGroup
	for idx := 0; idx < 128; idx++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				record, source, ok := service.Lookup(context.Background(), "1.1.1.1")
				if !ok || source != SourceL1 || record.LastDecision != DecisionAllow {
					t.Errorf("Lookup() = (%#v, %s, %t), want L1 allow hit", record, source, ok)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func newTestService(t *testing.T, ttl time.Duration) *Service {
	t.Helper()
	store, err := localdisk.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	cfg := &config.Config{}
	cfg.Cache.L1.Enabled = true
	cfg.Cache.L1.ShortCircuitEntries = 1024
	cfg.Cache.L1.Shards = 8
	cfg.Cache.ShortCircuitTTL = ttl
	cfg.Perf.AsyncWriteQueueSize = 128
	cfg.Cache.MongoCollections.DecisionCache = "decision_cache"
	controller := storage.NewController(config.StorageConfig{
		LocalPath:          filepath.Join(t.TempDir(), "controller.db"),
		ReplayInterval:     time.Second,
		MongoProbeInterval: time.Second,
		ReplayBatchSize:    10,
		ReplayWorkers:      1,
	}, config.MongoConfig{}, store, nil)

	return NewService(cfg, controller, nil)
}
