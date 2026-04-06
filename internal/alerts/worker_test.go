package alerts

import (
	"testing"
	"time"

	"gw-ipinfo-nginx/internal/config"
)

func TestBackoffCapsAtMax(t *testing.T) {
	cfg := config.DeliveryConfig{
		BaseBackoff: 2 * time.Second,
		MaxBackoff:  10 * time.Second,
	}

	if value := backoff(cfg, 1); value != 2*time.Second {
		t.Fatalf("backoff(attempt=1) = %s, want 2s", value)
	}
	if value := backoff(cfg, 4); value != 10*time.Second {
		t.Fatalf("backoff(attempt=4) = %s, want capped 10s", value)
	}
}
