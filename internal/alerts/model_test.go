package alerts

import (
	"testing"
	"time"

	"gw-ipinfo-nginx/internal/policy"
)

func TestDedupeKeyStableWithinWindow(t *testing.T) {
	payload := Payload{
		Type:        "allowed_with_risk",
		NotifyType:  "allowed_with_risk",
		ClientIP:    "1.1.1.1",
		ServiceName: "default",
		Reason:      "allow_privacy_vpn",
		URL:         "/login",
		Timestamp:   time.Unix(1700000000, 0).UTC(),
	}

	key1 := DedupeKey(payload, 10*time.Minute)
	payload.Timestamp = payload.Timestamp.Add(5 * time.Minute)
	key2 := DedupeKey(payload, 10*time.Minute)

	if key1 != key2 {
		t.Fatalf("DedupeKey() keys differ within same window: %s vs %s", key1, key2)
	}
}

func TestSeverityForDecision(t *testing.T) {
	decision := severityForDecision(policy.Decision{Allowed: true, AlertType: "allowed_with_risk"})
	if decision != "warning" {
		t.Fatalf("severityForDecision(allowed_with_risk) = %s, want warning", decision)
	}

	decision = severityForDecision(policy.Decision{Allowed: false, AlertType: "blocked_with_ambiguity"})
	if decision != "high" {
		t.Fatalf("severityForDecision(blocked_with_ambiguity) = %s, want high", decision)
	}
}
