package runtime

import (
	"testing"

	v4model "gw-ipinfo-nginx/internal/v4/model"
)

func TestNormalizeStateForHostResetsStaleSnapshotState(t *testing.T) {
	host := v4model.SnapshotHost{
		Host: "game.freefun.live",
		Probe: v4model.ProbeSpec{
			Enabled: true,
		},
	}
	state := v4model.HostRuntimeState{
		ID:                  "game.freefun.live",
		Host:                "game.freefun.live",
		SnapshotVersion:     "2026-04-13T10:00:00Z",
		SnapshotFingerprint: "old-fingerprint",
		Mode:                v4model.ModeDegradedRedirect,
		RedirectURL:         "https://old.example.com",
		LastProbeTargets:    []string{"https://old.example.com"},
		LastProbeError:      "old error",
	}

	normalized := normalizeStateForHost(host, state, "2026-04-14T10:00:00Z", "new-fingerprint")
	if normalized.Mode != v4model.ModePassthrough {
		t.Fatalf("normalizeStateForHost() mode = %q, want %q", normalized.Mode, v4model.ModePassthrough)
	}
	if normalized.RedirectURL != "" {
		t.Fatalf("normalizeStateForHost() redirect_url = %q, want empty", normalized.RedirectURL)
	}
	if normalized.SnapshotVersion != "2026-04-14T10:00:00Z" {
		t.Fatalf("normalizeStateForHost() snapshot_version = %q", normalized.SnapshotVersion)
	}
	if normalized.SnapshotFingerprint != "new-fingerprint" {
		t.Fatalf("normalizeStateForHost() snapshot_fingerprint = %q", normalized.SnapshotFingerprint)
	}
}

func TestNormalizeStateForHostPreservesCurrentSnapshotState(t *testing.T) {
	host := v4model.SnapshotHost{
		Host: "spin.gamefun.live",
		Probe: v4model.ProbeSpec{
			Enabled: true,
		},
	}
	state := v4model.HostRuntimeState{
		ID:                  "spin.gamefun.live",
		Host:                "spin.gamefun.live",
		SnapshotVersion:     "2026-04-14T10:00:00Z",
		SnapshotFingerprint: "same-fingerprint",
		Mode:                v4model.ModeDegradedRedirect,
		RedirectURL:         "https://redirect.example.com",
		LastProbeTargets:    []string{"https://target.example.com"},
	}

	normalized := normalizeStateForHost(host, state, "2026-04-14T10:00:00Z", "same-fingerprint")
	if normalized.Mode != v4model.ModeDegradedRedirect {
		t.Fatalf("normalizeStateForHost() mode = %q, want %q", normalized.Mode, v4model.ModeDegradedRedirect)
	}
	if normalized.RedirectURL != "https://redirect.example.com" {
		t.Fatalf("normalizeStateForHost() redirect_url = %q", normalized.RedirectURL)
	}
}

func TestRedirectAccessTrackingEnabledForDirectRedirect(t *testing.T) {
	host := v4model.SnapshotHost{
		Host: "promo.example.com",
		Probe: v4model.ProbeSpec{
			Enabled:               true,
			DirectRedirectEnabled: true,
		},
	}
	state := v4model.HostRuntimeState{
		Host: "promo.example.com",
		Mode: v4model.ModePassthrough,
	}

	if !redirectAccessTrackingEnabled(host, state) {
		t.Fatal("redirectAccessTrackingEnabled() = false, want true for direct redirect")
	}
}
