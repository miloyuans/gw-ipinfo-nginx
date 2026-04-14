package query

import (
	"testing"

	v4model "gw-ipinfo-nginx/internal/v4/model"
)

func TestNormalizeDisplayedStateIgnoresStaleRuntimeState(t *testing.T) {
	snapshot := v4model.Snapshot{
		Version:     "2026-04-14T10:00:00Z",
		Fingerprint: "current-fingerprint",
	}
	host := v4model.SnapshotHost{
		Host: "game.freefun.live",
		Probe: v4model.ProbeSpec{
			Enabled: true,
		},
	}
	state := v4model.HostRuntimeState{
		Host:                "game.freefun.live",
		SnapshotVersion:     "2026-04-13T10:00:00Z",
		SnapshotFingerprint: "old-fingerprint",
		Mode:                v4model.ModeDegradedRedirect,
		RedirectURL:         "https://old.example.com",
		LastProbeError:      "old error",
	}

	normalized := normalizeDisplayedState(snapshot, host, state)
	if normalized.Mode != v4model.ModePassthrough {
		t.Fatalf("normalizeDisplayedState() mode = %q, want %q", normalized.Mode, v4model.ModePassthrough)
	}
	if normalized.RedirectURL != "" {
		t.Fatalf("normalizeDisplayedState() redirect_url = %q, want empty", normalized.RedirectURL)
	}
	if normalized.SnapshotVersion != snapshot.Version {
		t.Fatalf("normalizeDisplayedState() snapshot_version = %q", normalized.SnapshotVersion)
	}
	if normalized.SnapshotFingerprint != snapshot.Fingerprint {
		t.Fatalf("normalizeDisplayedState() snapshot_fingerprint = %q", normalized.SnapshotFingerprint)
	}
}
