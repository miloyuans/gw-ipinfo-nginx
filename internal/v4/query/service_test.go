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

func TestBuildRouteStatsCountsDirectRedirectHosts(t *testing.T) {
	snapshot := v4model.Snapshot{
		Version:     "2026-04-14T10:00:00Z",
		Fingerprint: "current-fingerprint",
	}
	hosts := []v4model.SnapshotHost{
		{
			Host: "promo.example.com",
			Probe: v4model.ProbeSpec{
				Enabled:               true,
				DirectRedirectEnabled: true,
				RedirectURLs:          []string{"https://fallback.example.net/", "https://fallback2.example.net/"},
			},
		},
		{
			Host: "game.example.com",
			Probe: v4model.ProbeSpec{
				Enabled: true,
			},
		},
	}
	states := map[string]v4model.HostRuntimeState{
		"promo.example.com": {
			Host:                      "promo.example.com",
			SnapshotVersion:           snapshot.Version,
			SnapshotFingerprint:       snapshot.Fingerprint,
			Mode:                      v4model.ModePassthrough,
			RedirectUniqueClientCount: 3,
		},
		"game.example.com": {
			Host:                "game.example.com",
			SnapshotVersion:     snapshot.Version,
			SnapshotFingerprint: snapshot.Fingerprint,
			Mode:                v4model.ModeDegradedRedirect,
			RedirectURL:         "https://runtime-fallback.example.net/",
		},
	}

	stats := buildRouteStats(snapshot, hosts, states)
	if stats.DirectRedirectHosts != 1 || stats.ActiveDirectRedirectHosts != 1 {
		t.Fatalf("direct redirect stats = (%d, %d), want (1, 1)", stats.DirectRedirectHosts, stats.ActiveDirectRedirectHosts)
	}
	if stats.ActiveDegradedRedirectHosts != 1 {
		t.Fatalf("ActiveDegradedRedirectHosts = %d, want 1", stats.ActiveDegradedRedirectHosts)
	}
	if stats.RedirectPoolTargets != 2 {
		t.Fatalf("RedirectPoolTargets = %d, want 2", stats.RedirectPoolTargets)
	}
	if stats.RedirectClients != 3 {
		t.Fatalf("RedirectClients = %d, want 3", stats.RedirectClients)
	}
}

func TestBuildHostNoteEntriesOmitsRecoveredHistoricalFault(t *testing.T) {
	host := v4model.SnapshotHost{
		Host: "game.freefun.live",
		Probe: v4model.ProbeSpec{
			Enabled: true,
		},
	}
	state := v4model.HostRuntimeState{
		Host:            "game.freefun.live",
		Mode:            v4model.ModePassthrough,
		FaultActive:     false,
		FaultCount:      2,
		LastFaultReason: "https://apps.apple.com/app/old/id123 returned unhealthy status 404",
	}

	entries := buildHostNoteEntries(host, state)
	if len(entries) != 0 {
		t.Fatalf("buildHostNoteEntries() = %#v, want no current fault notes", entries)
	}
}

func TestBuildHostNoteEntriesShowsActiveFault(t *testing.T) {
	host := v4model.SnapshotHost{
		Host: "game.freefun.live",
		Probe: v4model.ProbeSpec{
			Enabled: true,
		},
	}
	state := v4model.HostRuntimeState{
		Host:            "game.freefun.live",
		Mode:            v4model.ModeDegradedRedirect,
		FaultActive:     true,
		FaultCount:      2,
		LastFaultReason: "https://apps.apple.com/app/current/id456 returned unhealthy status 404",
	}

	entries := buildHostNoteEntries(host, state)
	if len(entries) == 0 {
		t.Fatal("buildHostNoteEntries() returned no entries, want active fault note")
	}
	if entries[0].Value != state.LastFaultReason {
		t.Fatalf("fault note value = %q, want %q", entries[0].Value, state.LastFaultReason)
	}
}
