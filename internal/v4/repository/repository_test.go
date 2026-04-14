package repository

import (
	"testing"

	v4model "gw-ipinfo-nginx/internal/v4/model"
)

func TestSelectSnapshotHostsUsesSnapshotVersionOnly(t *testing.T) {
	snapshot := v4model.Snapshot{Version: "2026-04-14T10:00:00Z"}
	hostsMap := map[string]v4model.SnapshotHost{
		"game.freefun.live": {
			Host:       "game.freefun.live",
			SnapshotID: "2026-04-14T10:00:00Z",
		},
		"spin.gamefun.live": {
			Host:       "spin.gamefun.live",
			SnapshotID: "2026-04-13T10:00:00Z",
		},
	}

	hosts := selectSnapshotHosts(snapshot, hostsMap)
	if len(hosts) != 1 {
		t.Fatalf("selectSnapshotHosts() len = %d, want 1", len(hosts))
	}
	if hosts[0].Host != "game.freefun.live" {
		t.Fatalf("selectSnapshotHosts() host = %q, want %q", hosts[0].Host, "game.freefun.live")
	}
}

func TestValidateLoadedSnapshotRejectsFingerprintMismatch(t *testing.T) {
	repo := &SnapshotRepository{}
	hosts := []v4model.SnapshotHost{
		{
			Host:             "game.freefun.live",
			BackendService:   "luodiye",
			BackendHost:      "game.freefun.live",
			IPEnrichmentMode: "full",
			Probe: v4model.ProbeSpec{
				Enabled: true,
				Mode:    "local_js",
			},
			SecurityChecksEnabled: true,
		},
	}
	snapshot := v4model.Snapshot{
		ID:          "last_good",
		Version:     "2026-04-14T10:00:00Z",
		Fingerprint: "stale-fingerprint",
		HostCount:   1,
	}

	valid, err := repo.validateLoadedSnapshot("mongo", snapshot, hosts)
	if valid {
		t.Fatalf("validateLoadedSnapshot() valid = true, want false")
	}
	if err == nil {
		t.Fatal("validateLoadedSnapshot() error = nil, want mismatch error")
	}
}
