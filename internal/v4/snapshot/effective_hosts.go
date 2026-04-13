package snapshot

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"gw-ipinfo-nginx/internal/config"
	v4model "gw-ipinfo-nginx/internal/v4/model"
)

// LoadEffectiveOverrides returns the combined local v4 host overrides from the
// deprecated inline config and the dedicated route file.
func LoadEffectiveOverrides(baseConfigPath string, cfg config.V4Config, routeFile config.RouteSetFileConfig) ([]config.V4OverrideConfig, error) {
	routes := make([]config.V4OverrideConfig, 0, len(cfg.Overrides))
	if len(cfg.Overrides) > 0 {
		routes = append(routes, cfg.Overrides...)
	}
	if !routeFile.Enabled {
		return routes, nil
	}

	fileEntries, err := loadRouteFile(baseConfigPath, routeFile.ConfigPath)
	if err != nil {
		return nil, err
	}
	routes = append(routes, fileEntries...)
	return routes, nil
}

// BuildAutoHosts creates the default v4 host set produced from nginx
// server_name parsing before any route-file overlays are applied.
func BuildAutoHosts(autoHosts []string, cfg config.V4Config) []v4model.SnapshotHost {
	now := time.Now().UTC()
	hosts := make([]v4model.SnapshotHost, 0, len(autoHosts))
	for _, host := range autoHosts {
		hosts = append(hosts, v4model.SnapshotHost{
			ID:                    host,
			SnapshotID:            "last_good",
			Host:                  host,
			Source:                "auto",
			BackendService:        cfg.Passthrough.Service,
			BackendHost:           host,
			SecurityChecksEnabled: cfg.Security.SecurityChecksEnabled,
			IPEnrichmentMode:      cfg.IPEnrichment.Mode,
			UpdatedAt:             now,
		})
	}
	return hosts
}

// BuildEffectiveHosts overlays local route-file host overrides on top of a base
// host set. It is used both when persisting a snapshot and when materializing
// runtime/query views so local pod config can win over stale shared snapshots.
func BuildEffectiveHosts(baseHosts []v4model.SnapshotHost, cfg config.V4Config, overrides []config.V4OverrideConfig, serviceNames map[string]struct{}) ([]v4model.SnapshotHost, error) {
	byHost := make(map[string]v4model.SnapshotHost, len(baseHosts))
	now := time.Now().UTC()

	for _, host := range baseHosts {
		normalizedHost, err := normalizeV4Host(host.Host)
		if err != nil {
			return nil, fmt.Errorf("invalid base v4 host %q: %w", host.Host, err)
		}
		host.Host = normalizedHost
		host.ID = normalizedHost
		if strings.TrimSpace(host.SnapshotID) == "" {
			host.SnapshotID = "last_good"
		}
		if host.UpdatedAt.IsZero() {
			host.UpdatedAt = now
		}
		byHost[normalizedHost] = host
	}

	for _, override := range overrides {
		host, err := normalizeV4Host(override.Host)
		if err != nil {
			return nil, err
		}
		if !override.Enabled {
			delete(byHost, host)
			continue
		}

		entry, ok := byHost[host]
		if !ok {
			entry = v4model.SnapshotHost{
				ID:                    host,
				SnapshotID:            "last_good",
				Host:                  host,
				Source:                "route_file",
				BackendService:        cfg.Passthrough.Service,
				BackendHost:           host,
				SecurityChecksEnabled: cfg.Security.SecurityChecksEnabled,
				IPEnrichmentMode:      cfg.IPEnrichment.Mode,
				UpdatedAt:             now,
			}
		}

		backendService := firstNonEmpty(strings.TrimSpace(override.BackendService), entry.BackendService, cfg.Passthrough.Service)
		if _, ok := serviceNames[backendService]; !ok {
			return nil, fmt.Errorf("v4 backend service %q for host %q is not present in routing.services", backendService, host)
		}
		entry.BackendService = backendService

		backendHost := firstNonEmpty(strings.ToLower(strings.TrimSpace(override.BackendHost)), entry.BackendHost, host)
		normalizedBackendHost, err := normalizeV4Host(backendHost)
		if err != nil {
			return nil, fmt.Errorf("invalid v4 backend host for %q: %w", host, err)
		}
		entry.BackendHost = normalizedBackendHost

		if override.SecurityChecksEnabled != nil {
			entry.SecurityChecksEnabled = *override.SecurityChecksEnabled
		}
		entry.IPEnrichmentMode = firstNonEmpty(override.IPEnrichmentMode, entry.IPEnrichmentMode, cfg.IPEnrichment.Mode)
		entry.Probe = mergeProbe(cfg.ProbeDefaults, override.Probe)
		entry.Source = "route_file"
		entry.UpdatedAt = now
		byHost[host] = entry
	}

	hosts := make([]v4model.SnapshotHost, 0, len(byHost))
	for _, host := range byHost {
		hosts = append(hosts, host)
	}
	sortHosts(hosts)
	return hosts, nil
}

func HostsFingerprint(hosts []v4model.SnapshotHost) string {
	return snapshotFingerprint(hosts)
}

func sortHosts(hosts []v4model.SnapshotHost) {
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Host < hosts[j].Host })
}
