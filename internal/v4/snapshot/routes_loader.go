package snapshot

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gw-ipinfo-nginx/internal/config"

	"gopkg.in/yaml.v3"
)

type routeFile struct {
	Routes []routeEntry `yaml:"routes"`
}

type routeEntry struct {
	ID                    string               `yaml:"id"`
	Host                  string               `yaml:"host"`
	Enabled               *bool                `yaml:"enabled"`
	Backend               routeBackend         `yaml:"backend"`
	SecurityChecksEnabled *bool                `yaml:"security_checks_enabled"`
	IPEnrichmentMode      string               `yaml:"ip_enrichment_mode"`
	Probe                 config.V4ProbeConfig `yaml:"probe"`
}

type routeBackend struct {
	Service string `yaml:"service"`
	Host    string `yaml:"host"`
}

func loadRouteFile(baseConfigPath, value string) ([]config.V4OverrideConfig, error) {
	path := resolveV4FilePath(baseConfigPath, value)
	content, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("read v4 route file %s: %w", path, err)
	}

	var file routeFile
	if err := yaml.Unmarshal([]byte(os.ExpandEnv(string(content))), &file); err != nil {
		return nil, fmt.Errorf("unmarshal v4 route file %s: %w", path, err)
	}

	entries := make([]config.V4OverrideConfig, 0, len(file.Routes))
	var errs []error
	for idx, raw := range file.Routes {
		entry, err := normalizeRouteEntry(path, idx, raw)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		entries = append(entries, entry)
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return entries, nil
}

func normalizeRouteEntry(path string, idx int, raw routeEntry) (config.V4OverrideConfig, error) {
	host, err := normalizeV4Host(raw.Host)
	if err != nil {
		return config.V4OverrideConfig{}, fmt.Errorf("invalid v4 route entry in %s at index %d: %w", path, idx, err)
	}

	enabled := true
	if raw.Enabled != nil {
		enabled = *raw.Enabled
	}

	entry := config.V4OverrideConfig{
		Host:                  host,
		Enabled:               enabled,
		BackendService:        strings.TrimSpace(raw.Backend.Service),
		BackendHost:           strings.TrimSpace(raw.Backend.Host),
		SecurityChecksEnabled: raw.SecurityChecksEnabled,
		IPEnrichmentMode:      strings.TrimSpace(strings.ToLower(raw.IPEnrichmentMode)),
		Probe: config.V4ProbeConfig{
			Enabled:              raw.Probe.Enabled,
			DirectRedirectEnabled: raw.Probe.DirectRedirectEnabled,
			Mode:                 strings.TrimSpace(strings.ToLower(raw.Probe.Mode)),
			URL:                  strings.TrimSpace(raw.Probe.URL),
			HTMLPaths:            normalizeLocalPaths(raw.Probe.HTMLPaths),
			JSPaths:              normalizeLocalPaths(raw.Probe.JSPaths),
			LinkURL:              strings.TrimSpace(raw.Probe.LinkURL),
			RedirectURLs:         normalizeURLs(raw.Probe.RedirectURLs),
			Patterns:             normalizeStrings(raw.Probe.Patterns),
			UnhealthyStatusCodes: append([]int(nil), raw.Probe.UnhealthyStatusCodes...),
			Interval:             raw.Probe.Interval,
			Timeout:              raw.Probe.Timeout,
			HealthyThreshold:     raw.Probe.HealthyThreshold,
			UnhealthyThreshold:   raw.Probe.UnhealthyThreshold,
			MinSwitchInterval:    raw.Probe.MinSwitchInterval,
		},
	}

	if entry.BackendHost != "" {
		normalizedBackendHost, err := normalizeV4Host(entry.BackendHost)
		if err != nil {
			return config.V4OverrideConfig{}, fmt.Errorf("invalid v4 route backend.host for %s in %s: %w", host, path, err)
		}
		entry.BackendHost = normalizedBackendHost
	}
	if entry.IPEnrichmentMode != "" && !isValidV4EnrichmentMode(entry.IPEnrichmentMode) {
		return config.V4OverrideConfig{}, fmt.Errorf("invalid v4 route ip_enrichment_mode for %s in %s: %s", host, path, raw.IPEnrichmentMode)
	}
	if entry.Probe.Mode != "" && !isValidV4ProbeMode(entry.Probe.Mode) {
		return config.V4OverrideConfig{}, fmt.Errorf("invalid v4 route probe.mode for %s in %s: %s", host, path, raw.Probe.Mode)
	}
	if entry.Probe.DirectRedirectEnabled {
		if !entry.Probe.Enabled {
			return config.V4OverrideConfig{}, fmt.Errorf("invalid v4 route probe.direct_redirect_enabled for %s in %s: probe.enabled must be true", host, path)
		}
		if len(entry.Probe.RedirectURLs) == 0 {
			return config.V4OverrideConfig{}, fmt.Errorf("invalid v4 route probe.direct_redirect_enabled for %s in %s: probe.redirect_urls is required", host, path)
		}
	}
	return entry, nil
}

func normalizeV4Host(value string) (string, error) {
	host := strings.ToLower(strings.TrimSpace(value))
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return "", errors.New("host is required")
	}
	if strings.Contains(host, "://") || strings.ContainsAny(host, "/?#") {
		return "", fmt.Errorf("host must not contain scheme/path/query: %s", value)
	}
	if idx := strings.Index(host, ":"); idx > 0 && !strings.Contains(host[idx+1:], ":") {
		host = host[:idx]
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "", errors.New("host is empty after normalization")
	}
	return host, nil
}

func isValidV4EnrichmentMode(value string) bool {
	switch strings.TrimSpace(strings.ToLower(value)) {
	case "", "disabled", "cache_only", "full":
		return true
	default:
		return false
	}
}

func isValidV4ProbeMode(value string) bool {
	switch strings.TrimSpace(strings.ToLower(value)) {
	case "", "local_js", "html_discovery":
		return true
	default:
		return false
	}
}

func resolveV4FilePath(baseConfigPath, value string) string {
	if filepath.IsAbs(value) {
		return filepath.Clean(value)
	}
	return filepath.Join(filepath.Dir(filepath.Clean(baseConfigPath)), value)
}

func normalizeLocalPaths(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = filepath.Clean(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func normalizeURLs(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func normalizeStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
