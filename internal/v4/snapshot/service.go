package snapshot

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"gw-ipinfo-nginx/internal/config"
	"gw-ipinfo-nginx/internal/v4/events"
	"gw-ipinfo-nginx/internal/v4/nginxconf"
	"gw-ipinfo-nginx/internal/v4/repository"
	v4model "gw-ipinfo-nginx/internal/v4/model"
)

type Service struct {
	cfg       config.V4Config
	parser    *nginxconf.Parser
	repo      *repository.SnapshotRepository
	events    *events.Service
	logger    *slog.Logger
	onUpdated func(v4model.Snapshot, []v4model.SnapshotHost)
}

func NewService(cfg config.V4Config, repo *repository.SnapshotRepository, eventSvc *events.Service, logger *slog.Logger) *Service {
	return &Service{
		cfg:    cfg,
		parser: nginxconf.NewParser(),
		repo:   repo,
		events: eventSvc,
		logger: logger,
	}
}

func (s *Service) SetOnUpdated(fn func(v4model.Snapshot, []v4model.SnapshotHost)) {
	s.onUpdated = fn
}

func (s *Service) Run(ctx context.Context) {
	if s == nil || !s.cfg.Enabled || !s.cfg.Sync.Enabled {
		return
	}
	_ = s.SyncOnce(ctx)
	ticker := time.NewTicker(s.cfg.Sync.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = s.SyncOnce(ctx)
		}
	}
}

func (s *Service) SyncOnce(ctx context.Context) error {
	hosts, err := s.parser.ParseHosts(ctx, s.cfg.Ingress.ConfigPaths)
	if err != nil {
		if s.events != nil {
			_ = s.events.Emit(ctx, v4model.Event{
				Type:      v4model.EventSnapshotSyncFailed,
				Host:      "",
				Fingerprint: "snapshot_sync_failed:" + strings.TrimSpace(err.Error()),
				Level:     "error",
				Title:     "V4 snapshot sync failed",
				Message:   err.Error(),
				Metadata:  map[string]any{"config_paths": s.cfg.Ingress.ConfigPaths},
			})
		}
		return err
	}

	snapshotHosts := s.compileHosts(hosts)
	fingerprint := snapshotFingerprint(snapshotHosts)
	current, _, found, _ := s.repo.LoadLatest(ctx)
	if found && current.Fingerprint == fingerprint {
		return nil
	}

	now := time.Now().UTC()
	snapshot := v4model.Snapshot{
		ID:          "last_good",
		Version:     now.Format(time.RFC3339Nano),
		Fingerprint: fingerprint,
		HostCount:   len(snapshotHosts),
		CreatedAt:   now,
		UpdatedAt:   now,
		LastGood:    true,
		Source:      "nginx_conf",
	}
	if err := s.repo.ReplaceLastGood(ctx, snapshot, snapshotHosts); err != nil {
		if s.events != nil {
			_ = s.events.Emit(ctx, v4model.Event{
				Type:        v4model.EventSnapshotSyncFailed,
				Fingerprint: "snapshot_persist_failed:" + strings.TrimSpace(err.Error()),
				Level:       "error",
				Title:       "V4 snapshot persist failed",
				Message:     err.Error(),
			})
		}
		return err
	}
	if s.events != nil {
		_ = s.events.Emit(ctx, v4model.Event{
			Type:        v4model.EventSnapshotUpdated,
			Fingerprint: "snapshot_updated:" + fingerprint,
			Level:       "info",
			Title:       "V4 snapshot updated",
			Message:     fmt.Sprintf("updated v4 snapshot with %d hosts", len(snapshotHosts)),
			Metadata:    map[string]any{"host_count": len(snapshotHosts), "fingerprint": fingerprint},
		})
	}
	if s.onUpdated != nil {
		s.onUpdated(snapshot, snapshotHosts)
	}
	return nil
}

func (s *Service) compileHosts(autoHosts []string) []v4model.SnapshotHost {
	byHost := make(map[string]v4model.SnapshotHost)
	now := time.Now().UTC()
	for _, host := range autoHosts {
		byHost[host] = v4model.SnapshotHost{
			ID:                    host,
			SnapshotID:            "last_good",
			Host:                  host,
			Source:                "auto",
			BackendService:        s.cfg.Passthrough.Service,
			BackendHost:           host,
			SecurityChecksEnabled: s.cfg.Security.SecurityChecksEnabled,
			IPEnrichmentMode:      s.cfg.IPEnrichment.Mode,
			UpdatedAt:             now,
		}
	}
	for _, override := range s.cfg.Overrides {
		host := strings.TrimSpace(strings.ToLower(override.Host))
		if host == "" {
			continue
		}
		if !override.Enabled {
			delete(byHost, host)
			continue
		}
		entry, ok := byHost[host]
		if !ok {
			entry = v4model.SnapshotHost{
				ID:         host,
				SnapshotID: "last_good",
				Host:       host,
				Source:     "override",
				UpdatedAt:  now,
			}
		}
		entry.BackendService = firstNonEmpty(override.BackendService, entry.BackendService, s.cfg.Passthrough.Service)
		entry.BackendHost = firstNonEmpty(strings.ToLower(strings.TrimSpace(override.BackendHost)), entry.BackendHost, host)
		if override.SecurityChecksEnabled != nil {
			entry.SecurityChecksEnabled = *override.SecurityChecksEnabled
		}
		entry.IPEnrichmentMode = firstNonEmpty(override.IPEnrichmentMode, entry.IPEnrichmentMode, s.cfg.IPEnrichment.Mode)
		entry.Probe = mergeProbe(s.cfg.ProbeDefaults, override.Probe)
		entry.Source = "override"
		entry.UpdatedAt = now
		byHost[host] = entry
	}
	hosts := make([]v4model.SnapshotHost, 0, len(byHost))
	for _, host := range byHost {
		hosts = append(hosts, host)
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Host < hosts[j].Host })
	return hosts
}

func mergeProbe(defaults config.V4ProbeDefaultsConfig, probe config.V4ProbeConfig) v4model.ProbeSpec {
	return v4model.ProbeSpec{
		Enabled:            probe.Enabled,
		Mode:               probe.Mode,
		URL:                strings.TrimSpace(probe.URL),
		LinkURL:            strings.TrimSpace(probe.LinkURL),
		Patterns:           append([]string(nil), probe.Patterns...),
		Interval:           firstDuration(probe.Interval, defaults.Interval),
		Timeout:            firstDuration(probe.Timeout, defaults.Timeout),
		HealthyThreshold:   firstInt(probe.HealthyThreshold, defaults.HealthyThreshold),
		UnhealthyThreshold: firstInt(probe.UnhealthyThreshold, defaults.UnhealthyThreshold),
		MinSwitchInterval:  firstDuration(probe.MinSwitchInterval, defaults.MinSwitchInterval),
	}
}

func snapshotFingerprint(hosts []v4model.SnapshotHost) string {
	parts := make([]string, 0, len(hosts))
	for _, host := range hosts {
		parts = append(parts, strings.Join([]string{
			host.Host,
			host.Source,
			host.BackendService,
			host.BackendHost,
			host.IPEnrichmentMode,
			fmt.Sprintf("%t", host.SecurityChecksEnabled),
			fmt.Sprintf("%t", host.Probe.Enabled),
			host.Probe.Mode,
			host.Probe.URL,
			host.Probe.LinkURL,
			strings.Join(host.Probe.Patterns, ","),
		}, "|"))
	}
	sum := sha1.Sum([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(sum[:])
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func firstDuration(values ...time.Duration) time.Duration {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}

func firstInt(values ...int) int {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}
