package snapshot

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"gw-ipinfo-nginx/internal/config"
	"gw-ipinfo-nginx/internal/storage"
	"gw-ipinfo-nginx/internal/v4/events"
	v4model "gw-ipinfo-nginx/internal/v4/model"
	"gw-ipinfo-nginx/internal/v4/nginxconf"
	"gw-ipinfo-nginx/internal/v4/repository"
)

type Service struct {
	cfg                 config.V4Config
	routeFile           config.RouteSetFileConfig
	baseConfigPath      string
	parser              *nginxconf.Parser
	repo                *repository.SnapshotRepository
	events              *events.Service
	logger              *slog.Logger
	lease               *syncLeaseStore
	instanceID          string
	serviceNames        map[string]struct{}
	excludedHosts       map[string]struct{}
	legacyWarned        bool
	onUpdated           func(v4model.Snapshot, []v4model.SnapshotHost)
}

func NewService(
	cfg config.V4Config,
	routeFile config.RouteSetFileConfig,
	baseConfigPath string,
	repo *repository.SnapshotRepository,
	eventSvc *events.Service,
	controller *storage.Controller,
	sharedStatePath string,
	instanceID string,
	serviceNames []string,
	logger *slog.Logger,
) *Service {
	names := make(map[string]struct{}, len(serviceNames))
	for _, name := range serviceNames {
		names[strings.TrimSpace(name)] = struct{}{}
	}

	return &Service{
		cfg:            cfg,
		routeFile:      routeFile,
		baseConfigPath: baseConfigPath,
		parser:         nginxconf.NewParser(),
		repo:           repo,
		events:         eventSvc,
		logger:         logger,
		lease:          newSyncLeaseStore(controller, sharedStatePath, cfg.Sync.LeaseName),
		instanceID:     instanceID,
		serviceNames:   names,
		excludedHosts:  make(map[string]struct{}),
	}
}

func (s *Service) SetOnUpdated(fn func(v4model.Snapshot, []v4model.SnapshotHost)) {
	s.onUpdated = fn
}

func (s *Service) SetExcludedHosts(hosts []string) {
	if s == nil {
		return
	}
	next := make(map[string]struct{}, len(hosts))
	for _, host := range hosts {
		host = strings.TrimSpace(strings.ToLower(host))
		if host == "" {
			continue
		}
		next[host] = struct{}{}
	}
	s.excludedHosts = next
}

func (s *Service) Run(ctx context.Context) {
	if s == nil || !s.cfg.Enabled || !s.cfg.Sync.Enabled {
		return
	}

	syncTicker := time.NewTicker(s.cfg.Sync.Interval)
	renewTicker := time.NewTicker(s.cfg.Sync.RenewInterval)
	defer syncTicker.Stop()
	defer renewTicker.Stop()

	isLeader := false
	if s.acquireLeader(ctx) {
		isLeader = true
		_ = s.SyncOnce(ctx)
	}

	for {
		select {
		case <-ctx.Done():
			if isLeader {
				_ = s.lease.Release(context.Background(), s.instanceID)
			}
			return
		case <-renewTicker.C:
			if isLeader {
				ok, err := s.lease.Refresh(ctx, s.instanceID, time.Now().UTC(), s.cfg.Sync.LeaseTTL)
				if err != nil || !ok {
					isLeader = false
					if s.logger != nil {
						s.logger.Warn("v4_snapshot_leader_lost",
							"event", "v4_snapshot_leader_lost",
							"instance_id", s.instanceID,
							"error", err,
						)
					}
				}
				continue
			}
			isLeader = s.acquireLeader(ctx)
		case <-syncTicker.C:
			if !isLeader {
				continue
			}
			_ = s.SyncOnce(ctx)
		}
	}
}

func (s *Service) acquireLeader(ctx context.Context) bool {
	state, acquired, err := s.lease.TryAcquire(ctx, s.instanceID, time.Now().UTC(), s.cfg.Sync.LeaseTTL)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("v4_snapshot_leader_acquire_error",
				"event", "v4_snapshot_leader_acquire_error",
				"lease_name", s.cfg.Sync.LeaseName,
				"instance_id", s.instanceID,
				"error", err,
			)
		}
		return false
	}
	if !acquired {
		return false
	}
	if s.logger != nil {
		s.logger.Info("v4_snapshot_leader_acquired",
			"event", "v4_snapshot_leader_acquired",
			"lease_name", s.cfg.Sync.LeaseName,
			"instance_id", s.instanceID,
			"previous_owner", state.LeaseOwner,
		)
	}
	return true
}

func (s *Service) SyncOnce(ctx context.Context) error {
	now := time.Now().UTC()
	if s.logger != nil {
		s.logger.Info("v4_snapshot_sync_started",
			"event", "v4_snapshot_sync_started",
			"instance_id", s.instanceID,
			"config_paths", s.cfg.Ingress.ConfigPaths,
			"route_file_enabled", s.routeFile.Enabled,
			"route_file_path", s.routeFile.ConfigPath,
		)
	}

	autoHosts, err := s.parser.ParseHosts(ctx, s.cfg.Ingress.ConfigPaths)
	if err != nil {
		s.recordSyncFailure(ctx, now, err, map[string]any{"config_paths": s.cfg.Ingress.ConfigPaths})
		return err
	}
	autoHosts = s.filterExcludedHosts(autoHosts)

	fileEntries, err := s.loadExplicitRoutes()
	if err != nil {
		s.recordSyncFailure(ctx, now, err, map[string]any{"route_file_path": s.routeFile.ConfigPath})
		return err
	}

	snapshotHosts, err := s.compileHosts(autoHosts, fileEntries)
	if err != nil {
		s.recordSyncFailure(ctx, now, err, map[string]any{"route_file_path": s.routeFile.ConfigPath})
		return err
	}
	s.logCompiledOverrides(fileEntries, snapshotHosts)

	if s.logger != nil {
		s.logger.Info("v4_snapshot_sync_compiled",
			"event", "v4_snapshot_sync_compiled",
			"instance_id", s.instanceID,
			"auto_hosts_count", len(autoHosts),
			"explicit_routes_count", len(fileEntries),
			"snapshot_hosts_count", len(snapshotHosts),
		)
	}

	fingerprint := v4model.CanonicalSnapshotFingerprint(snapshotHosts)
	current, _, found, _ := s.repo.LoadLatest(ctx)
	if !found && s.logger != nil {
		s.logger.Info("v4_snapshot_bootstrap_rebuild",
			"event", "v4_snapshot_bootstrap_rebuild",
			"instance_id", s.instanceID,
			"reason", "missing_or_incompatible_history",
		)
	}
	if found && current.Fingerprint == fingerprint {
		_ = s.repo.UpsertSyncState(ctx, v4model.SyncState{
			ID:                  v4model.SyncStateID,
			LeaseName:           s.cfg.Sync.LeaseName,
			LeaseOwner:          s.instanceID,
			LeaseExpiresAt:      now.Add(s.cfg.Sync.LeaseTTL),
			LastSyncAt:          now,
			LastSuccessAt:       now,
			LastStatus:          "success_no_change",
			LastError:           "",
			LastSnapshotVersion: current.Version,
			LastFingerprint:     current.Fingerprint,
			LastHostCount:       current.HostCount,
			UpdatedAt:           now,
		})
		if s.logger != nil {
			s.logger.Info("v4_snapshot_sync_no_change",
				"event", "v4_snapshot_sync_no_change",
				"instance_id", s.instanceID,
				"fingerprint", fingerprint,
				"host_count", len(snapshotHosts),
			)
		}
		return nil
	}

	snapshot := v4model.Snapshot{
		ID:          "last_good",
		Version:     now.Format(time.RFC3339Nano),
		Fingerprint: fingerprint,
		HostCount:   len(snapshotHosts),
		CreatedAt:   now,
		UpdatedAt:   now,
		LastGood:    true,
		Source:      "nginx_conf+v4_routes",
	}
	if err := s.repo.ReplaceLastGood(ctx, snapshot, snapshotHosts); err != nil {
		if s.onUpdated != nil {
			s.onUpdated(snapshot, snapshotHosts)
		}
		if s.logger != nil {
			s.logger.Warn("v4_snapshot_persist_degraded_local_only",
				"event", "v4_snapshot_persist_degraded_local_only",
				"instance_id", s.instanceID,
				"fingerprint", fingerprint,
				"host_count", len(snapshotHosts),
				"error", err,
			)
		}
		s.recordSyncFailure(ctx, now, err, map[string]any{"host_count": len(snapshotHosts), "fingerprint": fingerprint})
		return err
	}

	_ = s.repo.UpsertSyncState(ctx, v4model.SyncState{
		ID:                  v4model.SyncStateID,
		LeaseName:           s.cfg.Sync.LeaseName,
		LeaseOwner:          s.instanceID,
		LeaseExpiresAt:      now.Add(s.cfg.Sync.LeaseTTL),
		LastSyncAt:          now,
		LastSuccessAt:       now,
		LastStatus:          "success",
		LastError:           "",
		LastSnapshotVersion: snapshot.Version,
		LastFingerprint:     snapshot.Fingerprint,
		LastHostCount:       snapshot.HostCount,
		UpdatedAt:           now,
	})

	if s.events != nil {
		_ = s.events.Emit(ctx, v4model.Event{
			Type:        v4model.EventSnapshotUpdated,
			Fingerprint: "snapshot_updated:" + fingerprint,
			Level:       "info",
			Title:       "V4 snapshot updated",
			Message:     fmt.Sprintf("updated v4 snapshot with %d hosts", len(snapshotHosts)),
			Metadata: map[string]any{
				"host_count":   len(snapshotHosts),
				"fingerprint":  fingerprint,
				"route_source": s.routeFile.ConfigPath,
			},
		})
	}
	if s.logger != nil {
		s.logger.Info("v4_snapshot_sync_persisted",
			"event", "v4_snapshot_sync_persisted",
			"instance_id", s.instanceID,
			"fingerprint", fingerprint,
			"host_count", len(snapshotHosts),
		)
	}
	if s.onUpdated != nil {
		s.onUpdated(snapshot, snapshotHosts)
	}
	return nil
}

func (s *Service) loadExplicitRoutes() ([]config.V4OverrideConfig, error) {
	if len(s.cfg.Overrides) > 0 {
		if !s.legacyWarned && s.logger != nil {
			s.logger.Warn("v4_overrides_deprecated",
				"event", "v4_overrides_deprecated",
				"count", len(s.cfg.Overrides),
				"message", "v4.overrides is deprecated; move host-level entries to route_sets.v4.config_path",
			)
		}
		s.legacyWarned = true
	}
	return LoadEffectiveOverrides(s.baseConfigPath, s.cfg, s.routeFile)
}

func (s *Service) compileHosts(autoHosts []string, overrides []config.V4OverrideConfig) ([]v4model.SnapshotHost, error) {
	return BuildEffectiveHosts(BuildAutoHosts(autoHosts, s.cfg), s.cfg, overrides, s.serviceNames)
}

func (s *Service) filterExcludedHosts(hosts []string) []string {
	if len(hosts) == 0 || len(s.excludedHosts) == 0 {
		return hosts
	}
	filtered := make([]string, 0, len(hosts))
	for _, host := range hosts {
		normalized := strings.TrimSpace(strings.ToLower(host))
		if normalized == "" {
			continue
		}
		if _, excluded := s.excludedHosts[normalized]; excluded {
			if s.logger != nil {
				s.logger.Info("v4_snapshot_host_excluded",
					"event", "v4_snapshot_host_excluded",
					"host", normalized,
					"reason", "claimed_by_route_sets",
				)
			}
			continue
		}
		filtered = append(filtered, host)
	}
	return filtered
}

func (s *Service) logCompiledOverrides(overrides []config.V4OverrideConfig, hosts []v4model.SnapshotHost) {
	if s.logger == nil || len(overrides) == 0 {
		return
	}

	byHost := make(map[string]v4model.SnapshotHost, len(hosts))
	for _, host := range hosts {
		byHost[host.Host] = host
	}

	for _, override := range overrides {
		host := strings.TrimSpace(strings.ToLower(override.Host))
		if host == "" {
			continue
		}
		compiled, ok := byHost[host]
		if !ok {
			s.logger.Info("v4_snapshot_route_overlay_compiled",
				"event", "v4_snapshot_route_overlay_compiled",
				"host", host,
				"enabled", override.Enabled,
				"compiled", false,
			)
			continue
		}
		s.logger.Info("v4_snapshot_route_overlay_compiled",
			"event", "v4_snapshot_route_overlay_compiled",
			"host", compiled.Host,
			"enabled", override.Enabled,
			"compiled", true,
			"backend_service", compiled.BackendService,
			"backend_host", compiled.BackendHost,
			"security_checks_enabled", compiled.SecurityChecksEnabled,
			"ip_enrichment_mode", compiled.IPEnrichmentMode,
			"probe_enabled", compiled.Probe.Enabled,
			"probe_mode", compiled.Probe.Mode,
			"redirect_urls_count", len(compiled.Probe.RedirectURLs),
		)
	}
}

func (s *Service) recordSyncFailure(ctx context.Context, now time.Time, err error, metadata map[string]any) {
	_ = s.repo.UpsertSyncState(ctx, v4model.SyncState{
		ID:             v4model.SyncStateID,
		LeaseName:      s.cfg.Sync.LeaseName,
		LeaseOwner:     s.instanceID,
		LeaseExpiresAt: now.Add(s.cfg.Sync.LeaseTTL),
		LastSyncAt:     now,
		LastStatus:     "failed",
		LastError:      strings.TrimSpace(err.Error()),
		UpdatedAt:      now,
	})
	if s.events != nil {
		_ = s.events.Emit(ctx, v4model.Event{
			Type:        v4model.EventSnapshotSyncFailed,
			Host:        "",
			Fingerprint: "snapshot_sync_failed:" + strings.TrimSpace(err.Error()),
			Level:       "error",
			Title:       "V4 snapshot sync failed",
			Message:     err.Error(),
			Metadata:    metadata,
		})
	}
	if s.logger != nil {
		s.logger.Error("v4_snapshot_sync_failed",
			"event", "v4_snapshot_sync_failed",
			"instance_id", s.instanceID,
			"error", err,
			"metadata", metadata,
		)
	}
}

func mergeProbe(defaults config.V4ProbeDefaultsConfig, probe config.V4ProbeConfig) v4model.ProbeSpec {
	return v4model.ProbeSpec{
		Enabled:            probe.Enabled,
		Mode:               probe.Mode,
		URL:                strings.TrimSpace(probe.URL),
		HTMLPaths:          append([]string(nil), probe.HTMLPaths...),
		JSPaths:            append([]string(nil), probe.JSPaths...),
		LinkURL:            strings.TrimSpace(probe.LinkURL),
		RedirectURLs:       append([]string(nil), probe.RedirectURLs...),
		Patterns:           append([]string(nil), probe.Patterns...),
		UnhealthyStatusCodes: firstStatusCodes(probe.UnhealthyStatusCodes, defaults.UnhealthyStatusCodes),
		Interval:           firstDuration(probe.Interval, defaults.Interval),
		Timeout:            firstDuration(probe.Timeout, defaults.Timeout),
		HealthyThreshold:   firstInt(probe.HealthyThreshold, defaults.HealthyThreshold),
		UnhealthyThreshold: firstInt(probe.UnhealthyThreshold, defaults.UnhealthyThreshold),
		MinSwitchInterval:  firstDuration(probe.MinSwitchInterval, defaults.MinSwitchInterval),
	}
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

func firstStatusCodes(values ...[]int) []int {
	for _, set := range values {
		if len(set) == 0 {
			continue
		}
		result := make([]int, 0, len(set))
		for _, value := range set {
			if value <= 0 {
				continue
			}
			result = append(result, value)
		}
		if len(result) > 0 {
			return result
		}
	}
	return nil
}
