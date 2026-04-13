package runtime

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"gw-ipinfo-nginx/internal/config"
	v4model "gw-ipinfo-nginx/internal/v4/model"
	"gw-ipinfo-nginx/internal/v4/repository"
)

type Resolution struct {
	Host  v4model.SnapshotHost
	State v4model.HostRuntimeState
	Found bool
	Reason string
}

type ProbeUpdate struct {
	Host        string
	Healthy     bool
	SourceURL   string
	RedirectURL string
	RedirectCandidates []string
	ProbeTargets []string
	FailedTargets []string
	WorkspaceFile string
	Error       string
	ProbeAt     time.Time
	Spec        v4model.ProbeSpec
}

type Service struct {
	cfg          config.V4Config
	routeFile    config.RouteSetFileConfig
	baseConfigPath string
	snapshots    *repository.SnapshotRepository
	states       *repository.RuntimeStateRepository
	logger       *slog.Logger
	serviceNames map[string]struct{}
	mu           sync.RWMutex
	hostsByName  map[string]v4model.SnapshotHost
	fingerprint  string
	snapshotVersion string
	snapshotUpdatedAt time.Time
}

func NewService(cfg config.V4Config, routeFile config.RouteSetFileConfig, baseConfigPath string, serviceNames []string, snapshots *repository.SnapshotRepository, states *repository.RuntimeStateRepository, logger *slog.Logger) *Service {
	names := make(map[string]struct{}, len(serviceNames))
	for _, name := range serviceNames {
		names[strings.TrimSpace(name)] = struct{}{}
	}
	return &Service{
		cfg:            cfg,
		routeFile:      routeFile,
		baseConfigPath: baseConfigPath,
		snapshots:      snapshots,
		states:         states,
		logger:         logger,
		serviceNames:   names,
		hostsByName:    make(map[string]v4model.SnapshotHost),
	}
}

func (s *Service) Enabled() bool {
	return s != nil && s.cfg.Enabled
}

func (s *Service) Run(ctx context.Context) {
	if !s.Enabled() || s.snapshots == nil {
		return
	}
	s.refreshSnapshot(ctx)
	interval := s.cfg.Sync.Interval
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.refreshSnapshot(ctx)
		}
	}
}

func (s *Service) ReplaceSnapshot(snapshot v4model.Snapshot, hosts []v4model.SnapshotHost) bool {
	return s.replaceSnapshot(snapshot, hosts)
}

func (s *Service) replaceSnapshot(snapshot v4model.Snapshot, hosts []v4model.SnapshotHost) bool {
	effectiveFingerprint := snapshotFingerprint(hosts)
	s.mu.Lock()
	defer s.mu.Unlock()
	if isOlderSnapshot(snapshot, s.snapshotUpdatedAt, s.snapshotVersion) {
		if s.logger != nil {
			s.logger.Info("v4_runtime_snapshot_ignored",
				"event", "v4_runtime_snapshot_ignored",
				"reason", "stale_snapshot",
				"incoming_version", strings.TrimSpace(snapshot.Version),
				"incoming_updated_at", snapshot.UpdatedAt,
				"current_version", s.snapshotVersion,
				"current_updated_at", s.snapshotUpdatedAt,
			)
		}
		return false
	}
	if s.fingerprint == effectiveFingerprint && effectiveFingerprint != "" {
		return false
	}
	next := make(map[string]v4model.SnapshotHost, len(hosts))
	for _, host := range hosts {
		next[host.Host] = host
	}
	s.hostsByName = next
	s.fingerprint = effectiveFingerprint
	s.snapshotVersion = strings.TrimSpace(snapshot.Version)
	s.snapshotUpdatedAt = snapshot.UpdatedAt.UTC()
	return true
}

func (s *Service) refreshSnapshot(ctx context.Context) {
	snapshot, hosts, found, err := s.snapshots.LoadLatest(ctx)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("v4_runtime_snapshot_refresh_error",
				"event", "v4_runtime_snapshot_refresh_error",
				"error", err,
			)
		}
		return
	}
	if !found {
		if s.logger != nil {
			s.logger.Info("v4_runtime_snapshot_missing",
				"event", "v4_runtime_snapshot_missing",
			)
		}
		return
	}

	if !s.replaceSnapshot(snapshot, hosts) {
		return
	}
	if s.logger != nil {
		s.logger.Info("v4_runtime_snapshot_refreshed",
			"event", "v4_runtime_snapshot_refreshed",
			"fingerprint", s.currentFingerprint(),
			"host_count", s.hostCount(),
		)
	}
}

func (s *Service) currentFingerprint() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.fingerprint
}

func (s *Service) hostCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.hostsByName)
}

func (s *Service) Resolve(ctx context.Context, req *http.Request) Resolution {
	if !s.Enabled() {
		return Resolution{Reason: "v4_disabled"}
	}
	host := normalizeRequestHost(req.Host)
	if host == "" {
		return Resolution{Reason: "empty_host"}
	}

	s.mu.RLock()
	spec, ok := s.hostsByName[host]
	hasSnapshot := len(s.hostsByName) > 0
	s.mu.RUnlock()
	if !hasSnapshot {
		return Resolution{Reason: "no_snapshot"}
	}
	if !ok {
		return Resolution{Reason: "host_not_found"}
	}

	state, found, err := s.states.Get(ctx, host)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("v4_runtime_state_load_error", "event", "v4_runtime_state_load_error", "host", host, "error", err)
		}
	}
	if !found {
		state = v4model.HostRuntimeState{
			ID:        host,
			Host:      host,
			Mode:      v4model.ModePassthrough,
			UpdatedAt: time.Now().UTC(),
		}
	}
	state = normalizeStateForHost(spec, state)
	return Resolution{Host: spec, State: state, Found: true, Reason: "matched"}
}

func (s *Service) ApplyProbeUpdate(ctx context.Context, update ProbeUpdate) (v4model.HostRuntimeState, bool, bool, error) {
	state, _, err := s.states.Get(ctx, update.Host)
	if err != nil {
		return v4model.HostRuntimeState{}, false, false, err
	}
	if state.Host == "" {
		state = v4model.HostRuntimeState{
			ID:   update.Host,
			Host: update.Host,
			Mode: v4model.ModePassthrough,
		}
	}

	now := update.ProbeAt.UTC()
	state.LastProbeAt = now
	state.LastProbeError = strings.TrimSpace(update.Error)
	state.SourceURL = strings.TrimSpace(update.SourceURL)
	state.RedirectCandidates = append([]string(nil), update.RedirectCandidates...)
	state.LastProbeTargets = append([]string(nil), update.ProbeTargets...)
	state.LastFailedTargets = append([]string(nil), update.FailedTargets...)
	state.WorkspaceFile = strings.TrimSpace(update.WorkspaceFile)
	modeChanged := false
	recovered := false

	if update.Healthy {
		state.HealthyCount++
		state.UnhealthyCount = 0
		state.LastHealthyAt = now
		if state.Mode == v4model.ModeDegradedRedirect || state.Mode == v4model.ModeRecovering {
			if state.Mode != v4model.ModeRecovering {
				state.Mode = v4model.ModeRecovering
				modeChanged = true
			}
			if state.HealthyCount >= update.Spec.HealthyThreshold && switchAllowed(state.LastSwitchAt, now, update.Spec.MinSwitchInterval) {
				state.Mode = v4model.ModePassthrough
				state.RedirectURL = ""
				state.LastSwitchAt = now
				modeChanged = true
				recovered = true
			}
		}
	} else {
		state.UnhealthyCount++
		state.HealthyCount = 0
		state.LastUnhealthyAt = now
		if update.RedirectURL != "" {
			state.RedirectURL = update.RedirectURL
		}
		if state.UnhealthyCount >= update.Spec.UnhealthyThreshold && update.RedirectURL != "" && switchAllowed(state.LastSwitchAt, now, update.Spec.MinSwitchInterval) {
			if state.Mode != v4model.ModeDegradedRedirect || state.RedirectURL != update.RedirectURL {
				state.Mode = v4model.ModeDegradedRedirect
				state.LastSwitchAt = now
				modeChanged = true
			}
		}
	}
	if state.Mode == v4model.ModePassthrough && strings.TrimSpace(state.RedirectURL) != "" {
		state.RedirectURL = ""
	}

	state.UpdatedAt = now
	if err := s.states.Upsert(ctx, state); err != nil {
		return v4model.HostRuntimeState{}, false, false, err
	}
	return state, modeChanged, recovered, nil
}

func (s *Service) ProbeHosts() []v4model.SnapshotHost {
	s.mu.RLock()
	defer s.mu.RUnlock()
	hosts := make([]v4model.SnapshotHost, 0, len(s.hostsByName))
	for _, host := range s.hostsByName {
		if host.Probe.Enabled {
			hosts = append(hosts, host)
		}
	}
	return hosts
}

func normalizeRequestHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if idx := strings.Index(host, ":"); idx > 0 && !strings.Contains(host[idx+1:], ":") {
		host = host[:idx]
	}
	return strings.TrimSuffix(host, ".")
}

func switchAllowed(lastSwitchAt, now time.Time, interval time.Duration) bool {
	if interval <= 0 || lastSwitchAt.IsZero() {
		return true
	}
	return !lastSwitchAt.Add(interval).After(now)
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
			boolString(host.SecurityChecksEnabled),
			boolString(host.Probe.Enabled),
			host.Probe.Mode,
			host.Probe.URL,
			strings.Join(host.Probe.HTMLPaths, ","),
			strings.Join(host.Probe.JSPaths, ","),
			host.Probe.LinkURL,
			strings.Join(host.Probe.RedirectURLs, ","),
			strings.Join(host.Probe.Patterns, ","),
			strings.Join(intStrings(host.Probe.UnhealthyStatusCodes), ","),
			host.Probe.Interval.String(),
			host.Probe.Timeout.String(),
			strconv.Itoa(host.Probe.HealthyThreshold),
			strconv.Itoa(host.Probe.UnhealthyThreshold),
			host.Probe.MinSwitchInterval.String(),
		}, "|"))
	}
	return strings.Join(parts, "\n")
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func intStrings(values []int) []string {
	if len(values) == 0 {
		return nil
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, strconv.Itoa(value))
	}
	return result
}

func normalizeStateForHost(host v4model.SnapshotHost, state v4model.HostRuntimeState) v4model.HostRuntimeState {
	if strings.TrimSpace(state.ID) == "" {
		state.ID = host.Host
	}
	if strings.TrimSpace(state.Host) == "" {
		state.Host = host.Host
	}

	switch strings.TrimSpace(state.Mode) {
	case "", v4model.ModePassthrough:
		state.Mode = v4model.ModePassthrough
	case v4model.ModeDegradedRedirect, v4model.ModeRecovering:
	default:
		state.Mode = v4model.ModePassthrough
	}

	if !host.Probe.Enabled {
		state.Mode = v4model.ModePassthrough
		state.RedirectURL = ""
		state.LastProbeTargets = nil
		state.LastFailedTargets = nil
		state.LastProbeError = ""
		return state
	}

	if state.Mode == v4model.ModePassthrough {
		state.RedirectURL = ""
	}
	return state
}

func isOlderSnapshot(incoming v4model.Snapshot, currentUpdatedAt time.Time, currentVersion string) bool {
	incomingVersion := strings.TrimSpace(incoming.Version)
	if currentUpdatedAt.IsZero() && strings.TrimSpace(currentVersion) == "" {
		return false
	}

	incomingUpdatedAt := incoming.UpdatedAt.UTC()
	if !incomingUpdatedAt.IsZero() && !currentUpdatedAt.IsZero() {
		if incomingUpdatedAt.Before(currentUpdatedAt) {
			return true
		}
		if incomingUpdatedAt.After(currentUpdatedAt) {
			return false
		}
	}

	if incomingVersion != "" && strings.TrimSpace(currentVersion) != "" {
		return incomingVersion < strings.TrimSpace(currentVersion)
	}
	return false
}
