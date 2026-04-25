package runtime

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"reflect"
	"sort"
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
	SwitchFailed bool
	SwitchFailureReason string
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
	instanceID   string
	instanceStartedAt time.Time
	serviceNames map[string]struct{}
	mu           sync.RWMutex
	hostsByName  map[string]v4model.SnapshotHost
	statesByHost map[string]v4model.HostRuntimeState
	fingerprint  string
	snapshotVersion string
	snapshotUpdatedAt time.Time
}

func NewService(cfg config.V4Config, routeFile config.RouteSetFileConfig, baseConfigPath string, serviceNames []string, snapshots *repository.SnapshotRepository, states *repository.RuntimeStateRepository, logger *slog.Logger, instanceID string, instanceStartedAt time.Time) *Service {
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
		instanceID:     strings.TrimSpace(instanceID),
		instanceStartedAt: instanceStartedAt.UTC(),
		serviceNames:   names,
		hostsByName:    make(map[string]v4model.SnapshotHost),
		statesByHost:   make(map[string]v4model.HostRuntimeState),
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
	s.refreshStates(ctx)
	interval := s.cfg.Sync.ReadModelRefreshInterval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.refreshSnapshot(ctx)
			s.refreshStates(ctx)
		}
	}
}

func (s *Service) ReplaceSnapshot(snapshot v4model.Snapshot, hosts []v4model.SnapshotHost) bool {
	changed := s.replaceSnapshot(snapshot, hosts)
	if changed {
		s.reconcileSnapshotState(context.Background(), snapshot, hosts)
		s.refreshStates(context.Background())
	}
	return changed
}

func (s *Service) replaceSnapshot(snapshot v4model.Snapshot, hosts []v4model.SnapshotHost) bool {
	effectiveFingerprint := v4model.CanonicalSnapshotFingerprint(hosts)
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

func (s *Service) clearSnapshotState() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hostsByName = make(map[string]v4model.SnapshotHost)
	s.statesByHost = make(map[string]v4model.HostRuntimeState)
	s.fingerprint = ""
	s.snapshotVersion = ""
	s.snapshotUpdatedAt = time.Time{}
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
		s.clearSnapshotState()
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
	s.reconcileSnapshotState(ctx, snapshot, hosts)
	if s.logger != nil {
		s.logger.Info("v4_runtime_snapshot_refreshed",
			"event", "v4_runtime_snapshot_refreshed",
			"version", strings.TrimSpace(snapshot.Version),
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

func (s *Service) refreshStates(ctx context.Context) {
	if s == nil || s.states == nil {
		return
	}

	s.mu.RLock()
	if len(s.hostsByName) == 0 {
		s.mu.RUnlock()
		return
	}
	hosts := make([]v4model.SnapshotHost, 0, len(s.hostsByName))
	for _, host := range s.hostsByName {
		hosts = append(hosts, host)
	}
	snapshotVersion := s.snapshotVersion
	snapshotFingerprint := s.fingerprint
	s.mu.RUnlock()

	states, err := s.states.List(ctx)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("v4_runtime_state_refresh_error",
				"event", "v4_runtime_state_refresh_error",
				"version", strings.TrimSpace(snapshotVersion),
				"fingerprint", strings.TrimSpace(snapshotFingerprint),
				"error", err,
			)
		}
		return
	}

	stateByHost := make(map[string]v4model.HostRuntimeState, len(states))
	for _, state := range states {
		stateByHost[strings.TrimSpace(state.Host)] = state
	}

	next := make(map[string]v4model.HostRuntimeState, len(hosts))
	for _, host := range hosts {
		next[host.Host] = normalizeStateForHost(host, stateByHost[host.Host], snapshotVersion, snapshotFingerprint)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.snapshotVersion != snapshotVersion || s.fingerprint != snapshotFingerprint {
		return
	}
	s.statesByHost = next
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
	snapshotVersion := s.snapshotVersion
	snapshotFingerprint := s.fingerprint
	state, found := s.statesByHost[host]
	s.mu.RUnlock()
	if !hasSnapshot {
		return Resolution{Reason: "no_snapshot"}
	}
	if !ok {
		return Resolution{Reason: "host_not_found"}
	}

	if !found {
		state = v4model.HostRuntimeState{
			ID:                 host,
			Host:               host,
			SnapshotVersion:    snapshotVersion,
			SnapshotFingerprint: snapshotFingerprint,
			WriterInstanceID:   s.instanceID,
			WriterStartedAt:    s.instanceStartedAt,
			Mode:               v4model.ModePassthrough,
			UpdatedAt:          time.Now().UTC(),
		}
	}
	state = normalizeStateForHost(spec, state, snapshotVersion, snapshotFingerprint)
	return Resolution{Host: spec, State: state, Found: true, Reason: "matched"}
}

func (s *Service) reconcileSnapshotState(ctx context.Context, snapshot v4model.Snapshot, hosts []v4model.SnapshotHost) {
	if s == nil || s.states == nil || len(hosts) == 0 {
		return
	}

	states, err := s.states.List(ctx)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("v4_runtime_state_reconcile_list_error",
				"event", "v4_runtime_state_reconcile_list_error",
				"version", strings.TrimSpace(snapshot.Version),
				"fingerprint", strings.TrimSpace(snapshot.Fingerprint),
				"error", err,
			)
		}
		return
	}

	stateByHost := make(map[string]v4model.HostRuntimeState, len(states))
	for _, state := range states {
		stateByHost[strings.TrimSpace(state.Host)] = state
	}

	now := time.Now().UTC()
	updated := 0
	for _, host := range hosts {
		current := stateByHost[host.Host]
		normalized := normalizeStateForHost(host, current, snapshot.Version, snapshot.Fingerprint)
		normalized.WriterInstanceID = s.instanceID
		normalized.WriterStartedAt = s.instanceStartedAt
		if !runtimeStateNeedsUpdate(current, normalized) {
			continue
		}
		normalized.UpdatedAt = now
		if err := s.states.Upsert(ctx, normalized); err != nil {
			if s.logger != nil {
				s.logger.Warn("v4_runtime_state_reconcile_upsert_error",
					"event", "v4_runtime_state_reconcile_upsert_error",
					"host", host.Host,
					"version", strings.TrimSpace(snapshot.Version),
					"fingerprint", strings.TrimSpace(snapshot.Fingerprint),
					"error", err,
				)
			}
			continue
		}
		updated++
	}

	if updated > 0 && s.logger != nil {
		s.logger.Info("v4_runtime_state_reconciled",
			"event", "v4_runtime_state_reconciled",
			"version", strings.TrimSpace(snapshot.Version),
			"fingerprint", strings.TrimSpace(snapshot.Fingerprint),
			"updated_hosts", updated,
		)
	}
}

func (s *Service) ApplyProbeUpdate(ctx context.Context, update ProbeUpdate) (v4model.HostRuntimeState, bool, bool, error) {
	s.mu.RLock()
	snapshotVersion := s.snapshotVersion
	snapshotFingerprint := s.fingerprint
	state, found := s.statesByHost[update.Host]
	s.mu.RUnlock()

	if !found || state.Host == "" {
		state = v4model.HostRuntimeState{
			ID:                  update.Host,
			Host:                update.Host,
			SnapshotVersion:     snapshotVersion,
			SnapshotFingerprint: snapshotFingerprint,
			WriterInstanceID:    s.instanceID,
			WriterStartedAt:     s.instanceStartedAt,
			Mode:                v4model.ModePassthrough,
		}
	}
	state = normalizeStateForHost(v4model.SnapshotHost{Host: update.Host, Probe: update.Spec}, state, snapshotVersion, snapshotFingerprint)

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
	wasFaultActive := state.FaultActive

	if update.Healthy {
		state.HealthyCount++
		state.UnhealthyCount = 0
		state.FaultActive = false
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
		threshold := update.Spec.UnhealthyThreshold
		if threshold <= 0 {
			threshold = 1
		}
		thresholdReached := state.UnhealthyCount >= threshold
		if update.RedirectURL != "" {
			state.RedirectURL = update.RedirectURL
		}
		if thresholdReached && !state.FaultActive {
			state.FaultActive = true
			state.FaultCount++
		}
		if thresholdReached && update.RedirectURL != "" && switchAllowed(state.LastSwitchAt, now, update.Spec.MinSwitchInterval) {
			if state.Mode != v4model.ModeDegradedRedirect {
				state.SwitchSuccessCount++
			}
			if state.Mode != v4model.ModeDegradedRedirect || state.RedirectURL != update.RedirectURL {
				state.Mode = v4model.ModeDegradedRedirect
				state.LastSwitchAt = now
				modeChanged = true
			}
		} else if thresholdReached && state.Mode != v4model.ModeDegradedRedirect && !wasFaultActive {
			state.SwitchFailureCount++
		}
	}
	if state.Mode == v4model.ModePassthrough && strings.TrimSpace(state.RedirectURL) != "" {
		state.RedirectURL = ""
	}

	state.SnapshotVersion = snapshotVersion
	state.SnapshotFingerprint = snapshotFingerprint
	state.WriterInstanceID = s.instanceID
	state.WriterStartedAt = s.instanceStartedAt
	state.UpdatedAt = now
	if err := s.states.Upsert(ctx, state); err != nil {
		return v4model.HostRuntimeState{}, false, false, err
	}
	s.mu.Lock()
	if s.statesByHost == nil {
		s.statesByHost = make(map[string]v4model.HostRuntimeState)
	}
	s.statesByHost[update.Host] = state
	s.mu.Unlock()
	return state, modeChanged, recovered, nil
}

func (s *Service) TrackRedirectAccess(ctx context.Context, host, clientIP string) error {
	if s == nil || s.states == nil {
		return nil
	}
	host = normalizeRequestHost(host)
	clientKey := normalizeClientKey(clientIP)
	if host == "" || clientKey == "" {
		return nil
	}

	s.mu.RLock()
	inMemory, found := s.statesByHost[host]
	snapshotVersion := s.snapshotVersion
	snapshotFingerprint := s.fingerprint
	s.mu.RUnlock()
	if found {
		inMemory = normalizeStateForHost(v4model.SnapshotHost{Host: host, Probe: v4model.ProbeSpec{Enabled: true}}, inMemory, snapshotVersion, snapshotFingerprint)
		if inMemory.Mode != v4model.ModeDegradedRedirect {
			return nil
		}
		if containsString(inMemory.RedirectClientKeys, clientKey) {
			return nil
		}
	}

	current, found, err := s.states.Get(ctx, host)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	current = normalizeStateForHost(v4model.SnapshotHost{Host: host, Probe: v4model.ProbeSpec{Enabled: true}}, current, snapshotVersion, snapshotFingerprint)
	if current.Mode != v4model.ModeDegradedRedirect {
		return nil
	}
	if containsString(current.RedirectClientKeys, clientKey) {
		return nil
	}
	current.RedirectClientKeys = append(current.RedirectClientKeys, clientKey)
	sort.Strings(current.RedirectClientKeys)
	current.RedirectClientKeys = dedupeStrings(current.RedirectClientKeys)
	current.RedirectUniqueClientCount = len(current.RedirectClientKeys)
	current.WriterInstanceID = s.instanceID
	current.WriterStartedAt = s.instanceStartedAt
	current.UpdatedAt = time.Now().UTC()
	if err := s.states.Upsert(ctx, current); err != nil {
		return err
	}

	s.mu.Lock()
	if s.statesByHost == nil {
		s.statesByHost = make(map[string]v4model.HostRuntimeState)
	}
	s.statesByHost[host] = current
	s.mu.Unlock()
	return nil
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

func normalizeStateForHost(host v4model.SnapshotHost, state v4model.HostRuntimeState, snapshotVersion, snapshotFingerprint string) v4model.HostRuntimeState {
	if strings.TrimSpace(state.ID) == "" {
		state.ID = host.Host
	}
	if strings.TrimSpace(state.Host) == "" {
		state.Host = host.Host
	}
	if staleStateForSnapshot(state, snapshotVersion, snapshotFingerprint) {
		state = v4model.HostRuntimeState{
			ID:                  host.Host,
			Host:                host.Host,
			SnapshotVersion:     snapshotVersion,
			SnapshotFingerprint: snapshotFingerprint,
			WriterInstanceID:    state.WriterInstanceID,
			WriterStartedAt:     state.WriterStartedAt,
			Mode:                v4model.ModePassthrough,
		}
	}
	if strings.TrimSpace(snapshotVersion) != "" {
		state.SnapshotVersion = snapshotVersion
	}
	if strings.TrimSpace(snapshotFingerprint) != "" {
		state.SnapshotFingerprint = snapshotFingerprint
	}

	switch strings.TrimSpace(state.Mode) {
	case "", v4model.ModePassthrough:
		state.Mode = v4model.ModePassthrough
	case v4model.ModeDegradedRedirect, v4model.ModeRecovering:
	default:
		state.Mode = v4model.ModePassthrough
	}

	if !host.Probe.Enabled {
		state.FaultActive = false
		state.FaultCount = 0
		state.SwitchSuccessCount = 0
		state.SwitchFailureCount = 0
		state.RedirectUniqueClientCount = 0
		state.Mode = v4model.ModePassthrough
		state.RedirectURL = ""
		state.RedirectClientKeys = nil
		state.LastProbeTargets = nil
		state.LastFailedTargets = nil
		state.LastProbeError = ""
		return state
	}

	if state.Mode == v4model.ModePassthrough {
		state.RedirectURL = ""
	}
	state.RedirectClientKeys = dedupeStrings(state.RedirectClientKeys)
	state.RedirectUniqueClientCount = len(state.RedirectClientKeys)
	return state
}

func normalizeClientKey(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return ""
	}
	if ip := net.ParseIP(value); ip != nil {
		return ip.String()
	}
	return value
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func dedupeStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
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
	sort.Strings(result)
	return result
}

func staleStateForSnapshot(state v4model.HostRuntimeState, snapshotVersion, snapshotFingerprint string) bool {
	currentVersion := strings.TrimSpace(snapshotVersion)
	currentFingerprint := strings.TrimSpace(snapshotFingerprint)
	stateVersion := strings.TrimSpace(state.SnapshotVersion)
	stateFingerprint := strings.TrimSpace(state.SnapshotFingerprint)

	if currentVersion == "" && currentFingerprint == "" {
		return false
	}
	if stateVersion == "" && stateFingerprint == "" {
		return true
	}
	if currentVersion != "" && stateVersion != "" && currentVersion != stateVersion {
		return true
	}
	if currentFingerprint != "" && stateFingerprint != "" && currentFingerprint != stateFingerprint {
		return true
	}
	return false
}

func runtimeStateNeedsUpdate(current, normalized v4model.HostRuntimeState) bool {
	current.UpdatedAt = time.Time{}
	normalized.UpdatedAt = time.Time{}
	return !reflect.DeepEqual(current, normalized)
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
