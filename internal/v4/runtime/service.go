package runtime

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"gw-ipinfo-nginx/internal/config"
	"gw-ipinfo-nginx/internal/v4/repository"
	v4model "gw-ipinfo-nginx/internal/v4/model"
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
	snapshots    *repository.SnapshotRepository
	states       *repository.RuntimeStateRepository
	logger       *slog.Logger
	mu           sync.RWMutex
	hostsByName  map[string]v4model.SnapshotHost
	fingerprint  string
}

func NewService(cfg config.V4Config, snapshots *repository.SnapshotRepository, states *repository.RuntimeStateRepository, logger *slog.Logger) *Service {
	return &Service{
		cfg:         cfg,
		snapshots:   snapshots,
		states:      states,
		logger:      logger,
		hostsByName: make(map[string]v4model.SnapshotHost),
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

func (s *Service) ReplaceSnapshot(snapshot v4model.Snapshot, hosts []v4model.SnapshotHost) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := make(map[string]v4model.SnapshotHost, len(hosts))
	for _, host := range hosts {
		next[host.Host] = host
	}
	s.hostsByName = next
	s.fingerprint = snapshot.Fingerprint
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

	s.mu.RLock()
	currentFingerprint := s.fingerprint
	s.mu.RUnlock()
	if currentFingerprint == snapshot.Fingerprint && currentFingerprint != "" {
		return
	}

	s.ReplaceSnapshot(snapshot, hosts)
	if s.logger != nil {
		s.logger.Info("v4_runtime_snapshot_refreshed",
			"event", "v4_runtime_snapshot_refreshed",
			"fingerprint", snapshot.Fingerprint,
			"host_count", len(hosts),
		)
	}
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
