package routesets

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

type v3TargetHealthState struct {
	RuleID              string
	Target              V3PoolTarget
	mu                  sync.RWMutex
	healthy             bool
	consecutiveSuccess  int
	consecutiveFailure  int
}

func newV3TargetHealthState(ruleID string, target V3PoolTarget) *v3TargetHealthState {
	return &v3TargetHealthState{
		RuleID:  ruleID,
		Target:  target,
		healthy: true,
	}
}

func (s *v3TargetHealthState) IsHealthy() bool {
	if s == nil {
		return false
	}
	if !s.Target.HealthCheckEnabled {
		return true
	}
	s.mu.RLock()
	healthy := s.healthy
	s.mu.RUnlock()
	return healthy
}

func (s *v3TargetHealthState) markSuccess(logger *slog.Logger) {
	if s == nil || !s.Target.HealthCheckEnabled {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.consecutiveSuccess++
	s.consecutiveFailure = 0
	if !s.healthy && s.consecutiveSuccess >= s.Target.HealthyThreshold {
		s.healthy = true
		if logger != nil {
			logger.Info("v3_target_recovered",
				"event", "v3_target_recovered",
				"route_id", s.RuleID,
				"target_id", s.Target.ID,
				"target_host", s.Target.Host,
				"health_check_url", s.Target.HealthCheckURL,
			)
		}
	}
}

func (s *v3TargetHealthState) markFailure(logger *slog.Logger, err error) {
	if s == nil || !s.Target.HealthCheckEnabled {
		return
	}
	if logger != nil {
		logger.Warn("v3_health_check_error",
			"event", "v3_health_check_error",
			"route_id", s.RuleID,
			"target_id", s.Target.ID,
			"target_host", s.Target.Host,
			"health_check_url", s.Target.HealthCheckURL,
			"error", err,
		)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.consecutiveFailure++
	s.consecutiveSuccess = 0
	if s.healthy && s.consecutiveFailure >= s.Target.UnhealthyThreshold {
		s.healthy = false
		if logger != nil {
			logger.Warn("v3_target_marked_unhealthy",
				"event", "v3_target_marked_unhealthy",
				"route_id", s.RuleID,
				"target_id", s.Target.ID,
				"target_host", s.Target.Host,
				"health_check_url", s.Target.HealthCheckURL,
			)
		}
	}
}

func runV3HealthLoop(ctx context.Context, client *http.Client, logger *slog.Logger, state *v3TargetHealthState) {
	if state == nil || !state.Target.HealthCheckEnabled {
		return
	}
	ticker := time.NewTicker(state.Target.HealthCheckInterval)
	defer ticker.Stop()

	check := func() {
		checkCtx, cancel := context.WithTimeout(ctx, state.Target.HealthCheckTimeout)
		defer cancel()
		req, err := http.NewRequestWithContext(checkCtx, http.MethodGet, state.Target.HealthCheckURL, nil)
		if err != nil {
			state.markFailure(logger, err)
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			state.markFailure(logger, err)
			return
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			state.markSuccess(logger)
			return
		}
		state.markFailure(logger, errUnexpectedStatus(resp.StatusCode))
	}

	check()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			check()
		}
	}
}
