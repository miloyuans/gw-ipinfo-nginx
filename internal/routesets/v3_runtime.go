package routesets

import (
	contextpkg "context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

var ErrNoHealthyTarget = errors.New("v3: no healthy target")

type V3Selection struct {
	Target        V3PoolTarget
	BindingReused bool
}

type V3Runtime struct {
	logger      *slog.Logger
	httpClient  *http.Client
	bindings    *v3BindingStore
	rules       map[string]CompiledRule
	targets     map[string]map[string]*v3TargetHealthState
	rrCounters  sync.Map
	randomMu    sync.Mutex
	random      *rand.Rand
	started     atomic.Bool
}

func NewV3Runtime(compiled *Compiled, logger *slog.Logger) *V3Runtime {
	if compiled == nil || compiled.Summary.V3RulesCount == 0 {
		return nil
	}
	targets := make(map[string]map[string]*v3TargetHealthState)
	ruleIndex := make(map[string]CompiledRule)
	for _, hostRules := range compiled.V3RulesByHost {
		for _, rule := range hostRules {
			if rule.Kind != KindV3 {
				continue
			}
			ruleIndex[rule.ID] = rule
			byID := make(map[string]*v3TargetHealthState, len(rule.V3PoolTargets))
			for _, target := range rule.V3PoolTargets {
				byID[target.ID] = newV3TargetHealthState(rule.ID, target)
			}
			targets[rule.ID] = byID
		}
	}
	return &V3Runtime{
		logger:     logger,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		bindings:   newV3BindingStore(),
		rules:      ruleIndex,
		targets:    targets,
		random:     rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (r *V3Runtime) Run(ctx contextpkg.Context) {
	if r == nil || !r.started.CompareAndSwap(false, true) {
		return
	}
	for _, targetStates := range r.targets {
		for _, state := range targetStates {
			if !state.Target.HealthCheckEnabled {
				continue
			}
			go runV3HealthLoop(ctx, r.httpClient, r.logger, state)
		}
	}
	go r.runBindingSweeper(ctx)
}

func (r *V3Runtime) Select(rule CompiledRule, clientIP string, now time.Time) (V3Selection, error) {
	if r == nil {
		return V3Selection{}, ErrNoHealthyTarget
	}
	if clientIP != "" {
		if binding, ok := r.bindings.Get(rule.ID, clientIP, now); ok {
			if target, ok := r.targetByID(rule.ID, binding.SelectedTargetID); ok && target.IsHealthy() {
				expireAt := now.Add(rule.V3SessionTTL)
				r.bindings.Touch(rule.ID, clientIP, now, expireAt)
				return V3Selection{
					Target:        target.Target,
					BindingReused: true,
				}, nil
			}
		}
	}

	healthyTargets := r.healthyTargets(rule.ID, rule.V3PoolTargets)
	if len(healthyTargets) == 0 {
		return V3Selection{}, ErrNoHealthyTarget
	}
	selected := r.pickTarget(rule, healthyTargets)
	if clientIP != "" {
		r.bindings.Put(v3Binding{
			RouteID:          rule.ID,
			ClientIP:         clientIP,
			SelectedTargetID: selected.ID,
			ExpireAt:         now.Add(rule.V3SessionTTL),
			LastSeenAt:       now,
		})
	}
	return V3Selection{Target: selected}, nil
}

func (r *V3Runtime) healthyTargets(ruleID string, configured []V3PoolTarget) []V3PoolTarget {
	targets := make([]V3PoolTarget, 0, len(configured))
	for _, target := range configured {
		state, ok := r.targetByID(ruleID, target.ID)
		if ok {
			if state.IsHealthy() {
				targets = append(targets, state.Target)
			}
			continue
		}
		targets = append(targets, target)
	}
	return targets
}

func (r *V3Runtime) targetByID(ruleID, targetID string) (*v3TargetHealthState, bool) {
	targetStates, ok := r.targets[ruleID]
	if !ok {
		return nil, false
	}
	state, ok := targetStates[targetID]
	return state, ok
}

func (r *V3Runtime) pickTarget(rule CompiledRule, targets []V3PoolTarget) V3PoolTarget {
	switch rule.V3StrategyMode {
	case "round_robin":
		return targets[r.nextCounter(rule.ID)%uint64(len(targets))]
	case "weighted_round_robin":
		totalWeight := 0
		for _, target := range targets {
			totalWeight += target.Weight
		}
		if totalWeight <= 0 {
			return targets[r.nextCounter(rule.ID)%uint64(len(targets))]
		}
		slot := int(r.nextCounter(rule.ID) % uint64(totalWeight))
		acc := 0
		for _, target := range targets {
			acc += target.Weight
			if slot < acc {
				return target
			}
		}
		return targets[len(targets)-1]
	default:
		r.randomMu.Lock()
		index := r.random.Intn(len(targets))
		r.randomMu.Unlock()
		return targets[index]
	}
}

func (r *V3Runtime) nextCounter(routeID string) uint64 {
	value, _ := r.rrCounters.LoadOrStore(routeID, new(uint64))
	counter := value.(*uint64)
	return atomic.AddUint64(counter, 1) - 1
}

func (r *V3Runtime) runBindingSweeper(ctx contextpkg.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			for _, rule := range r.rules {
				r.bindings.SweepRoute(rule.ID, now.UTC(), rule.V3SessionIdleTimeout)
			}
		}
	}
}

func errUnexpectedStatus(status int) error {
	return fmt.Errorf("unexpected status %d", status)
}
