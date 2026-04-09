package routesets

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"gw-ipinfo-nginx/internal/config"
)

type compileState struct {
	compiled        *Compiled
	serviceNames    map[string]struct{}
	sourceIndex     map[string]CompiledRule
	targetIndex     map[string]CompiledRule
	failFast        bool
	logger          *slog.Logger
	conflictCount   int
	issues          []error
	sourceHostSet   map[string]struct{}
	targetHostSet   map[string]struct{}
	ruleIDIndex     map[string]CompiledRule
}

func LoadAndCompile(baseConfigPath string, cfg config.RouteSetsConfig, routing config.RoutingConfig, logger *slog.Logger) (*Compiled, error) {
	state := &compileState{
		compiled: &Compiled{
			Enabled:            cfg.Default.Enabled || cfg.V1.Enabled || cfg.V2.Enabled,
			StrictHostControl:  cfg.StrictHostControl,
			RedirectStatusCode: cfg.RedirectStatusCode,
			SourceRulesByHost:  make(map[string][]CompiledRule),
			TargetHostIndex:    make(map[string]TargetBinding),
			AllowedHosts:       make(map[string]struct{}),
			RulesByID:          make(map[string]CompiledRule),
		},
		serviceNames:  make(map[string]struct{}, len(routing.Services)),
		sourceIndex:   make(map[string]CompiledRule),
		targetIndex:   make(map[string]CompiledRule),
		failFast:      cfg.FailFastOnConflict,
		logger:        logger,
		sourceHostSet: make(map[string]struct{}),
		targetHostSet: make(map[string]struct{}),
		ruleIDIndex:   make(map[string]CompiledRule),
	}

	for _, service := range routing.Services {
		state.serviceNames[service.Name] = struct{}{}
	}

	if !state.compiled.Enabled {
		return state.compiled, nil
	}

	if cfg.Default.Enabled {
		if err := state.compileDefault(resolveFilePath(baseConfigPath, cfg.Default.ConfigPath)); err != nil {
			return nil, err
		}
	}
	if cfg.V1.Enabled {
		if err := state.compilePassKind(resolveFilePath(baseConfigPath, cfg.V1.ConfigPath), KindV1); err != nil {
			return nil, err
		}
	}
	if cfg.V2.Enabled {
		if err := state.compilePassKind(resolveFilePath(baseConfigPath, cfg.V2.ConfigPath), KindV2); err != nil {
			return nil, err
		}
	}

	if len(state.issues) > 0 {
		return nil, errors.Join(state.issues...)
	}

	for host, rules := range state.compiled.SourceRulesByHost {
		sortRulesByPathLen(rules)
		state.compiled.SourceRulesByHost[host] = rules
	}

	state.compiled.Summary.AllowedSourceHosts = len(state.sourceHostSet)
	state.compiled.Summary.AllowedTargetHosts = len(state.targetHostSet)
	state.compiled.Summary.ConflictCount = state.conflictCount

	if logger != nil {
		logger.Info("route_sets_compiled",
			"event", "route_sets_compiled",
			"default_rules_count", state.compiled.Summary.DefaultRulesCount,
			"v1_rules_count", state.compiled.Summary.V1RulesCount,
			"v2_rules_count", state.compiled.Summary.V2RulesCount,
			"allowed_source_hosts_count", state.compiled.Summary.AllowedSourceHosts,
			"allowed_target_hosts_count", state.compiled.Summary.AllowedTargetHosts,
			"conflict_count", state.compiled.Summary.ConflictCount,
		)
	}

	return state.compiled, nil
}

func (s *compileState) compileDefault(path string) error {
	routes, err := loadDefaultFile(path)
	if err != nil {
		return fmt.Errorf("load default routes %s: %w", path, err)
	}
	for _, raw := range routes {
		host, prefix, err := normalizeDefaultRouteEntry(raw)
		if err != nil {
			s.recordIssue(
				"invalid_default_route_entry",
				fmt.Errorf("invalid default route entry %q in %s: %w", raw, path, err),
				"file", path,
				"raw_value", raw,
			)
			if s.failFast {
				return errors.Join(s.issues...)
			}
			continue
		}
		rule := CompiledRule{
			Kind:             KindDefault,
			ID:               defaultRouteID(host, prefix),
			SourceHost:       host,
			SourcePathPrefix: prefix,
			SourceFile:       path,
			RawRule:          raw,
		}
		if !s.addSourceRule(rule) && s.failFast {
			return errors.Join(s.issues...)
		}
	}
	return nil
}

func (s *compileState) compilePassKind(path string, kind Kind) error {
	var (
		routes []passRoute
		err    error
	)
	if kind == KindV1 {
		routes, err = loadV1File(path)
	} else {
		routes, err = loadV2File(path)
	}
	if err != nil {
		return fmt.Errorf("load %s routes %s: %w", kind, path, err)
	}

	for _, raw := range routes {
		rule, ok := s.normalizePassRoute(path, kind, raw)
		if !ok {
			if s.failFast {
				return errors.Join(s.issues...)
			}
			continue
		}
		if !s.addSourceRule(rule) && s.failFast {
			return errors.Join(s.issues...)
		}
		if !s.addTargetBinding(rule) && s.failFast {
			return errors.Join(s.issues...)
		}
	}
	return nil
}

func (s *compileState) normalizePassRoute(path string, kind Kind, raw passRoute) (CompiledRule, bool) {
	ruleID := strings.TrimSpace(raw.ID)
	if ruleID == "" {
		ruleID = string(kind) + ":" + strings.TrimSpace(raw.Source.Host) + strings.TrimSpace(raw.Source.PathPrefix)
	}
	if existing, ok := s.ruleIDIndex[ruleID]; ok {
		s.recordIssue(
			"duplicate_route_id",
			fmt.Errorf("duplicate route id %q", ruleID),
			"file", path,
			"rule_id", ruleID,
			"left_file", existing.SourceFile,
			"left_rule_id", existing.ID,
		)
		return CompiledRule{}, false
	}

	sourceHost, err := normalizeHost(raw.Source.Host)
	if err != nil {
		s.recordIssue("invalid_source_host", fmt.Errorf("invalid source host for %s rule %q: %w", kind, ruleID, err), "file", path, "rule_id", ruleID, "value", raw.Source.Host)
		return CompiledRule{}, false
	}
	sourcePrefix, err := normalizePathPrefix(raw.Source.PathPrefix)
	if err != nil {
		s.recordIssue("invalid_source_path_prefix", fmt.Errorf("invalid source path prefix for %s rule %q: %w", kind, ruleID, err), "file", path, "rule_id", ruleID, "value", raw.Source.PathPrefix)
		return CompiledRule{}, false
	}
	publicURL, targetHost, err := normalizePublicURL(raw.Target.PublicURL)
	if err != nil {
		s.recordIssue(
			"invalid_target_public_url",
			fmt.Errorf("invalid target public url for %s rule %q: %w", kind, ruleID, err),
			"file", path,
			"rule_id", ruleID,
			"value", raw.Target.PublicURL,
		)
		return CompiledRule{}, false
	}
	backendService := strings.TrimSpace(raw.Target.BackendService)
	if _, ok := s.serviceNames[backendService]; !ok {
		s.recordIssue(
			"backend_service_not_found",
			fmt.Errorf("backend service %q not found for %s rule %q", backendService, kind, ruleID),
			"file", path,
			"rule_id", ruleID,
			"backend_service", backendService,
		)
		return CompiledRule{}, false
	}
	backendHost, err := normalizeHost(raw.Target.BackendHost)
	if err != nil {
		s.recordIssue("invalid_backend_host", fmt.Errorf("invalid backend host for %s rule %q: %w", kind, ruleID, err), "file", path, "rule_id", ruleID, "value", raw.Target.BackendHost)
		return CompiledRule{}, false
	}

	rule := CompiledRule{
		Kind:             kind,
		ID:               ruleID,
		SourceHost:       sourceHost,
		SourcePathPrefix: sourcePrefix,
		TargetHost:       targetHost,
		TargetPublicURL:  publicURL,
		BackendService:   backendService,
		BackendHost:      backendHost,
		SourceFile:       path,
		RawRule:          raw.ID,
	}
	s.ruleIDIndex[rule.ID] = rule
	return rule, true
}

func (s *compileState) addSourceRule(rule CompiledRule) bool {
	key := routeKey(rule.SourceHost, rule.SourcePathPrefix)
	if existing, ok := s.sourceIndex[key]; ok {
		s.recordIssue(
			"duplicate_source_route",
			fmt.Errorf("duplicate source route %q", key),
			"key", key,
			"left_file", existing.SourceFile,
			"left_rule", printableRule(existing),
			"right_file", rule.SourceFile,
			"right_rule", printableRule(rule),
		)
		return false
	}

	s.sourceIndex[key] = rule
	s.compiled.SourceRulesByHost[rule.SourceHost] = append(s.compiled.SourceRulesByHost[rule.SourceHost], rule)
	s.compiled.AllowedHosts[rule.SourceHost] = struct{}{}
	s.sourceHostSet[rule.SourceHost] = struct{}{}
	switch rule.Kind {
	case KindDefault:
		s.compiled.Summary.DefaultRulesCount++
	case KindV1:
		s.compiled.Summary.V1RulesCount++
	case KindV2:
		s.compiled.Summary.V2RulesCount++
	}
	if rule.ID != "" {
		s.compiled.RulesByID[rule.ID] = rule
	}
	return true
}

func (s *compileState) addTargetBinding(rule CompiledRule) bool {
	if rule.TargetHost == "" {
		return true
	}
	if existing, ok := s.targetIndex[rule.TargetHost]; ok {
		if existing.Kind != rule.Kind || existing.BackendService != rule.BackendService || existing.BackendHost != rule.BackendHost {
			s.recordIssue(
				"conflicting_target_backend",
				fmt.Errorf("conflicting target backend for %s", rule.TargetHost),
				"target_host", rule.TargetHost,
				"left_file", existing.SourceFile,
				"left_rule_id", existing.ID,
				"left_rule_kind", existing.Kind,
				"left_backend_service", existing.BackendService,
				"left_backend_host", existing.BackendHost,
				"right_file", rule.SourceFile,
				"right_rule_id", rule.ID,
				"right_rule_kind", rule.Kind,
				"right_backend_service", rule.BackendService,
				"right_backend_host", rule.BackendHost,
			)
			return false
		}
		return true
	}

	s.targetIndex[rule.TargetHost] = rule
	s.compiled.TargetHostIndex[rule.TargetHost] = TargetBinding{
		RuleKind:       rule.Kind,
		BackendService: rule.BackendService,
		BackendHost:    rule.BackendHost,
		PublicURL:      rule.TargetPublicURL,
	}
	s.compiled.AllowedHosts[rule.TargetHost] = struct{}{}
	s.targetHostSet[rule.TargetHost] = struct{}{}
	return true
}

func printableRule(rule CompiledRule) string {
	if rule.Kind == KindDefault {
		if rule.RawRule != "" {
			return rule.RawRule
		}
		return rule.SourceHost + rule.SourcePathPrefix
	}
	if rule.ID != "" {
		return rule.ID
	}
	return rule.SourceHost + rule.SourcePathPrefix
}

func (s *compileState) recordIssue(event string, err error, attrs ...any) {
	s.conflictCount++
	if s.logger != nil {
		args := append([]any{"event", event}, attrs...)
		args = append(args, "error", err)
		s.logger.Error(event, args...)
	}
	s.issues = append(s.issues, err)
}
