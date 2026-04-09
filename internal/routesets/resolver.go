package routesets

import "net/http"

func (c *Compiled) Resolve(req *http.Request) Resolution {
	if c == nil || !c.Enabled {
		return Resolution{}
	}

	host := normalizeRequestHost(req.Host)
	path := requestPath(req)
	result := Resolution{
		Enabled: true,
		Host:    host,
		Path:    path,
	}

	if c.StrictHostControl {
		if _, ok := c.AllowedHosts[host]; !ok {
			result.DenyReason = "deny_host_not_allowed"
			return result
		}
	}

	if rules := c.BypassRulesByHost[host]; len(rules) > 0 {
		for _, rule := range rules {
			if pathMatches(path, rule.SourcePathPrefix) {
				result.MatchType = MatchSource
				result.Rule = rule
				return result
			}
		}
	}

	if rules := c.SourceRulesByHost[host]; len(rules) > 0 {
		for _, rule := range rules {
			if pathMatches(path, rule.SourcePathPrefix) {
				result.MatchType = MatchSource
				result.Rule = rule
				return result
			}
		}
	}

	if binding, ok := c.TargetHostIndex[host]; ok {
		result.MatchType = MatchTarget
		result.Binding = binding
		return result
	}

	result.DenyReason = "deny_route_not_found"
	return result
}
