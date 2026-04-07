package policy

import (
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"gw-ipinfo-nginx/internal/config"
	"gw-ipinfo-nginx/internal/ipctx"
)

type Decision struct {
	Allowed    bool
	Result     string
	Reason     string
	RiskTypes  []string
	Ambiguous  bool
	AlertType  string
}

type Engine struct {
	cfg          config.SecurityConfig
	uaPatterns   []*regexp.Regexp
	allowRiskSet map[string]struct{}
	geoRules     map[string]geoRule
}

type geoRule struct {
	allowAllCities bool
	cities         map[string]struct{}
}

func NewEngine(cfg config.SecurityConfig) (*Engine, error) {
	patterns := make([]*regexp.Regexp, 0, len(cfg.UA.DenyPatterns))
	for _, pattern := range cfg.UA.DenyPatterns {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("compile ua deny pattern %q: %w", pattern, err)
		}
		patterns = append(patterns, compiled)
	}

	allowRiskSet := make(map[string]struct{}, len(cfg.Privacy.AllowTypes))
	for _, risk := range cfg.Privacy.AllowTypes {
		allowRiskSet[risk] = struct{}{}
	}

	geoRules := make(map[string]geoRule, len(cfg.Geo.Whitelist))
	for country, rule := range cfg.Geo.Whitelist {
		normalizedCountry := strings.ToUpper(strings.TrimSpace(country))
		compiledRule := geoRule{
			allowAllCities: len(rule.Cities) == 0,
			cities:         make(map[string]struct{}, len(rule.Cities)),
		}
		for _, city := range rule.Cities {
			compiledRule.cities[normalizeCity(city)] = struct{}{}
		}
		geoRules[normalizedCountry] = compiledRule
	}

	return &Engine{
		cfg:          cfg,
		uaPatterns:   patterns,
		allowRiskSet: allowRiskSet,
		geoRules:     geoRules,
	}, nil
}

func (e *Engine) EvaluateRequest(req *http.Request, serviceName string) *Decision {
	if e.cfg.UA.Enabled {
		userAgent := strings.ToLower(req.UserAgent())
		for _, keyword := range e.cfg.UA.DenyKeywords {
			if strings.Contains(userAgent, strings.ToLower(keyword)) {
				return &Decision{Allowed: false, Result: "deny", Reason: "deny_ua_keyword"}
			}
		}
		for _, pattern := range e.uaPatterns {
			if pattern.MatchString(req.UserAgent()) {
				return &Decision{Allowed: false, Result: "deny", Reason: "deny_ua_pattern"}
			}
		}
	}

	if e.requiresAcceptLanguage(serviceName) && strings.TrimSpace(req.Header.Get("Accept-Language")) == "" {
		return &Decision{Allowed: false, Result: "deny", Reason: "deny_missing_accept_language"}
	}

	return nil
}

func (e *Engine) EvaluateIP(ipContext ipctx.Context, lookupErr error) Decision {
	if lookupErr != nil {
		return Decision{
			Allowed:   false,
			Result:    "deny",
			Reason:    "deny_ipinfo_lookup_failed",
			Ambiguous: true,
			AlertType: "blocked_with_ambiguity",
		}
	}

	if decision, denied := e.evaluateGeo(ipContext.CountryCode, ipContext.City); denied {
		return decision
	}

	risks := ipContext.RiskTypes()
	if len(risks) == 0 {
		return Decision{Allowed: true, Result: "allow", Reason: "allow_geo_privacy_clean"}
	}

	deniedRisks := make([]string, 0, len(risks))
	allowedRisks := make([]string, 0, len(risks))
	for _, risk := range risks {
		if _, ok := e.allowRiskSet[risk]; ok {
			allowedRisks = append(allowedRisks, risk)
			continue
		}
		deniedRisks = append(deniedRisks, risk)
	}

	if len(deniedRisks) > 0 && e.cfg.Privacy.DenyByDefault {
		slices.Sort(deniedRisks)
		return Decision{
			Allowed:   false,
			Result:    "deny",
			Reason:    "deny_privacy_" + deniedRisks[0],
			RiskTypes: risks,
		}
	}

	if len(allowedRisks) > 0 {
		slices.Sort(allowedRisks)
		return Decision{
			Allowed:   true,
			Result:    "allow_with_risk",
			Reason:    "allow_privacy_" + allowedRisks[0],
			RiskTypes: allowedRisks,
			AlertType: "allowed_with_risk",
		}
	}

	return Decision{Allowed: true, Result: "allow", Reason: "allow_geo_privacy_clean"}
}

func (e *Engine) requiresAcceptLanguage(serviceName string) bool {
	if !e.cfg.AcceptLanguage.RequireHeader {
		return false
	}
	override, ok := e.cfg.AcceptLanguage.ServiceOverrides[serviceName]
	if ok {
		return !override.AllowMissing
	}
	return true
}

func (e *Engine) evaluateGeo(countryCode, city string) (Decision, bool) {
	normalizedCountry := strings.ToUpper(strings.TrimSpace(countryCode))
	rule, ok := e.geoRules[normalizedCountry]
	if !ok {
		return Decision{
			Allowed: false,
			Result:  "deny",
			Reason:  "deny_geo_country_not_allowed",
		}, true
	}
	if rule.allowAllCities {
		return Decision{}, false
	}

	normalizedCity := normalizeCity(city)
	if normalizedCity == "" {
		return Decision{
			Allowed:   false,
			Result:    "deny",
			Reason:    "deny_geo_city_missing",
			Ambiguous: true,
			AlertType: "blocked_with_ambiguity",
		}, true
	}
	if _, ok = rule.cities[normalizedCity]; !ok {
		return Decision{
			Allowed: false,
			Result:  "deny",
			Reason:  "deny_geo_city_not_allowed",
		}, true
	}
	return Decision{}, false
}

func normalizeCity(value string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(value))), " ")
}

func SortedRiskTypes(risks []string) []string {
	values := append([]string(nil), risks...)
	slices.Sort(values)
	return values
}
