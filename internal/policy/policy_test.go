package policy

import (
	"net/http"
	"testing"

	"gw-ipinfo-nginx/internal/config"
	"gw-ipinfo-nginx/internal/ipctx"
)

func TestEvaluateRequestBlocksUserAgentAndMissingLanguage(t *testing.T) {
	engine, err := NewEngine(config.SecurityConfig{
		UA: config.UAConfig{
			Enabled:      true,
			DenyKeywords: []string{"bot"},
		},
		AcceptLanguage: config.AcceptLanguageConfig{
			RequireHeader: true,
		},
		Geo: config.GeoConfig{
			DefaultAction: "deny",
			Whitelist: map[string]config.GeoCountryRule{
				"US": {},
			},
		},
		Privacy: config.PrivacyConfig{DenyByDefault: true},
	})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	req.Header.Set("User-Agent", "GoogleBot/1.0")
	if decision := engine.EvaluateRequest(req, "default"); decision == nil || decision.Reason != "deny_ua_keyword" {
		t.Fatalf("EvaluateRequest() = %#v, want deny_ua_keyword", decision)
	}

	req2, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	req2.Header.Set("User-Agent", "Mozilla/5.0")
	if decision := engine.EvaluateRequest(req2, "default"); decision == nil || decision.Reason != "deny_missing_accept_language" {
		t.Fatalf("EvaluateRequest() = %#v, want deny_missing_accept_language", decision)
	}
}

func TestEvaluateIPGeoAndPrivacy(t *testing.T) {
	engine, err := NewEngine(config.SecurityConfig{
		Geo: config.GeoConfig{
			DefaultAction: "deny",
			Whitelist: map[string]config.GeoCountryRule{
				"US": {},
				"CA": {Cities: []string{"Toronto"}},
			},
		},
		Privacy: config.PrivacyConfig{
			DenyByDefault: true,
			AllowTypes:    []string{"vpn"},
		},
	})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	allowed := engine.EvaluateIP(ipctx.Context{CountryCode: "US"}, nil)
	if !allowed.Allowed || allowed.Reason != "allow_geo_privacy_clean" {
		t.Fatalf("EvaluateIP() allowed = %#v, want allow", allowed)
	}

	deniedGeo := engine.EvaluateIP(ipctx.Context{CountryCode: "CA", City: "Montreal"}, nil)
	if deniedGeo.Allowed || deniedGeo.Reason != "deny_geo_city:CA:montreal" {
		t.Fatalf("EvaluateIP() deniedGeo = %#v, want deny", deniedGeo)
	}

	ambiguousGeo := engine.EvaluateIP(ipctx.Context{CountryCode: "CA"}, nil)
	if ambiguousGeo.Allowed || ambiguousGeo.AlertType != "blocked_with_ambiguity" {
		t.Fatalf("EvaluateIP() ambiguousGeo = %#v, want blocked_with_ambiguity", ambiguousGeo)
	}

	allowedRisk := engine.EvaluateIP(ipctx.Context{
		CountryCode: "US",
		Privacy:     ipctx.PrivacyFlags{VPN: true},
	}, nil)
	if !allowedRisk.Allowed || allowedRisk.Result != "allow_with_risk" || allowedRisk.Reason != "allow_privacy_vpn" {
		t.Fatalf("EvaluateIP() allowedRisk = %#v, want allow_with_risk", allowedRisk)
	}

	deniedRisk := engine.EvaluateIP(ipctx.Context{
		CountryCode: "US",
		Privacy:     ipctx.PrivacyFlags{Proxy: true},
	}, nil)
	if deniedRisk.Allowed || deniedRisk.Reason != "deny_privacy_proxy" {
		t.Fatalf("EvaluateIP() deniedRisk = %#v, want deny", deniedRisk)
	}
}
