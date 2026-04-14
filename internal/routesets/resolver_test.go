package routesets

import (
	"net/http/httptest"
	"testing"
)

func TestCompiledResolveMatchesDefaultSourceBeforeV4Fallback(t *testing.T) {
	compiled := &Compiled{
		Enabled: true,
		SourceRulesByHost: map[string][]CompiledRule{
			"game.freefun.live": {
				{
					Kind:             KindDefault,
					ID:               "default:game.freefun.live/",
					SourceHost:       "game.freefun.live",
					SourcePathPrefix: "/",
				},
			},
		},
		AllowedHosts: map[string]struct{}{
			"game.freefun.live": {},
		},
	}

	req := httptest.NewRequest("GET", "http://game.freefun.live/login", nil)
	req.Host = "game.freefun.live"

	resolution := compiled.Resolve(req)
	if resolution.MatchType != MatchSource {
		t.Fatalf("Resolve() match type = %q, want %q", resolution.MatchType, MatchSource)
	}
	if resolution.Rule.Kind != KindDefault {
		t.Fatalf("Resolve() rule kind = %q, want %q", resolution.Rule.Kind, KindDefault)
	}
	if resolution.DenyReason != "" {
		t.Fatalf("Resolve() deny reason = %q, want empty", resolution.DenyReason)
	}
}
