package routesets

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"gw-ipinfo-nginx/internal/config"
)

type Runtime struct {
	compiled *Compiled
	grant    *GrantManager
	v3       *V3Runtime
}

type V1GrantResult struct {
	Status    GrantStatus
	Claims    GrantClaims
	Rule      CompiledRule
	Token     string
	ExpiresAt time.Time
}

func NewRuntime(compiled *Compiled, cfg config.RouteSetsConfig, logger *slog.Logger) *Runtime {
	if compiled == nil || !compiled.Enabled {
		return nil
	}
	return &Runtime{
		compiled: compiled,
		grant:    NewGrantManager(cfg.V1Grant),
		v3:       NewV3Runtime(compiled, logger),
	}
}

func (r *Runtime) Enabled() bool {
	return r != nil && r.compiled != nil && r.compiled.Enabled
}

func (r *Runtime) Resolve(req *http.Request) Resolution {
	if !r.Enabled() {
		return Resolution{}
	}
	return r.compiled.Resolve(req)
}

func (r *Runtime) IssueV1Grant(rule CompiledRule, clientIP, userAgent string) (string, time.Time, error) {
	if r == nil || r.grant == nil {
		return "", time.Time{}, errors.New("v1 grant manager is not configured")
	}
	return r.grant.Issue(rule, clientIP, userAgent, time.Now().UTC())
}

func (r *Runtime) BuildRedirectURL(publicURL, token string) (string, error) {
	if r == nil || r.grant == nil {
		return "", errors.New("v1 grant manager is not configured")
	}
	return r.grant.SignRedirectURL(publicURL, token)
}

func (r *Runtime) ExchangeV1Target(req *http.Request, expectedTargetHost, clientIP string) V1GrantResult {
	if r == nil || r.grant == nil {
		return V1GrantResult{Status: GrantStatusInvalid}
	}

	now := time.Now().UTC()
	if token := r.grant.QueryToken(req); token != "" {
		claims, err := r.grant.Validate(token, expectedTargetHost, clientIP, req.UserAgent(), now)
		return r.validationResult(claims, token, err, GrantStatusQueryOK)
	}
	if token := r.grant.CookieToken(req); token != "" {
		claims, err := r.grant.Validate(token, expectedTargetHost, clientIP, req.UserAgent(), now)
		return r.validationResult(claims, token, err, GrantStatusCookieOK)
	}
	return V1GrantResult{Status: GrantStatusNone}
}

func (r *Runtime) ExchangeCookie(token string, expiresAt time.Time) *http.Cookie {
	if r == nil || r.grant == nil {
		return nil
	}
	return r.grant.ExchangeCookie(token, expiresAt)
}

func (r *Runtime) RedirectStatusCode() int {
	if r == nil || r.compiled == nil {
		return http.StatusFound
	}
	return r.compiled.RedirectStatusCode
}

func (r *Runtime) Run(ctx context.Context) {
	if r == nil || r.v3 == nil {
		return
	}
	r.v3.Run(ctx)
}

func (r *Runtime) SelectV3Target(rule CompiledRule, clientIP string) (V3Selection, error) {
	if r == nil || r.v3 == nil {
		return V3Selection{}, ErrNoHealthyTarget
	}
	return r.v3.Select(rule, clientIP, time.Now().UTC())
}

func (r *Runtime) validationResult(claims GrantClaims, token string, err error, successStatus GrantStatus) V1GrantResult {
	if err == nil {
		rule, ok := r.compiled.RulesByID[claims.RouteID]
		if !ok || rule.Kind != KindV1 || rule.TargetHost != claims.TargetHost {
			return V1GrantResult{Status: GrantStatusInvalid}
		}
		return V1GrantResult{
			Status:    successStatus,
			Claims:    claims,
			Rule:      rule,
			Token:     token,
			ExpiresAt: timeFromUnix(claims.ExpiresAt),
		}
	}
	if errors.Is(err, ErrGrantExpired) {
		return V1GrantResult{Status: GrantStatusExpired}
	}
	return V1GrantResult{Status: GrantStatusInvalid}
}
