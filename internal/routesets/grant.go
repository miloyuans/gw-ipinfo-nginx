package routesets

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"gw-ipinfo-nginx/internal/config"
)

var (
	ErrGrantInvalid = errors.New("invalid grant")
	ErrGrantExpired = errors.New("expired grant")
)

type GrantManager struct {
	cfg config.V1GrantConfig
	key []byte
}

func NewGrantManager(cfg config.V1GrantConfig) *GrantManager {
	return &GrantManager{
		cfg: cfg,
		key: []byte(cfg.SigningKey),
	}
}

func (g *GrantManager) Issue(rule CompiledRule, clientIP, userAgent string, now time.Time) (string, time.Time, error) {
	claims := GrantClaims{
		RouteID:    rule.ID,
		SourceHost: rule.SourceHost,
		TargetHost: rule.TargetHost,
		ExpiresAt:  now.Add(g.cfg.TTL).UTC().Unix(),
	}
	if g.cfg.BindUserAgent {
		claims.UAHash = hashGrantUserAgent(userAgent)
	}
	if g.cfg.BindClientIP {
		prefix, err := grantIPPrefix(clientIP, g.cfg.BindClientIPv4Prefix, g.cfg.BindClientIPv6Prefix)
		if err != nil {
			return "", time.Time{}, err
		}
		claims.IPPrefix = prefix
	}
	return g.signClaims(claims)
}

func (g *GrantManager) SignRedirectURL(publicURL string, token string) (string, error) {
	parsed, err := urlFromString(publicURL)
	if err != nil {
		return "", err
	}
	query := parsed.Query()
	query.Set(g.cfg.QueryParam, token)
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func (g *GrantManager) Validate(token, expectedTargetHost, clientIP, userAgent string, now time.Time) (GrantClaims, error) {
	claims, err := g.parseAndVerify(token)
	if err != nil {
		return GrantClaims{}, err
	}
	if claims.TargetHost != expectedTargetHost {
		return GrantClaims{}, ErrGrantInvalid
	}
	if timeFromUnix(claims.ExpiresAt).Before(now.UTC()) {
		return GrantClaims{}, ErrGrantExpired
	}
	if g.cfg.BindUserAgent && claims.UAHash != hashGrantUserAgent(userAgent) {
		return GrantClaims{}, ErrGrantInvalid
	}
	if g.cfg.BindClientIP {
		prefix, err := grantIPPrefix(clientIP, g.cfg.BindClientIPv4Prefix, g.cfg.BindClientIPv6Prefix)
		if err != nil {
			return GrantClaims{}, ErrGrantInvalid
		}
		if claims.IPPrefix != prefix {
			return GrantClaims{}, ErrGrantInvalid
		}
	}
	return claims, nil
}

func (g *GrantManager) QueryToken(req *http.Request) string {
	if req == nil || req.URL == nil {
		return ""
	}
	return strings.TrimSpace(req.URL.Query().Get(g.cfg.QueryParam))
}

func (g *GrantManager) CookieToken(req *http.Request) string {
	if req == nil {
		return ""
	}
	cookie, err := req.Cookie(g.cfg.CookieName)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(cookie.Value)
}

func (g *GrantManager) ExchangeCookie(token string, expiresAt time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     g.cfg.CookieName,
		Value:    token,
		Path:     "/",
		Expires:  expiresAt.UTC(),
		MaxAge:   int(time.Until(expiresAt).Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
}

func (g *GrantManager) signClaims(claims GrantClaims) (string, time.Time, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", time.Time{}, err
	}
	payloadPart := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, g.key)
	_, _ = mac.Write([]byte(payloadPart))
	signaturePart := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return payloadPart + "." + signaturePart, timeFromUnix(claims.ExpiresAt), nil
}

func (g *GrantManager) parseAndVerify(token string) (GrantClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return GrantClaims{}, ErrGrantInvalid
	}
	mac := hmac.New(sha256.New, g.key)
	_, _ = mac.Write([]byte(parts[0]))
	expected := mac.Sum(nil)
	got, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !hmac.Equal(expected, got) {
		return GrantClaims{}, ErrGrantInvalid
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return GrantClaims{}, ErrGrantInvalid
	}
	var claims GrantClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return GrantClaims{}, ErrGrantInvalid
	}
	if claims.RouteID == "" || claims.TargetHost == "" || claims.SourceHost == "" || claims.ExpiresAt <= 0 {
		return GrantClaims{}, ErrGrantInvalid
	}
	return claims, nil
}

func hashGrantUserAgent(value string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(strings.ToLower(value))))
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

func grantIPPrefix(clientIP string, v4Prefix, v6Prefix int) (string, error) {
	host := strings.TrimSpace(clientIP)
	if host == "" {
		return "", errors.New("empty client ip")
	}
	if strings.Contains(host, ":") {
		if parsed, _, err := net.SplitHostPort(host); err == nil {
			host = parsed
		}
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return "", err
	}
	if addr.Is4() {
		return netip.PrefixFrom(addr, v4Prefix).Masked().String(), nil
	}
	return netip.PrefixFrom(addr, v6Prefix).Masked().String(), nil
}

func urlFromString(value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil {
		return nil, fmt.Errorf("parse url: %w", err)
	}
	return parsed, nil
}
