package routesets

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

type Kind string

const (
	KindBypass  Kind = "bypass"
	KindDefault Kind = "default"
	KindV1      Kind = "v1"
	KindV2      Kind = "v2"
)

type MatchType string

const (
	MatchNone   MatchType = "none"
	MatchSource MatchType = "source"
	MatchTarget MatchType = "target"
)

type GrantStatus string

const (
	GrantStatusNone    GrantStatus = "none"
	GrantStatusQueryOK GrantStatus = "query_ok"
	GrantStatusCookieOK GrantStatus = "cookie_ok"
	GrantStatusExpired GrantStatus = "expired"
	GrantStatusInvalid GrantStatus = "invalid"
)

type CompiledRule struct {
	Kind             Kind
	ID               string
	SourceHost       string
	SourcePathPrefix string
	TargetHost       string
	TargetPublicURL  string
	BackendService   string
	BackendHost      string
	SourceFile       string
	RawRule          string
}

type TargetBinding struct {
	RuleKind       Kind
	BackendService string
	BackendHost    string
	PublicURL      string
}

type CompileSummary struct {
	BypassRulesCount     int
	DefaultRulesCount    int
	V1RulesCount         int
	V2RulesCount         int
	AllowedSourceHosts   int
	AllowedTargetHosts   int
	ConflictCount        int
}

type Compiled struct {
	Enabled            bool
	StrictHostControl  bool
	RedirectStatusCode int
	BypassRulesByHost  map[string][]CompiledRule
	SourceRulesByHost  map[string][]CompiledRule
	TargetHostIndex    map[string]TargetBinding
	AllowedHosts       map[string]struct{}
	RulesByID          map[string]CompiledRule
	Summary            CompileSummary
}

type Resolution struct {
	Enabled    bool
	Host       string
	Path       string
	MatchType  MatchType
	Rule       CompiledRule
	Binding    TargetBinding
	DenyReason string
}

type GrantClaims struct {
	RouteID    string `json:"route_id"`
	SourceHost string `json:"source_host"`
	TargetHost string `json:"target_host"`
	ExpiresAt  int64  `json:"exp"`
	UAHash     string `json:"ua_hash,omitempty"`
	IPPrefix   string `json:"ip_prefix,omitempty"`
}

func (c *Compiled) IsEnabled() bool {
	return c != nil && c.Enabled
}

func resolveFilePath(baseConfigPath, value string) string {
	if filepath.IsAbs(value) {
		return filepath.Clean(value)
	}
	return filepath.Join(filepath.Dir(filepath.Clean(baseConfigPath)), value)
}

func readExpandedFile(path string) ([]byte, error) {
	content, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	return []byte(os.ExpandEnv(string(content))), nil
}

func normalizeHost(value string) (string, error) {
	host := strings.ToLower(strings.TrimSpace(value))
	if host == "" {
		return "", errors.New("empty host")
	}
	if strings.Contains(host, "://") {
		return "", fmt.Errorf("host must not include scheme: %s", value)
	}
	if strings.ContainsAny(host, "/?#") {
		return "", fmt.Errorf("host must not include path/query: %s", value)
	}
	if strings.Contains(host, ":") {
		if parsedHost, parsedPort, err := net.SplitHostPort(host); err == nil {
			if parsedPort != "" {
				host = parsedHost
			}
		}
	}
	if host == "" {
		return "", fmt.Errorf("invalid host: %s", value)
	}
	return host, nil
}

func normalizeRequestHost(value string) string {
	host := strings.TrimSpace(strings.ToLower(value))
	if host == "" {
		return ""
	}
	if strings.Contains(host, ":") {
		if parsedHost, parsedPort, err := net.SplitHostPort(host); err == nil && parsedPort != "" {
			return strings.ToLower(strings.TrimSpace(parsedHost))
		}
	}
	return host
}

func normalizePathPrefix(value string) (string, error) {
	path := strings.TrimSpace(value)
	if path == "" {
		return "/", nil
	}
	if strings.ContainsAny(path, "?#") {
		return "", fmt.Errorf("path prefix must not contain query or fragment: %s", value)
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if len(path) > 1 {
		path = strings.TrimRight(path, "/")
		if path == "" {
			path = "/"
		}
	}
	return path, nil
}

func normalizeDefaultRouteEntry(value string) (string, string, error) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return "", "", errors.New("empty route")
	}
	if strings.Contains(raw, "://") {
		return "", "", fmt.Errorf("default route must not include scheme: %s", value)
	}
	host := raw
	path := "/"
	if slash := strings.Index(raw, "/"); slash >= 0 {
		host = raw[:slash]
		path = raw[slash:]
	}
	normalizedHost, err := normalizeHost(host)
	if err != nil {
		return "", "", err
	}
	normalizedPath, err := normalizePathPrefix(path)
	if err != nil {
		return "", "", err
	}
	return normalizedHost, normalizedPath, nil
}

func normalizePublicURL(value string) (string, string, error) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return "", "", errors.New("empty public_url")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", "", err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", "", fmt.Errorf("unsupported scheme %q", parsed.Scheme)
	}
	if strings.TrimSpace(parsed.Host) == "" {
		return "", "", errors.New("public_url host is required")
	}
	host, err := normalizeHost(parsed.Hostname())
	if err != nil {
		return "", "", err
	}
	return parsed.String(), host, nil
}

func routeKey(host, path string) string {
	return host + " " + path
}

func defaultRouteID(host, path string) string {
	return "default:" + host + path
}

func requestPath(req *http.Request) string {
	if req == nil || req.URL == nil {
		return "/"
	}
	path, err := normalizePathPrefix(req.URL.Path)
	if err != nil {
		return "/"
	}
	return path
}

func pathMatches(path, prefix string) bool {
	if prefix == "/" {
		return true
	}
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

func sortRulesByPathLen(rules []CompiledRule) {
	slices.SortStableFunc(rules, func(left, right CompiledRule) int {
		if len(left.SourcePathPrefix) == len(right.SourcePathPrefix) {
			switch {
			case left.SourcePathPrefix < right.SourcePathPrefix:
				return -1
			case left.SourcePathPrefix > right.SourcePathPrefix:
				return 1
			default:
				return 0
			}
		}
		if len(left.SourcePathPrefix) > len(right.SourcePathPrefix) {
			return -1
		}
		return 1
	})
}

func timeFromUnix(sec int64) time.Time {
	if sec <= 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0).UTC()
}
