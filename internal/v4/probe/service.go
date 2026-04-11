package probe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"gw-ipinfo-nginx/internal/config"
	"gw-ipinfo-nginx/internal/v4/events"
	v4model "gw-ipinfo-nginx/internal/v4/model"
	v4runtime "gw-ipinfo-nginx/internal/v4/runtime"
)

var (
	jsRedirectPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)location\.href\s*=\s*['"]([^'"]+)['"]`),
		regexp.MustCompile(`(?i)window\.location\s*=\s*['"]([^'"]+)['"]`),
		regexp.MustCompile(`(?i)window\.open\(\s*['"]([^'"]+)['"]`),
	}
	htmlRedirectPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)<a[^>]+href=['"]([^'"]+)['"]`),
		regexp.MustCompile(`(?i)http-equiv=['"]refresh['"][^>]+content=['"][^'"]*url=([^'"]+)['"]`),
	}
)

type Service struct {
	cfg     config.V4Config
	runtime *v4runtime.Service
	events  *events.Service
	logger  *slog.Logger
	client  *http.Client
	mu      sync.Mutex
	lastRun map[string]time.Time
}

func NewService(cfg config.V4Config, runtime *v4runtime.Service, eventSvc *events.Service, logger *slog.Logger) *Service {
	return &Service{
		cfg:     cfg,
		runtime: runtime,
		events:  eventSvc,
		logger:  logger,
		client: &http.Client{
			Timeout: cfg.ProbeDefaults.Timeout,
		},
		lastRun: make(map[string]time.Time),
	}
}

func (s *Service) Run(ctx context.Context) {
	if s == nil || !s.cfg.Enabled || s.runtime == nil {
		return
	}
	ticker := time.NewTicker(s.cfg.ProbeDefaults.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runOnce(ctx)
		}
	}
}

func (s *Service) runOnce(ctx context.Context) {
	now := time.Now().UTC()
	for _, host := range s.runtime.ProbeHosts() {
		if !s.shouldProbe(host, now) {
			continue
		}
		update := s.probeHost(ctx, host)
		state, changed, recovered, err := s.runtime.ApplyProbeUpdate(ctx, update)
		if err != nil {
			if s.logger != nil {
				s.logger.Warn("v4_probe_apply_error", "event", "v4_probe_apply_error", "host", host.Host, "error", err)
			}
			continue
		}
		if !changed {
			continue
		}
		if state.Mode == v4model.ModeDegradedRedirect {
			_ = s.events.Emit(ctx, v4model.Event{
				Type:        v4model.EventDomainUnhealthy,
				Host:        host.Host,
				Fingerprint: "domain_unhealthy:" + host.Host,
				Level:       "warning",
				Title:       "V4 domain unhealthy",
				Message:     fmt.Sprintf("%s switched to degraded redirect", host.Host),
				Metadata:    map[string]any{"redirect_url": state.RedirectURL, "probe_url": host.Probe.URL},
			})
			_ = s.events.Emit(ctx, v4model.Event{
				Type:        v4model.EventTrafficSwitchedToRedirect,
				Host:        host.Host,
				Fingerprint: "traffic_switched_to_redirect:" + host.Host + ":" + state.RedirectURL,
				Level:       "warning",
				Title:       "V4 traffic switched to redirect",
				Message:     fmt.Sprintf("%s switched to redirect %s", host.Host, state.RedirectURL),
				Metadata:    map[string]any{"redirect_url": state.RedirectURL},
			})
		}
		if recovered {
			_ = s.events.Emit(ctx, v4model.Event{
				Type:        v4model.EventDomainRecovered,
				Host:        host.Host,
				Fingerprint: "domain_recovered:" + host.Host,
				Level:       "info",
				Title:       "V4 domain recovered",
				Message:     fmt.Sprintf("%s recovered to passthrough", host.Host),
			})
			_ = s.events.Emit(ctx, v4model.Event{
				Type:        v4model.EventTrafficRestoredPassthrough,
				Host:        host.Host,
				Fingerprint: "traffic_restored_to_passthrough:" + host.Host,
				Level:       "info",
				Title:       "V4 traffic restored",
				Message:     fmt.Sprintf("%s restored to passthrough", host.Host),
			})
		}
	}
}

func (s *Service) probeHost(ctx context.Context, host v4model.SnapshotHost) v4runtime.ProbeUpdate {
	probeCtx := ctx
	cancel := func() {}
	if host.Probe.Timeout > 0 {
		probeCtx, cancel = context.WithTimeout(ctx, host.Probe.Timeout)
	}
	defer cancel()

	update := v4runtime.ProbeUpdate{
		Host:    host.Host,
		ProbeAt: time.Now().UTC(),
		Spec:    host.Probe,
		Healthy: true,
	}
	probeURL := strings.TrimSpace(host.Probe.URL)
	if err := validateRemoteURL(probeCtx, probeURL); err != nil {
		update.Healthy = false
		update.Error = err.Error()
		return update
	}
	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, probeURL, nil)
	if err != nil {
		update.Healthy = false
		update.Error = err.Error()
		return update
	}
	req.Header.Set("User-Agent", s.cfg.ProbeDefaults.UserAgent)
	resp, err := s.client.Do(req)
	if err != nil {
		update.Healthy = false
		update.Error = err.Error()
		return update
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		update.Healthy = false
		update.Error = err.Error()
		return update
	}

	redirectURL, found, err := extractRedirectURL(probeURL, string(body), host.Probe)
	if err != nil {
		update.Healthy = false
		update.Error = err.Error()
		return update
	}
	if found {
		update.Healthy = false
		update.RedirectURL = redirectURL
		return update
	}
	return update
}

func extractRedirectURL(baseURL string, body string, probe v4model.ProbeSpec) (string, bool, error) {
	candidates := collectCandidates(body, probe.Mode)
	if len(candidates) == 0 {
		return "", false, nil
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", false, err
	}

	explicit := strings.TrimSpace(probe.LinkURL)
	for _, candidate := range candidates {
		absolute, err := base.Parse(strings.TrimSpace(candidate))
		if err != nil {
			continue
		}
		value := absolute.String()
		if explicit != "" {
			matchTarget, err := base.Parse(explicit)
			if err == nil && strings.EqualFold(matchTarget.String(), value) {
				if err := validateRemoteURL(context.Background(), value); err != nil {
					return "", false, err
				}
				return value, true, nil
			}
			continue
		}
		for _, pattern := range probe.Patterns {
			re, err := regexp.Compile(pattern)
			if err != nil {
				continue
			}
			if re.MatchString(value) {
				if err := validateRemoteURL(context.Background(), value); err != nil {
					return "", false, err
				}
				return value, true, nil
			}
		}
	}
	return "", false, nil
}

func collectCandidates(body, mode string) []string {
	var patterns []*regexp.Regexp
	switch strings.TrimSpace(mode) {
	case "local_js":
		patterns = jsRedirectPatterns
	case "html_discovery":
		patterns = htmlRedirectPatterns
	default:
		return nil
	}
	seen := make(map[string]struct{})
	values := make([]string, 0)
	for _, pattern := range patterns {
		matches := pattern.FindAllStringSubmatch(body, -1)
		for _, match := range matches {
			if len(match) < 2 {
				continue
			}
			value := strings.TrimSpace(match[1])
			if value == "" {
				continue
			}
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			values = append(values, value)
		}
	}
	return values
}

func validateRemoteURL(ctx context.Context, raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return errors.New("probe url scheme must be http or https")
	}
	if parsed.Hostname() == "" {
		return errors.New("probe url host is required")
	}
	if parsed.User != nil {
		return errors.New("probe url userinfo is not allowed")
	}
	if ip := net.ParseIP(parsed.Hostname()); ip != nil {
		if !isPublicIP(ip) {
			return errors.New("probe url host must be public")
		}
		return nil
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, parsed.Hostname())
	if err != nil {
		return fmt.Errorf("resolve probe host: %w", err)
	}
	if len(ips) == 0 {
		return errors.New("probe url host resolved to no addresses")
	}
	for _, ip := range ips {
		if isPublicIP(ip.IP) {
			return nil
		}
	}
	return errors.New("probe url host resolved only to private addresses")
}

func isPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		switch {
		case v4[0] == 10:
			return false
		case v4[0] == 127:
			return false
		case v4[0] == 169 && v4[1] == 254:
			return false
		case v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31:
			return false
		case v4[0] == 192 && v4[1] == 168:
			return false
		default:
			return true
		}
	}
	if strings.HasPrefix(ip.String(), "fc") || strings.HasPrefix(ip.String(), "fd") || strings.HasPrefix(ip.String(), "fe80:") || ip.IsPrivate() {
		return false
	}
	return true
}

func (s *Service) shouldProbe(host v4model.SnapshotHost, now time.Time) bool {
	interval := host.Probe.Interval
	if interval <= 0 {
		interval = s.cfg.ProbeDefaults.Interval
	}
	if interval <= 0 {
		return true
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	lastAt := s.lastRun[host.Host]
	if !lastAt.IsZero() && now.Sub(lastAt) < interval {
		return false
	}
	s.lastRun[host.Host] = now
	return true
}
