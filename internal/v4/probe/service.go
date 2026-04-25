package probe

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"gw-ipinfo-nginx/internal/config"
	"gw-ipinfo-nginx/internal/v4/events"
	v4model "gw-ipinfo-nginx/internal/v4/model"
	v4runtime "gw-ipinfo-nginx/internal/v4/runtime"
)

var (
	jsVariablePatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:var|let|const)\s+(?:linkUrl|iosUrl|androidUrl|jumpUrl|redirectUrl|downloadUrl|targetUrl)\s*=\s*['"]([^'"]+)['"]`),
	}
	jsRedirectPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)location\.href\s*=\s*['"]([^'"]+)['"]`),
		regexp.MustCompile(`(?i)window\.location\s*=\s*['"]([^'"]+)['"]`),
		regexp.MustCompile(`(?i)window\.open\(\s*['"]([^'"]+)['"]`),
	}
	htmlMetaPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)http-equiv=['"]refresh['"][^>]+content=['"][^'"]*url=([^'"]+)['"]`),
	}
	htmlScriptSrcPattern = regexp.MustCompile(`(?i)<script[^>]+src=['"]([^'"]+)['"]`)
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

type probeWorkspaceRecord struct {
	Host          string    `json:"host"`
	UpdatedAt     time.Time `json:"updated_at"`
	Mode          string    `json:"mode"`
	SourceURL     string    `json:"source_url"`
	HTMLPaths     []string  `json:"html_paths"`
	JSPaths       []string  `json:"js_paths"`
	DiscoveredURLs []string `json:"discovered_urls"`
	FailedURLs    []string  `json:"failed_urls"`
	RedirectURLs  []string  `json:"redirect_urls"`
	LastError     string    `json:"last_error"`
}

const maxProbeScriptSources = 12

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
				Title:       "V4 路由切换 / V4 Route Switch",
				Message:     "切换到故障跳转 / Switched to failover",
				Metadata: map[string]any{
					"action":       "switch_to_redirect",
					"result":       "applied",
					"source_url":   firstNonEmpty(strings.TrimSpace(update.SourceURL), defaultHostBaseURL(host.Host)),
					"redirect_url": state.RedirectURL,
					"target_urls":  append([]string(nil), update.ProbeTargets...),
					"failed_urls":  append([]string(nil), update.FailedTargets...),
					"reason":       compactProbeReason(update.Error),
				},
			})
			_ = s.events.Emit(ctx, v4model.Event{
				Type:        v4model.EventTrafficSwitchedToRedirect,
				Host:        host.Host,
				Fingerprint: "traffic_switched_to_redirect:" + host.Host + ":" + state.RedirectURL,
				Level:       "warning",
				Title:       "V4 路由切换 / V4 Route Switch",
				Message:     "切换到故障跳转 / Switched to failover",
				Metadata: map[string]any{
					"action":       "switch_to_redirect",
					"result":       "applied",
					"source_url":   firstNonEmpty(strings.TrimSpace(update.SourceURL), defaultHostBaseURL(host.Host)),
					"redirect_url": state.RedirectURL,
					"target_urls":  append([]string(nil), update.ProbeTargets...),
					"failed_urls":  append([]string(nil), update.FailedTargets...),
					"reason":       compactProbeReason(update.Error),
				},
			})
		}
		if recovered {
			lastRedirect := firstNonEmpty(state.RedirectURL, firstSliceValue(update.RedirectCandidates))
			_ = s.events.Emit(ctx, v4model.Event{
				Type:        v4model.EventDomainRecovered,
				Host:        host.Host,
				Fingerprint: "domain_recovered:" + host.Host,
				Level:       "info",
				Title:       "V4 路由恢复 / V4 Route Restore",
				Message:     "恢复原始透传 / Restored passthrough",
				Metadata: map[string]any{
					"action":       "restore_to_passthrough",
					"result":       "restored",
					"source_url":   firstNonEmpty(strings.TrimSpace(update.SourceURL), defaultHostBaseURL(host.Host)),
					"redirect_url": lastRedirect,
					"target_urls":  append([]string(nil), update.ProbeTargets...),
					"reason":       "探测恢复正常 / Health check recovered",
				},
			})
			_ = s.events.Emit(ctx, v4model.Event{
				Type:        v4model.EventTrafficRestoredPassthrough,
				Host:        host.Host,
				Fingerprint: "traffic_restored_to_passthrough:" + host.Host,
				Level:       "info",
				Title:       "V4 路由恢复 / V4 Route Restore",
				Message:     "恢复原始透传 / Restored passthrough",
				Metadata: map[string]any{
					"action":       "restore_to_passthrough",
					"result":       "restored",
					"source_url":   firstNonEmpty(strings.TrimSpace(update.SourceURL), defaultHostBaseURL(host.Host)),
					"redirect_url": lastRedirect,
					"target_urls":  append([]string(nil), update.ProbeTargets...),
					"reason":       "探测恢复正常 / Health check recovered",
				},
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
		Host:               host.Host,
		ProbeAt:            time.Now().UTC(),
		Spec:               host.Probe,
		Healthy:            true,
		SourceURL:          firstNonEmpty(strings.TrimSpace(host.Probe.URL), defaultHostBaseURL(host.Host)),
		RedirectCandidates: dedupeSortedURLs(append([]string(nil), host.Probe.RedirectURLs...)),
	}
	discoveredURLs, workspacePath, discoveryErr := s.discoverProbeURLs(probeCtx, host)
	update.ProbeTargets = discoveredURLs
	update.WorkspaceFile = workspacePath

	failedURLs := make([]string, 0)
	failureReasons := make([]string, 0)
	if discoveryErr != nil {
		failureReasons = append(failureReasons, discoveryErr.Error())
	}
	if len(discoveredURLs) == 0 {
		failureReasons = append(failureReasons, "no probe targets discovered")
	} else {
		failedURLs, failureReasons = s.checkProbeTargets(probeCtx, discoveredURLs, host.Probe)
	}
	update.FailedTargets = failedURLs
	if len(failedURLs) > 0 || len(failureReasons) > 0 {
		update.Healthy = false
		update.RedirectURL = s.pickRedirectURL(probeCtx, host)
		if update.RedirectURL == "" {
			update.SwitchFailed = true
			update.SwitchFailureReason = "no healthy redirect target available"
			failureReasons = append(failureReasons, update.SwitchFailureReason)
		}
		update.Error = strings.Join(failureReasons, " | ")
	}
	s.writeWorkspace(host, discoveredURLs, failedURLs, update.Error)
	return update
}

func (s *Service) discoverProbeURLs(ctx context.Context, host v4model.SnapshotHost) ([]string, string, error) {
	seen := make(map[string]struct{})
	discovered := make([]string, 0)
	var errs []string

	if probeURL := strings.TrimSpace(host.Probe.URL); probeURL != "" {
		if targets, err := s.discoverFromRemoteURL(ctx, probeURL, host.Probe); err != nil {
			errs = append(errs, err.Error())
		} else {
			discovered = appendUniqueURLs(discovered, seen, targets...)
		}
	}

	baseURL := defaultHostBaseURL(host.Host)
	for _, filePath := range host.Probe.HTMLPaths {
		if targets, err := s.discoverFromLocalFile(filePath, baseURL, host.Probe.Mode, true); err != nil {
			errs = append(errs, err.Error())
		} else {
			discovered = appendUniqueURLs(discovered, seen, targets...)
		}
	}
	for _, filePath := range host.Probe.JSPaths {
		if targets, err := s.discoverFromLocalFile(filePath, baseURL, "local_js", false); err != nil {
			errs = append(errs, err.Error())
		} else {
			discovered = appendUniqueURLs(discovered, seen, targets...)
		}
	}

	discovered = filterCandidateURLs(baseURL, discovered, host.Probe)
	sort.Strings(discovered)

	var err error
	if len(errs) > 0 {
		err = errors.New(strings.Join(errs, " | "))
	}
	return discovered, s.workspaceFilePath(host.Host), err
}

func (s *Service) discoverFromRemoteURL(ctx context.Context, probeURL string, probe v4model.ProbeSpec) ([]string, error) {
	if err := validateRemoteURL(ctx, probeURL); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", s.cfg.ProbeDefaults.UserAgent)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	discovered := extractCandidateURLs(probeURL, string(body), probe.Mode)
	if strings.TrimSpace(probe.Mode) == "html_discovery" {
		for _, scriptURL := range extractRemoteScriptURLs(probeURL, string(body)) {
			targets, scriptErr := s.fetchRemoteJSURLs(ctx, scriptURL)
			if scriptErr != nil {
				continue
			}
			discovered = append(discovered, targets...)
		}
	}
	return dedupeSortedURLs(discovered), nil
}

func (s *Service) discoverFromLocalFile(path, baseURL, mode string, htmlMode bool) ([]string, error) {
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("read local probe file %s: %w", path, err)
	}
	effectiveMode := mode
	if htmlMode && strings.TrimSpace(effectiveMode) == "" {
		effectiveMode = "html_discovery"
	}
	if !htmlMode {
		effectiveMode = "local_js"
	}
	discovered := extractCandidateURLs(baseURL, string(raw), effectiveMode)
	if htmlMode {
		for _, jsPath := range extractLocalScriptPaths(path, string(raw)) {
			jsRaw, readErr := os.ReadFile(filepath.Clean(jsPath))
			if readErr != nil {
				continue
			}
			discovered = append(discovered, extractCandidateURLs(baseURL, string(jsRaw), "local_js")...)
		}
	}
	return dedupeSortedURLs(discovered), nil
}

func extractCandidateURLs(baseURL string, body string, mode string) []string {
	candidates := collectCandidates(body, mode)
	if len(candidates) == 0 {
		return nil
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}
	seen := make(map[string]struct{}, len(candidates))
	values := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		absolute, err := base.Parse(strings.TrimSpace(candidate))
		if err != nil {
			continue
		}
		if absolute.Scheme != "http" && absolute.Scheme != "https" {
			continue
		}
		if absolute.Hostname() == "" {
			continue
		}
		value := absolute.String()
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		values = append(values, value)
	}
	return values
}

func filterCandidateURLs(baseURL string, candidates []string, probe v4model.ProbeSpec) []string {
	if len(candidates) == 0 {
		return nil
	}
	explicit := strings.TrimSpace(probe.LinkURL)
	hasPatterns := len(probe.Patterns) > 0
	if explicit == "" && !hasPatterns {
		return candidates
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		return candidates
	}
	allowed := make(map[string]struct{})
	if explicit != "" {
		if target, parseErr := base.Parse(explicit); parseErr == nil {
			allowed[strings.TrimSpace(target.String())] = struct{}{}
		}
	}

	filtered := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if _, ok := allowed[candidate]; ok {
			filtered = append(filtered, candidate)
			continue
		}
		for _, pattern := range probe.Patterns {
			if matchProbePattern(candidate, pattern) {
				filtered = append(filtered, candidate)
				break
			}
		}
	}
	return dedupeSortedURLs(filtered)
}

func extractRemoteScriptURLs(baseURL string, body string) []string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}
	matches := htmlScriptSrcPattern.FindAllStringSubmatch(body, -1)
	values := make([]string, 0, len(matches))
	seen := make(map[string]struct{}, len(matches))
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		raw := strings.TrimSpace(match[1])
		if raw == "" {
			continue
		}
		target, err := base.Parse(raw)
		if err != nil {
			continue
		}
		if target.Host != "" && !strings.EqualFold(target.Hostname(), base.Hostname()) {
			continue
		}
		if target.Scheme != "http" && target.Scheme != "https" {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(target.Path), ".js") {
			continue
		}
		value := target.String()
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		values = append(values, value)
		if len(values) >= maxProbeScriptSources {
			break
		}
	}
	return values
}

func extractLocalScriptPaths(htmlPath string, body string) []string {
	baseDir := filepath.Dir(filepath.Clean(htmlPath))
	matches := htmlScriptSrcPattern.FindAllStringSubmatch(body, -1)
	values := make([]string, 0, len(matches))
	seen := make(map[string]struct{}, len(matches))
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		raw := strings.TrimSpace(match[1])
		if raw == "" {
			continue
		}
		if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") || strings.HasPrefix(raw, "//") {
			continue
		}
		var resolved string
		if filepath.IsAbs(raw) {
			resolved = filepath.Clean(raw)
		} else {
			resolved = filepath.Clean(filepath.Join(baseDir, raw))
		}
		if _, ok := seen[resolved]; ok {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(resolved), ".js") {
			continue
		}
		seen[resolved] = struct{}{}
		values = append(values, resolved)
		if len(values) >= maxProbeScriptSources {
			break
		}
	}
	return values
}

func (s *Service) fetchRemoteJSURLs(ctx context.Context, scriptURL string) ([]string, error) {
	if err := validateRemoteURL(ctx, scriptURL); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scriptURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", s.cfg.ProbeDefaults.UserAgent)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	return extractCandidateURLs(scriptURL, string(body), "local_js"), nil
}

func (s *Service) checkProbeTargets(ctx context.Context, targets []string, probe v4model.ProbeSpec) ([]string, []string) {
	unhealthyCodes := unhealthyStatusCodeSet(probe.UnhealthyStatusCodes)
	failed := make([]string, 0)
	reasons := make([]string, 0)
	for _, target := range targets {
		if err := validateRemoteURL(ctx, target); err != nil {
			failed = append(failed, target)
			reasons = append(reasons, fmt.Sprintf("%s invalid: %s", target, err.Error()))
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			failed = append(failed, target)
			reasons = append(reasons, fmt.Sprintf("%s request build failed: %s", target, err.Error()))
			continue
		}
		req.Header.Set("User-Agent", s.cfg.ProbeDefaults.UserAgent)
		resp, err := s.client.Do(req)
		if err != nil {
			failed = append(failed, target)
			reasons = append(reasons, fmt.Sprintf("%s request failed: %s", target, err.Error()))
			continue
		}
		_ = resp.Body.Close()
		if _, bad := unhealthyCodes[resp.StatusCode]; bad {
			failed = append(failed, target)
			reasons = append(reasons, fmt.Sprintf("%s returned unhealthy status %d", target, resp.StatusCode))
		}
	}
	return dedupeSortedURLs(failed), reasons
}

func matchProbePattern(value, pattern string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}
	if strings.Contains(value, pattern) {
		return true
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	return re.MatchString(value)
}

func collectCandidates(body, mode string) []string {
	var patterns []*regexp.Regexp
	switch strings.TrimSpace(mode) {
	case "local_js":
		patterns = append(patterns, jsVariablePatterns...)
		patterns = append(patterns, jsRedirectPatterns...)
	case "html_discovery":
		patterns = append(patterns, htmlMetaPatterns...)
		patterns = append(patterns, jsVariablePatterns...)
		patterns = append(patterns, jsRedirectPatterns...)
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

func unhealthyStatusCodeSet(values []int) map[int]struct{} {
	set := make(map[int]struct{}, len(values))
	for _, value := range values {
		if value < 100 || value > 599 {
			continue
		}
		set[value] = struct{}{}
	}
	if len(set) == 0 {
		set[http.StatusNotFound] = struct{}{}
	}
	return set
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

func (s *Service) pickRedirectURL(ctx context.Context, host v4model.SnapshotHost) string {
	probe := host.Probe
	candidates := dedupeSortedURLs(append([]string(nil), probe.RedirectURLs...))
	if len(candidates) == 0 && strings.TrimSpace(probe.LinkURL) != "" {
		candidates = []string{strings.TrimSpace(probe.LinkURL)}
	}
	if len(candidates) == 0 {
		return ""
	}
	healthy := make([]string, 0, len(candidates))
	unhealthyCodes := unhealthyStatusCodeSet(probe.UnhealthyStatusCodes)
	for _, candidate := range candidates {
		if s.isHealthyRedirectTarget(ctx, candidate, unhealthyCodes) {
			healthy = append(healthy, candidate)
		}
	}
	if len(healthy) == 0 {
		return ""
	}
	return randomURLForHost(host.Host, healthy)
}

func (s *Service) isHealthyRedirectTarget(ctx context.Context, target string, unhealthyCodes map[int]struct{}) bool {
	if err := validateRemoteURL(ctx, target); err != nil {
		return false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", s.cfg.ProbeDefaults.UserAgent)
	resp, err := s.client.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	_, bad := unhealthyCodes[resp.StatusCode]
	return !bad
}

func randomURLForHost(host string, candidates []string) string {
	if len(candidates) == 0 {
		return ""
	}
	if len(candidates) == 1 {
		return candidates[0]
	}
	var seedBytes [8]byte
	if _, err := rand.Read(seedBytes[:]); err == nil {
		return candidates[int(binary.LittleEndian.Uint64(seedBytes[:])%uint64(len(candidates)))]
	}
	hasher := fnv.New32a()
	_, _ = hasher.Write([]byte(strings.TrimSpace(strings.ToLower(host))))
	index := int(hasher.Sum32() % uint32(len(candidates)))
	return candidates[index]
}

func (s *Service) workspaceFilePath(host string) string {
	dir := filepath.Clean(strings.TrimSpace(s.cfg.ProbeDefaults.WorkspaceDir))
	if dir == "." || dir == "" {
		return ""
	}
	return filepath.Join(dir, sanitizeHostFileName(host)+".json")
}

func (s *Service) writeWorkspace(host v4model.SnapshotHost, discoveredURLs, failedURLs []string, lastError string) {
	path := s.workspaceFilePath(host.Host)
	if path == "" {
		return
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		if s.logger != nil {
			s.logger.Warn("v4_probe_workspace_mkdir_error", "event", "v4_probe_workspace_mkdir_error", "host", host.Host, "path", path, "error", err)
		}
		return
	}
	record := probeWorkspaceRecord{
		Host:           host.Host,
		UpdatedAt:      time.Now().UTC(),
		Mode:           host.Probe.Mode,
		SourceURL:      firstNonEmpty(strings.TrimSpace(host.Probe.URL), defaultHostBaseURL(host.Host)),
		HTMLPaths:      append([]string(nil), host.Probe.HTMLPaths...),
		JSPaths:        append([]string(nil), host.Probe.JSPaths...),
		DiscoveredURLs: append([]string(nil), discoveredURLs...),
		FailedURLs:     append([]string(nil), failedURLs...),
		RedirectURLs:   dedupeSortedURLs(append([]string(nil), host.Probe.RedirectURLs...)),
		LastError:      strings.TrimSpace(lastError),
	}
	raw, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return
	}
	tmpFile, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("v4_probe_workspace_tempfile_error", "event", "v4_probe_workspace_tempfile_error", "host", host.Host, "path", path, "error", err)
		}
		return
	}
	tmpPath := tmpFile.Name()
	if _, err := tmpFile.Write(raw); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		if s.logger != nil {
			s.logger.Warn("v4_probe_workspace_write_error", "event", "v4_probe_workspace_write_error", "host", host.Host, "path", path, "error", err)
		}
		return
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		if s.logger != nil {
			s.logger.Warn("v4_probe_workspace_close_error", "event", "v4_probe_workspace_close_error", "host", host.Host, "path", path, "error", err)
		}
		return
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		if s.logger != nil {
			s.logger.Warn("v4_probe_workspace_rename_error", "event", "v4_probe_workspace_rename_error", "host", host.Host, "path", path, "error", err)
		}
	}
}

func appendUniqueURLs(values []string, seen map[string]struct{}, candidates ...string) []string {
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		values = append(values, candidate)
	}
	return values
}

func dedupeSortedURLs(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func defaultHostBaseURL(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return "https://invalid.local/"
	}
	return "https://" + host + "/"
}

func compactProbeReason(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	parts := strings.Split(value, " | ")
	first := strings.TrimSpace(parts[0])
	if first == "" {
		return value
	}
	return first
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func firstSliceValue(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return strings.TrimSpace(values[0])
}

func sanitizeHostFileName(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return "unknown-host"
	}
	replacer := strings.NewReplacer("/", "_", "\\", "_", ":", "_", "*", "_", "?", "_", "\"", "_", "<", "_", ">", "_", "|", "_")
	value := replacer.Replace(host)
	if value == "" {
		return "unknown-host"
	}
	return value
}
