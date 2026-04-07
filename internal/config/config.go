package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server   ServerConfig   `yaml:"server"`
	RealIP   RealIPConfig   `yaml:"real_ip"`
	IPInfo   IPInfoConfig   `yaml:"ipinfo"`
	Mongo    MongoConfig    `yaml:"mongo"`
	Cache    CacheConfig    `yaml:"cache"`
	Security SecurityConfig `yaml:"security"`
	Routing  RoutingConfig  `yaml:"routing"`
	Alerts   AlertsConfig   `yaml:"alerts"`
	Reports  ReportsConfig  `yaml:"reports"`
	Storage  StorageConfig  `yaml:"storage"`
	Perf     PerformanceConfig `yaml:"performance"`
	DenyPage DenyPageConfig `yaml:"deny_page"`
	Logging  LoggingConfig  `yaml:"logging"`
	Metrics  MetricsConfig  `yaml:"metrics"`
}

type ServerConfig struct {
	ListenAddress   string        `yaml:"listen_address"`
	ReadTimeout     time.Duration `yaml:"read_timeout"`
	WriteTimeout    time.Duration `yaml:"write_timeout"`
	IdleTimeout     time.Duration `yaml:"idle_timeout"`
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout"`
	DenyStatusCode  int           `yaml:"deny_status_code"`
}

type RealIPConfig struct {
	TrustedProxyCIDRs    []string `yaml:"trusted_proxy_cidrs"`
	HeaderPriority       []string `yaml:"header_priority"`
	TrustAllSources      bool     `yaml:"trust_all_sources"`
	UntrustedProxyAction string   `yaml:"untrusted_proxy_action"`
}

type IPInfoConfig struct {
	Enabled                 bool          `yaml:"enabled"`
	BaseURL                 string        `yaml:"base_url"`
	LookupPathTemplate      string        `yaml:"lookup_path_template"`
	Token                   string        `yaml:"token"`
	Timeout                 time.Duration `yaml:"timeout"`
	MaxRetries              int           `yaml:"max_retries"`
	RetryBackoff            time.Duration `yaml:"retry_backoff"`
	IncludeResidentialProxy bool          `yaml:"include_residential_proxy"`
}

type MongoConfig struct {
	URI              string        `yaml:"uri"`
	Database         string        `yaml:"database"`
	ConnectTimeout   time.Duration `yaml:"connect_timeout"`
	OperationTimeout time.Duration `yaml:"operation_timeout"`
}

type CacheConfig struct {
	L1               L1CacheConfig   `yaml:"l1"`
	TTL              CacheTTLConfig  `yaml:"ttl"`
	FailureTTL       time.Duration   `yaml:"failure_ttl"`
	ShortCircuitTTL  time.Duration   `yaml:"short_circuit_ttl"`
	LocalFallbackTTL time.Duration   `yaml:"local_fallback_ttl"`
	MongoCollections MongoCollections `yaml:"mongo_collections"`
}

type L1CacheConfig struct {
	Enabled            bool `yaml:"enabled"`
	MaxEntries         int  `yaml:"max_entries"`
	ShortCircuitEntries int `yaml:"short_circuit_entries"`
	Shards             int  `yaml:"shards"`
	CleanupIntervalSec int  `yaml:"cleanup_interval_sec"`
}

type CacheTTLConfig struct {
	Geo              time.Duration `yaml:"geo"`
	Privacy          time.Duration `yaml:"privacy"`
	ResidentialProxy time.Duration `yaml:"residential_proxy"`
}

type MongoCollections struct {
	IPCache      string `yaml:"ip_cache"`
	DecisionCache string `yaml:"decision_cache"`
	AlertOutbox  string `yaml:"alert_outbox"`
	AlertDedupe  string `yaml:"alert_dedupe"`
	ReportEvents string `yaml:"report_events"`
}

type SecurityConfig struct {
	UA             UAConfig             `yaml:"ua"`
	AcceptLanguage AcceptLanguageConfig `yaml:"accept_language"`
	Geo            GeoConfig            `yaml:"geo"`
	Privacy        PrivacyConfig        `yaml:"privacy"`
}

type UAConfig struct {
	Enabled      bool     `yaml:"enabled"`
	DenyKeywords []string `yaml:"deny_keywords"`
	DenyPatterns []string `yaml:"deny_patterns"`
}

type AcceptLanguageConfig struct {
	RequireHeader    bool                               `yaml:"require_header"`
	ServiceOverrides map[string]AcceptLanguageOverride `yaml:"service_overrides"`
}

type AcceptLanguageOverride struct {
	AllowMissing bool `yaml:"allow_missing"`
}

type GeoConfig struct {
	DefaultAction string                    `yaml:"default_action"`
	Whitelist     map[string]GeoCountryRule `yaml:"whitelist"`
}

type GeoCountryRule struct {
	Cities []string `yaml:"cities"`
}

type PrivacyConfig struct {
	DenyByDefault          bool     `yaml:"deny_by_default"`
	AllowTypes             []string `yaml:"allow_types"`
	EnableResidentialProxy bool     `yaml:"enable_residential_proxy"`
}

type RoutingConfig struct {
	DefaultService string          `yaml:"default_service"`
	Services       []ServiceConfig `yaml:"services"`
}

type ServiceConfig struct {
	Name              string   `yaml:"name"`
	MatchPathPrefixes []string `yaml:"match_path_prefixes"`
	TargetURL         string   `yaml:"target_url"`
	PreserveHost      bool     `yaml:"preserve_host"`
}

type AlertsConfig struct {
	Telegram TelegramConfig `yaml:"telegram"`
	Delivery DeliveryConfig `yaml:"delivery"`
	Dedupe   DedupeConfig   `yaml:"dedupe"`
}

type ReportsConfig struct {
	Enabled           bool          `yaml:"enabled"`
	TimeZone          string        `yaml:"timezone"`
	DailySendTime     string        `yaml:"daily_send_time"`
	Lookback          time.Duration `yaml:"lookback"`
	TopN              int           `yaml:"top_n"`
	IncludeCSV        bool          `yaml:"include_csv"`
	IncludeHTML       bool          `yaml:"include_html"`
	WorkerEnabled     bool          `yaml:"worker_enabled"`
	PollInterval      time.Duration `yaml:"poll_interval"`
	ReplayBatchSize   int           `yaml:"replay_batch_size"`
}

type StorageConfig struct {
	LocalPath          string        `yaml:"local_path"`
	ReplayInterval     time.Duration `yaml:"replay_interval"`
	MongoProbeInterval time.Duration `yaml:"mongo_probe_interval"`
	ReplayBatchSize    int           `yaml:"replay_batch_size"`
	ReplayWorkers      int           `yaml:"replay_workers"`
}

type PerformanceConfig struct {
	RequestQueueSize       int           `yaml:"request_queue_size"`
	AsyncWriteQueueSize    int           `yaml:"async_write_queue_size"`
	StatsQueueSize         int           `yaml:"stats_queue_size"`
	DecisionWorkers        int           `yaml:"decision_workers"`
	AlertWorkers           int           `yaml:"alert_workers"`
	LogSampleRate          int           `yaml:"log_sample_rate"`
	ProxyMaxIdleConns      int           `yaml:"proxy_max_idle_conns"`
	ProxyMaxIdleConnsPerHost int         `yaml:"proxy_max_idle_conns_per_host"`
	ProxyIdleConnTimeout   time.Duration `yaml:"proxy_idle_conn_timeout"`
	ProxyResponseHeaderTimeout time.Duration `yaml:"proxy_response_header_timeout"`
	ProxyExpectContinueTimeout time.Duration `yaml:"proxy_expect_continue_timeout"`
}

type DenyPageConfig struct {
	TargetURL    string `yaml:"target_url"`
	PreserveHost bool   `yaml:"preserve_host"`
	Title        string `yaml:"title"`
	Heading      string `yaml:"heading"`
	Message      string `yaml:"message"`
	Hint         string `yaml:"hint"`
}

type TelegramConfig struct {
	Enabled          bool   `yaml:"enabled"`
	BotToken         string `yaml:"bot_token"`
	ChatID           string `yaml:"chat_id"`
	APIBaseURL       string `yaml:"api_base_url"`
	Timeout          time.Duration `yaml:"timeout"`
	ParseMode        string `yaml:"parse_mode"`
	MaskQuery        bool   `yaml:"mask_query"`
	IncludeUserAgent bool   `yaml:"include_user_agent"`
}

type DeliveryConfig struct {
	WorkerEnabled      bool          `yaml:"worker_enabled"`
	PollInterval       time.Duration `yaml:"poll_interval"`
	BatchSize          int           `yaml:"batch_size"`
	ClaimLease         time.Duration `yaml:"claim_lease"`
	MaxAttempts        int           `yaml:"max_attempts"`
	BaseBackoff        time.Duration `yaml:"base_backoff"`
	MaxBackoff         time.Duration `yaml:"max_backoff"`
	RateLimitPerSecond int         `yaml:"rate_limit_per_second"`
}

type DedupeConfig struct {
	Window time.Duration `yaml:"window"`
}

type LoggingConfig struct {
	Level          string `yaml:"level"`
	Format         string `yaml:"format"`
	RedactQuery    bool   `yaml:"redact_query"`
	AccessLog      bool   `yaml:"access_log"`
}

type MetricsConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
}

func Load(path string) (*Config, error) {
	content, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	expanded := os.ExpandEnv(string(content))
	var cfg Config
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Server.ListenAddress == "" {
		c.Server.ListenAddress = ":8080"
	}
	if c.Server.ReadTimeout == 0 {
		c.Server.ReadTimeout = 10 * time.Second
	}
	if c.Server.WriteTimeout == 0 {
		c.Server.WriteTimeout = 15 * time.Second
	}
	if c.Server.IdleTimeout == 0 {
		c.Server.IdleTimeout = 60 * time.Second
	}
	if c.Server.ShutdownTimeout == 0 {
		c.Server.ShutdownTimeout = 15 * time.Second
	}
	if c.Server.DenyStatusCode == 0 {
		c.Server.DenyStatusCode = 403
	}

	if c.RealIP.UntrustedProxyAction == "" {
		c.RealIP.UntrustedProxyAction = "deny"
	}
	if len(c.RealIP.TrustedProxyCIDRs) == 0 {
		c.RealIP.TrustAllSources = true
	}
	if len(c.RealIP.HeaderPriority) == 0 {
		c.RealIP.HeaderPriority = []string{
			"CF-Connecting-IP",
			"CF-Connecting-IPv6",
			"True-Client-IP",
			"X-Real-IP",
			"X-Forwarded-For",
		}
	}

	if c.IPInfo.BaseURL == "" {
		c.IPInfo.BaseURL = "https://api.ipinfo.io"
	}
	if c.IPInfo.LookupPathTemplate == "" {
		c.IPInfo.LookupPathTemplate = "/lookup/%s"
	}
	if c.IPInfo.Timeout == 0 {
		c.IPInfo.Timeout = 2 * time.Second
	}
	if c.IPInfo.MaxRetries == 0 {
		c.IPInfo.MaxRetries = 2
	}
	if c.IPInfo.RetryBackoff == 0 {
		c.IPInfo.RetryBackoff = 250 * time.Millisecond
	}

	if c.Mongo.ConnectTimeout == 0 {
		c.Mongo.ConnectTimeout = 5 * time.Second
	}
	if c.Mongo.OperationTimeout == 0 {
		c.Mongo.OperationTimeout = 3 * time.Second
	}

	if c.Cache.L1.MaxEntries == 0 {
		c.Cache.L1.MaxEntries = 10000
	}
	if c.Cache.L1.ShortCircuitEntries == 0 {
		c.Cache.L1.ShortCircuitEntries = 200000
	}
	if c.Cache.L1.Shards == 0 {
		c.Cache.L1.Shards = 64
	}
	if c.Cache.L1.CleanupIntervalSec == 0 {
		c.Cache.L1.CleanupIntervalSec = 300
	}
	if c.Cache.TTL.Geo == 0 {
		c.Cache.TTL.Geo = 24 * time.Hour
	}
	if c.Cache.TTL.Privacy == 0 {
		c.Cache.TTL.Privacy = 6 * time.Hour
	}
	if c.Cache.TTL.ResidentialProxy == 0 {
		c.Cache.TTL.ResidentialProxy = 6 * time.Hour
	}
	if c.Cache.FailureTTL == 0 {
		c.Cache.FailureTTL = 5 * time.Minute
	}
	if c.Cache.ShortCircuitTTL == 0 {
		c.Cache.ShortCircuitTTL = 10 * time.Hour
	}
	if c.Cache.LocalFallbackTTL == 0 {
		c.Cache.LocalFallbackTTL = 24 * time.Hour
	}
	if c.Cache.MongoCollections.IPCache == "" {
		c.Cache.MongoCollections.IPCache = "ip_risk_cache"
	}
	if c.Cache.MongoCollections.DecisionCache == "" {
		c.Cache.MongoCollections.DecisionCache = "decision_short_circuit_cache"
	}
	if c.Cache.MongoCollections.AlertOutbox == "" {
		c.Cache.MongoCollections.AlertOutbox = "alerts_outbox"
	}
	if c.Cache.MongoCollections.AlertDedupe == "" {
		c.Cache.MongoCollections.AlertDedupe = "alerts_dedupe"
	}
	if c.Cache.MongoCollections.ReportEvents == "" {
		c.Cache.MongoCollections.ReportEvents = "request_reports_daily"
	}

	if len(c.Security.UA.DenyKeywords) == 0 {
		c.Security.UA.DenyKeywords = []string{"bot", "crawler", "spider", "facebookexternalhit", "facebot"}
	}
	if c.Security.Geo.DefaultAction == "" {
		c.Security.Geo.DefaultAction = "deny"
	}

	if c.Routing.DefaultService == "" && len(c.Routing.Services) > 0 {
		c.Routing.DefaultService = c.Routing.Services[0].Name
	}

	if c.Alerts.Telegram.APIBaseURL == "" {
		c.Alerts.Telegram.APIBaseURL = "https://api.telegram.org"
	}
	if c.Alerts.Telegram.Timeout == 0 {
		c.Alerts.Telegram.Timeout = 5 * time.Second
	}
	if c.Alerts.Delivery.PollInterval == 0 {
		c.Alerts.Delivery.PollInterval = 2 * time.Second
	}
	if c.Alerts.Delivery.BatchSize == 0 {
		c.Alerts.Delivery.BatchSize = 10
	}
	if c.Alerts.Delivery.ClaimLease == 0 {
		c.Alerts.Delivery.ClaimLease = 30 * time.Second
	}
	if c.Alerts.Delivery.MaxAttempts == 0 {
		c.Alerts.Delivery.MaxAttempts = 8
	}
	if c.Alerts.Delivery.BaseBackoff == 0 {
		c.Alerts.Delivery.BaseBackoff = 5 * time.Second
	}
	if c.Alerts.Delivery.MaxBackoff == 0 {
		c.Alerts.Delivery.MaxBackoff = 5 * time.Minute
	}
	if c.Alerts.Delivery.RateLimitPerSecond == 0 {
		c.Alerts.Delivery.RateLimitPerSecond = 2
	}
	if c.Alerts.Dedupe.Window == 0 {
		c.Alerts.Dedupe.Window = 10 * time.Minute
	}
	if c.Reports.TimeZone == "" {
		c.Reports.TimeZone = "UTC"
	}
	if c.Reports.DailySendTime == "" {
		c.Reports.DailySendTime = "09:00"
	}
	if c.Reports.Lookback == 0 {
		c.Reports.Lookback = 24 * time.Hour
	}
	if c.Reports.TopN == 0 {
		c.Reports.TopN = 10
	}
	if !c.Reports.IncludeCSV && !c.Reports.IncludeHTML {
		c.Reports.IncludeCSV = true
		c.Reports.IncludeHTML = true
	}
	if c.Reports.PollInterval == 0 {
		c.Reports.PollInterval = time.Minute
	}
	if c.Reports.ReplayBatchSize == 0 {
		c.Reports.ReplayBatchSize = 1000
	}

	if c.Storage.LocalPath == "" {
		c.Storage.LocalPath = "/data/shared/gw-ipinfo-nginx.db"
	}
	if c.Storage.ReplayInterval == 0 {
		c.Storage.ReplayInterval = 30 * time.Second
	}
	if c.Storage.MongoProbeInterval == 0 {
		c.Storage.MongoProbeInterval = 10 * time.Second
	}
	if c.Storage.ReplayBatchSize == 0 {
		c.Storage.ReplayBatchSize = 500
	}
	if c.Storage.ReplayWorkers == 0 {
		c.Storage.ReplayWorkers = 2
	}

	if c.Perf.RequestQueueSize == 0 {
		c.Perf.RequestQueueSize = 4096
	}
	if c.Perf.AsyncWriteQueueSize == 0 {
		c.Perf.AsyncWriteQueueSize = 16384
	}
	if c.Perf.StatsQueueSize == 0 {
		c.Perf.StatsQueueSize = 32768
	}
	if c.Perf.DecisionWorkers == 0 {
		c.Perf.DecisionWorkers = 4
	}
	if c.Perf.AlertWorkers == 0 {
		c.Perf.AlertWorkers = 2
	}
	if c.Perf.LogSampleRate == 0 {
		c.Perf.LogSampleRate = 1
	}
	if c.Perf.ProxyMaxIdleConns == 0 {
		c.Perf.ProxyMaxIdleConns = 2048
	}
	if c.Perf.ProxyMaxIdleConnsPerHost == 0 {
		c.Perf.ProxyMaxIdleConnsPerHost = 1024
	}
	if c.Perf.ProxyIdleConnTimeout == 0 {
		c.Perf.ProxyIdleConnTimeout = 90 * time.Second
	}
	if c.Perf.ProxyResponseHeaderTimeout == 0 {
		c.Perf.ProxyResponseHeaderTimeout = 5 * time.Second
	}
	if c.Perf.ProxyExpectContinueTimeout == 0 {
		c.Perf.ProxyExpectContinueTimeout = time.Second
	}

	if c.DenyPage.Title == "" {
		c.DenyPage.Title = "Access Unavailable"
	}
	if c.DenyPage.Heading == "" {
		c.DenyPage.Heading = "Request Blocked"
	}
	if c.DenyPage.Message == "" {
		c.DenyPage.Message = "Your request did not pass the gateway security checks."
	}
	if c.DenyPage.Hint == "" {
		c.DenyPage.Hint = "If you believe this is a mistake, contact support and provide the request ID."
	}

	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Logging.Format == "" {
		c.Logging.Format = "text"
	}

	if c.Metrics.Path == "" {
		c.Metrics.Path = "/metrics"
	}
}

func (c *Config) Validate() error {
	var errs []error

	if c.Server.ListenAddress == "" {
		errs = append(errs, errors.New("server.listen_address is required"))
	}
	if c.Server.DenyStatusCode < 400 || c.Server.DenyStatusCode > 599 {
		errs = append(errs, errors.New("server.deny_status_code must be a 4xx/5xx code"))
	}

	if !slices.Contains([]string{"deny", "use_remote_addr"}, c.RealIP.UntrustedProxyAction) {
		errs = append(errs, errors.New("real_ip.untrusted_proxy_action must be deny or use_remote_addr"))
	}
	if !c.RealIP.TrustAllSources && len(c.RealIP.TrustedProxyCIDRs) == 0 {
		errs = append(errs, errors.New("real_ip.trusted_proxy_cidrs is required when real_ip.trust_all_sources is false"))
	}
	for _, cidr := range c.RealIP.TrustedProxyCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			errs = append(errs, fmt.Errorf("invalid trusted proxy cidr %q: %w", cidr, err))
		}
	}
	validHeaders := map[string]struct{}{
		"CF-Connecting-IP":   {},
		"CF-Connecting-IPv6": {},
		"True-Client-IP":     {},
		"X-Real-IP":          {},
		"X-Forwarded-For":    {},
	}
	for _, header := range c.RealIP.HeaderPriority {
		if _, ok := validHeaders[header]; !ok {
			errs = append(errs, fmt.Errorf("unsupported real_ip.header_priority value %q", header))
		}
	}
	if c.IPInfo.Enabled && strings.TrimSpace(c.IPInfo.Token) == "" {
		errs = append(errs, errors.New("ipinfo.token is required when ipinfo.enabled is true"))
	}
	if c.Cache.ShortCircuitTTL <= 0 {
		errs = append(errs, errors.New("cache.short_circuit_ttl must be > 0"))
	}
	if c.Cache.LocalFallbackTTL <= 0 {
		errs = append(errs, errors.New("cache.local_fallback_ttl must be > 0"))
	}
	if c.Cache.L1.Shards <= 0 {
		errs = append(errs, errors.New("cache.l1.shards must be > 0"))
	}
	if c.Cache.L1.ShortCircuitEntries <= 0 {
		errs = append(errs, errors.New("cache.l1.short_circuit_entries must be > 0"))
	}

	if len(c.Routing.Services) == 0 {
		errs = append(errs, errors.New("routing.services must contain at least one service"))
	}
	seenServices := make(map[string]struct{}, len(c.Routing.Services))
	for _, svc := range c.Routing.Services {
		if svc.Name == "" {
			errs = append(errs, errors.New("routing.services[].name is required"))
			continue
		}
		if _, exists := seenServices[svc.Name]; exists {
			errs = append(errs, fmt.Errorf("duplicate routing service %q", svc.Name))
		}
		seenServices[svc.Name] = struct{}{}
		if svc.TargetURL == "" {
			errs = append(errs, fmt.Errorf("routing service %q requires target_url", svc.Name))
		} else if _, err := url.ParseRequestURI(svc.TargetURL); err != nil {
			errs = append(errs, fmt.Errorf("invalid target_url for service %q: %w", svc.Name, err))
		}
	}
	if _, ok := seenServices[c.Routing.DefaultService]; !ok {
		errs = append(errs, fmt.Errorf("routing.default_service %q is not present in routing.services", c.Routing.DefaultService))
	}

	if c.Security.Geo.DefaultAction != "deny" {
		errs = append(errs, errors.New("security.geo.default_action currently only supports deny"))
	}
	for country := range c.Security.Geo.Whitelist {
		if len(strings.TrimSpace(country)) != 2 {
			errs = append(errs, fmt.Errorf("security.geo.whitelist country %q must be ISO-3166 alpha-2 code", country))
		}
	}

	validRiskTypes := map[string]struct{}{
		"vpn": {}, "proxy": {}, "tor": {}, "relay": {}, "hosting": {}, "residential_proxy": {},
	}
	for _, allowType := range c.Security.Privacy.AllowTypes {
		if _, ok := validRiskTypes[allowType]; !ok {
			errs = append(errs, fmt.Errorf("unsupported privacy allow_type %q", allowType))
		}
	}

	if strings.TrimSpace(c.DenyPage.TargetURL) != "" {
		if _, err := url.ParseRequestURI(c.DenyPage.TargetURL); err != nil {
			errs = append(errs, fmt.Errorf("invalid deny_page.target_url: %w", err))
		}
	}

	if strings.TrimSpace(c.Mongo.URI) != "" && strings.TrimSpace(c.Mongo.Database) == "" {
		errs = append(errs, errors.New("mongo.database is required when mongo.uri is set"))
	}
	if strings.TrimSpace(c.Mongo.Database) != "" && strings.TrimSpace(c.Mongo.URI) == "" {
		errs = append(errs, errors.New("mongo.uri is required when mongo.database is set"))
	}
	if c.Alerts.Telegram.Enabled {
		if strings.TrimSpace(c.Alerts.Telegram.BotToken) == "" {
			errs = append(errs, errors.New("alerts.telegram.bot_token is required when alerts.telegram.enabled is true"))
		}
		if strings.TrimSpace(c.Alerts.Telegram.ChatID) == "" {
			errs = append(errs, errors.New("alerts.telegram.chat_id is required when alerts.telegram.enabled is true"))
		}
	}
	if c.Alerts.Delivery.WorkerEnabled && !c.Alerts.Telegram.Enabled {
		errs = append(errs, errors.New("alerts.delivery.worker_enabled requires alerts.telegram.enabled to be true"))
	}
	if c.Reports.Enabled && !c.Alerts.Telegram.Enabled {
		errs = append(errs, errors.New("reports.enabled requires alerts.telegram.enabled to be true"))
	}
	if c.Reports.TimeZone != "" {
		if _, err := time.LoadLocation(c.Reports.TimeZone); err != nil {
			errs = append(errs, fmt.Errorf("invalid reports.timezone %q: %w", c.Reports.TimeZone, err))
		}
	}
	if !strings.Contains(c.Reports.DailySendTime, ":") {
		errs = append(errs, errors.New("reports.daily_send_time must use HH:MM format"))
	}
	if c.Storage.LocalPath == "" {
		errs = append(errs, errors.New("storage.local_path is required"))
	}
	if c.Storage.ReplayInterval <= 0 {
		errs = append(errs, errors.New("storage.replay_interval must be > 0"))
	}
	if c.Storage.MongoProbeInterval <= 0 {
		errs = append(errs, errors.New("storage.mongo_probe_interval must be > 0"))
	}
	if c.Storage.ReplayBatchSize <= 0 {
		errs = append(errs, errors.New("storage.replay_batch_size must be > 0"))
	}
	if c.Storage.ReplayWorkers <= 0 {
		errs = append(errs, errors.New("storage.replay_workers must be > 0"))
	}
	if c.Perf.RequestQueueSize <= 0 {
		errs = append(errs, errors.New("performance.request_queue_size must be > 0"))
	}
	if c.Perf.AsyncWriteQueueSize <= 0 {
		errs = append(errs, errors.New("performance.async_write_queue_size must be > 0"))
	}
	if c.Perf.StatsQueueSize <= 0 {
		errs = append(errs, errors.New("performance.stats_queue_size must be > 0"))
	}
	if c.Perf.ProxyMaxIdleConns <= 0 || c.Perf.ProxyMaxIdleConnsPerHost <= 0 {
		errs = append(errs, errors.New("performance proxy pool sizes must be > 0"))
	}
	if !slices.Contains([]string{"json", "text"}, strings.ToLower(c.Logging.Format)) {
		errs = append(errs, errors.New("logging.format must be json or text"))
	}

	if len(errs) == 0 {
		return nil
	}
	return errors.Join(errs...)
}

func (c *Config) NeedsMongo() bool {
	return c.IPInfo.Enabled || c.Alerts.Telegram.Enabled || c.Alerts.Delivery.WorkerEnabled
}
