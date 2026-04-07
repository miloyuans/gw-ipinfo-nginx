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
	MongoCollections MongoCollections `yaml:"mongo_collections"`
}

type L1CacheConfig struct {
	Enabled           bool `yaml:"enabled"`
	MaxEntries        int  `yaml:"max_entries"`
	CleanupIntervalSec int  `yaml:"cleanup_interval_sec"`
}

type CacheTTLConfig struct {
	Geo              time.Duration `yaml:"geo"`
	Privacy          time.Duration `yaml:"privacy"`
	ResidentialProxy time.Duration `yaml:"residential_proxy"`
}

type MongoCollections struct {
	IPCache     string `yaml:"ip_cache"`
	AlertOutbox string `yaml:"alert_outbox"`
	AlertDedupe string `yaml:"alert_dedupe"`
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

type DenyPageConfig struct {
	Title   string `yaml:"title"`
	Heading string `yaml:"heading"`
	Message string `yaml:"message"`
	Hint    string `yaml:"hint"`
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
	if c.Cache.MongoCollections.IPCache == "" {
		c.Cache.MongoCollections.IPCache = "ip_risk_cache"
	}
	if c.Cache.MongoCollections.AlertOutbox == "" {
		c.Cache.MongoCollections.AlertOutbox = "alerts_outbox"
	}
	if c.Cache.MongoCollections.AlertDedupe == "" {
		c.Cache.MongoCollections.AlertDedupe = "alerts_dedupe"
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
		"CF-Connecting-IP": {},
		"True-Client-IP":   {},
		"X-Real-IP":        {},
		"X-Forwarded-For":  {},
	}
	for _, header := range c.RealIP.HeaderPriority {
		if _, ok := validHeaders[header]; !ok {
			errs = append(errs, fmt.Errorf("unsupported real_ip.header_priority value %q", header))
		}
	}
	if c.IPInfo.Enabled && strings.TrimSpace(c.IPInfo.Token) == "" {
		errs = append(errs, errors.New("ipinfo.token is required when ipinfo.enabled is true"))
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

	if c.NeedsMongo() {
		if c.Mongo.URI == "" {
			errs = append(errs, errors.New("mongo.uri is required when ipinfo or alerts are enabled"))
		}
		if c.Mongo.Database == "" {
			errs = append(errs, errors.New("mongo.database is required when ipinfo or alerts are enabled"))
		}
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
