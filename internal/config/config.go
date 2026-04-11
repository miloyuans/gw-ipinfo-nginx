package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
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
	RouteSets RouteSetsConfig `yaml:"route_sets"`
	V3Defaults V3DefaultsConfig `yaml:"v3_defaults"`
	V4       V4Config         `yaml:"v4"`
	Alerts   AlertsConfig   `yaml:"alerts"`
	Reports  ReportsConfig  `yaml:"reports"`
	Storage  StorageConfig  `yaml:"storage"`
	Perf     PerformanceConfig `yaml:"performance"`
	Branding BrandingConfig `yaml:"branding"`
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
	Prefork         PreforkConfig `yaml:"prefork"`
}

type PreforkConfig struct {
	Enabled   bool `yaml:"enabled"`
	Processes int  `yaml:"processes"`
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
	Timeout          time.Duration `yaml:"timeout"`
	MaxPoolSize      uint64        `yaml:"maxPoolSize"`
	MaxOpenConns     uint64        `yaml:"maxOpenConns"`
	MaxIdleConns     uint64        `yaml:"maxIdleConns"`
	MinPoolSize      uint64        `yaml:"minPoolSize"`
	MaxConnecting    uint64        `yaml:"maxConnecting"`
	MaxConnIdleTime  time.Duration `yaml:"maxConnIdleTime"`
	ConnMaxLifetime  time.Duration `yaml:"connMaxLifetime"`
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

type RouteSetsConfig struct {
	Bypass             RouteSetFileConfig `yaml:"bypass"`
	Default            RouteSetFileConfig `yaml:"default"`
	V1                 RouteSetFileConfig `yaml:"v1"`
	V2                 RouteSetFileConfig `yaml:"v2"`
	V3                 RouteSetFileConfig `yaml:"v3"`
	V4                 RouteSetFileConfig `yaml:"v4"`
	StrictHostControl  bool               `yaml:"strict_host_control"`
	FailFastOnConflict bool               `yaml:"fail_fast_on_conflict"`
	RedirectStatusCode int                `yaml:"redirect_status_code"`
	V1Grant            V1GrantConfig      `yaml:"v1_grant"`
}

type RouteSetFileConfig struct {
	Enabled    bool   `yaml:"enabled"`
	ConfigPath string `yaml:"config_path"`
}

type V1GrantConfig struct {
	TTL                  time.Duration `yaml:"ttl"`
	BindUserAgent        bool          `yaml:"bind_user_agent"`
	BindClientIP         bool          `yaml:"bind_client_ip"`
	BindClientIPv4Prefix int           `yaml:"bind_client_ip_v4_prefix"`
	BindClientIPv6Prefix int           `yaml:"bind_client_ip_v6_prefix"`
	QueryParam           string        `yaml:"query_param"`
	CookieName           string        `yaml:"cookie_name"`
	SigningKey           string        `yaml:"signing_key"`
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
	Enabled         bool                  `yaml:"enabled"`
	Title           string                `yaml:"title"`
	TimeZoneMode    string                `yaml:"timezone_mode"`
	TimeZone        string                `yaml:"timezone"`
	DailySendTime   string                `yaml:"daily_send_time"`
	PeriodMode      string                `yaml:"period_mode"`
	Lookback        time.Duration         `yaml:"lookback"`
	RetryInterval   time.Duration         `yaml:"retry_interval"`
	MaxBackfillDays int                   `yaml:"max_backfill_days"`
	TopN            int                   `yaml:"top_n"`
	IncludeCSV      bool                  `yaml:"include_csv"`
	IncludeHTML     bool                  `yaml:"include_html"`
	WorkerEnabled   bool                  `yaml:"worker_enabled"`
	PollInterval    time.Duration         `yaml:"poll_interval"`
	ReplayBatchSize int                   `yaml:"replay_batch_size"`
	Output          ReportsOutputConfig   `yaml:"output"`
	Filename        ReportsFilenameConfig `yaml:"filename"`
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
	DisplayName      string `yaml:"display_name"`
	TitlePrefix      string `yaml:"title_prefix"`
	MaskQuery        bool   `yaml:"mask_query"`
	IncludeUserAgent bool   `yaml:"include_user_agent"`
	Lifecycle        TelegramLifecycleConfig `yaml:"lifecycle"`
	CommandBot       TelegramCommandBotConfig `yaml:"command_bot"`
}

type TelegramLifecycleConfig struct {
	StartupNotify    bool          `yaml:"startup_notify"`
	ShutdownNotify   bool          `yaml:"shutdown_notify"`
	UncleanExitNotify bool         `yaml:"unclean_exit_notify"`
	SelfCheckOnStart bool          `yaml:"self_check_on_start"`
	HeartbeatEnabled bool          `yaml:"heartbeat_enabled"`
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval"`
	NotifyMode       string        `yaml:"notify_mode"`
}

type TelegramCommandBotConfig struct {
	Enabled               bool                            `yaml:"enabled"`
	BotToken              string                          `yaml:"bot_token"`
	ChatID                string                          `yaml:"chat_id"`
	AllowedUserIDs        []int64                         `yaml:"allowed_user_ids"`
	APIBaseURL            string                          `yaml:"api_base_url"`
	Timeout               time.Duration                   `yaml:"timeout"`
	PollTimeout           time.Duration                   `yaml:"poll_timeout"`
	ErrorBackoff          time.Duration                   `yaml:"error_backoff"`
	LeaseName             string                          `yaml:"lease_name"`
	LeaseTTL              time.Duration                   `yaml:"lease_ttl"`
	RenewInterval         time.Duration                   `yaml:"renew_interval"`
	Command               string                          `yaml:"command"`
	ParseMode             string                          `yaml:"parse_mode"`
	IPInfoToken           string                          `yaml:"ipinfo_token"`
	DisablePrivateChat    bool                            `yaml:"disable_private_chat"`
	ReplyUnauthorizedChat bool                            `yaml:"reply_unauthorized_chat"`
	MaxIPsPerRequest      int                             `yaml:"max_ips_per_request"`
	MaxConcurrentLookups  int                             `yaml:"max_concurrent_lookups"`
	MessageChunkSize      int                             `yaml:"message_chunk_size"`
	Templates             TelegramCommandTemplateConfig   `yaml:"templates"`
}

type TelegramCommandTemplateConfig struct {
	Usage            string `yaml:"usage"`
	UnauthorizedChat string `yaml:"unauthorized_chat"`
	UnauthorizedUser string `yaml:"unauthorized_user"`
	TooManyIPs       string `yaml:"too_many_ips"`
	EmptyResult      string `yaml:"empty_result"`
}

type ReportsOutputConfig struct {
	TelegramEnabled bool   `yaml:"telegram_enabled"`
	FileEnabled     bool   `yaml:"file_enabled"`
	OutputDir       string `yaml:"output_dir"`
}

type ReportsFilenameConfig struct {
	Prefix     string `yaml:"prefix"`
	AppendDate bool   `yaml:"append_date"`
	DateFormat string `yaml:"date_format"`
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

type BrandingConfig struct {
	DisplayName string `yaml:"display_name"`
}

type V3DefaultsConfig struct {
	HealthCheck V3HealthDefaultsConfig `yaml:"health_check"`
}

type V3HealthDefaultsConfig struct {
	Interval           time.Duration `yaml:"interval"`
	Timeout            time.Duration `yaml:"timeout"`
	HealthyThreshold   int           `yaml:"healthy_threshold"`
	UnhealthyThreshold int           `yaml:"unhealthy_threshold"`
}

type V4Config struct {
	Enabled        bool                   `yaml:"enabled"`
	Sync           V4SyncConfig           `yaml:"sync"`
	Ingress        V4IngressConfig        `yaml:"ingress"`
	Passthrough    V4PassthroughConfig    `yaml:"passthrough"`
	Security       V4SecurityConfig       `yaml:"security"`
	IPEnrichment   V4IPEnrichmentConfig   `yaml:"ip_enrichment"`
	ProbeDefaults  V4ProbeDefaultsConfig  `yaml:"probe_defaults"`
	Telegram       V4TelegramConfig       `yaml:"telegram"`
	Overrides      []V4OverrideConfig     `yaml:"overrides"`
}

type V4SyncConfig struct {
	Enabled       bool          `yaml:"enabled"`
	Interval      time.Duration `yaml:"interval"`
	LeaseName     string        `yaml:"lease_name"`
	LeaseTTL      time.Duration `yaml:"lease_ttl"`
	RenewInterval time.Duration `yaml:"renew_interval"`
}

type V4IngressConfig struct {
	ConfigPaths []string `yaml:"config_paths"`
}

type V4PassthroughConfig struct {
	Service string `yaml:"service"`
}

type V4SecurityConfig struct {
	SecurityChecksEnabled bool `yaml:"security_checks_enabled"`
}

type V4IPEnrichmentConfig struct {
	Mode string `yaml:"mode"`
}

type V4ProbeDefaultsConfig struct {
	Interval           time.Duration `yaml:"interval"`
	Timeout            time.Duration `yaml:"timeout"`
	HealthyThreshold   int           `yaml:"healthy_threshold"`
	UnhealthyThreshold int           `yaml:"unhealthy_threshold"`
	MinSwitchInterval  time.Duration `yaml:"min_switch_interval"`
	UserAgent          string        `yaml:"user_agent"`
}

type V4TelegramConfig struct {
	Enabled       bool          `yaml:"enabled"`
	Command       string        `yaml:"command"`
	SendHTMLFile  bool          `yaml:"send_html_file"`
	MaxHosts      int           `yaml:"max_hosts"`
	DedupeWindow  time.Duration `yaml:"dedupe_window"`
	SilentWindow  time.Duration `yaml:"silent_window"`
}

type V4OverrideConfig struct {
	Host                  string               `yaml:"host"`
	Enabled               bool                 `yaml:"enabled"`
	BackendService        string               `yaml:"backend_service"`
	BackendHost           string               `yaml:"backend_host"`
	SecurityChecksEnabled *bool                `yaml:"security_checks_enabled"`
	IPEnrichmentMode      string               `yaml:"ip_enrichment_mode"`
	Probe                 V4ProbeConfig        `yaml:"probe"`
}

type V4ProbeConfig struct {
	Enabled            bool          `yaml:"enabled"`
	Mode               string        `yaml:"mode"`
	URL                string        `yaml:"url"`
	LinkURL            string        `yaml:"link_url"`
	Patterns           []string      `yaml:"patterns"`
	Interval           time.Duration `yaml:"interval"`
	Timeout            time.Duration `yaml:"timeout"`
	HealthyThreshold   int           `yaml:"healthy_threshold"`
	UnhealthyThreshold int           `yaml:"unhealthy_threshold"`
	MinSwitchInterval  time.Duration `yaml:"min_switch_interval"`
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
	if c.Server.Prefork.Enabled && c.Server.Prefork.Processes == 0 {
		c.Server.Prefork.Processes = runtime.NumCPU()
		if c.Server.Prefork.Processes <= 0 {
			c.Server.Prefork.Processes = 1
		}
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
	if c.Mongo.MaxPoolSize == 0 && c.Mongo.MaxOpenConns > 0 {
		c.Mongo.MaxPoolSize = c.Mongo.MaxOpenConns
	}
	if c.Mongo.MinPoolSize == 0 && c.Mongo.MaxIdleConns > 0 {
		c.Mongo.MinPoolSize = c.Mongo.MaxIdleConns
		if c.Mongo.MaxPoolSize > 0 && c.Mongo.MinPoolSize > c.Mongo.MaxPoolSize {
			c.Mongo.MinPoolSize = c.Mongo.MaxPoolSize
		}
	}
	if c.Mongo.MaxConnIdleTime == 0 && c.Mongo.ConnMaxLifetime > 0 {
		c.Mongo.MaxConnIdleTime = c.Mongo.ConnMaxLifetime
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
	if c.RouteSets.Default.ConfigPath == "" {
		c.RouteSets.Default.ConfigPath = "defaultroute.yaml"
	}
	if c.RouteSets.Bypass.ConfigPath == "" {
		c.RouteSets.Bypass.ConfigPath = "bypassroute.yaml"
	}
	if c.RouteSets.V1.ConfigPath == "" {
		c.RouteSets.V1.ConfigPath = "passroute_v1.yaml"
	}
	if c.RouteSets.V2.ConfigPath == "" {
		c.RouteSets.V2.ConfigPath = "passroute_v2.yaml"
	}
	if c.RouteSets.V3.ConfigPath == "" {
		c.RouteSets.V3.ConfigPath = "passroute_v3.yaml"
	}
	if c.RouteSets.V4.ConfigPath == "" {
		c.RouteSets.V4.ConfigPath = "passroute_v4.yaml"
	}
	if c.RouteSets.RedirectStatusCode == 0 {
		c.RouteSets.RedirectStatusCode = 302
	}
	if c.RouteSets.V1Grant.TTL == 0 {
		c.RouteSets.V1Grant.TTL = time.Hour
	}
	if c.RouteSets.V1Grant.BindClientIPv4Prefix == 0 {
		c.RouteSets.V1Grant.BindClientIPv4Prefix = 24
	}
	if c.RouteSets.V1Grant.BindClientIPv6Prefix == 0 {
		c.RouteSets.V1Grant.BindClientIPv6Prefix = 56
	}
	if c.RouteSets.V1Grant.QueryParam == "" {
		c.RouteSets.V1Grant.QueryParam = "gwgr"
	}
	if c.RouteSets.V1Grant.CookieName == "" {
		c.RouteSets.V1Grant.CookieName = "__Host-gwgr"
	}

	if c.Alerts.Telegram.APIBaseURL == "" {
		c.Alerts.Telegram.APIBaseURL = "https://api.telegram.org"
	}
	if c.Branding.DisplayName == "" {
		c.Branding.DisplayName = "gw-ipinfo-nginx"
	}
	if c.Alerts.Telegram.Timeout == 0 {
		c.Alerts.Telegram.Timeout = 5 * time.Second
	}
	if c.Alerts.Telegram.DisplayName == "" {
		c.Alerts.Telegram.DisplayName = c.Branding.DisplayName
	}
	if c.Alerts.Telegram.Lifecycle.HeartbeatInterval == 0 {
		c.Alerts.Telegram.Lifecycle.HeartbeatInterval = 30 * time.Minute
	}
	if c.Alerts.Telegram.Lifecycle.NotifyMode == "" {
		c.Alerts.Telegram.Lifecycle.NotifyMode = "notify"
	}
	if c.Alerts.Telegram.CommandBot.APIBaseURL == "" {
		c.Alerts.Telegram.CommandBot.APIBaseURL = c.Alerts.Telegram.APIBaseURL
	}
	if c.Alerts.Telegram.CommandBot.BotToken == "" {
		c.Alerts.Telegram.CommandBot.BotToken = c.Alerts.Telegram.BotToken
	}
	if c.Alerts.Telegram.CommandBot.ChatID == "" {
		c.Alerts.Telegram.CommandBot.ChatID = c.Alerts.Telegram.ChatID
	}
	if c.Alerts.Telegram.CommandBot.Timeout == 0 {
		if c.Alerts.Telegram.Timeout > 0 {
			c.Alerts.Telegram.CommandBot.Timeout = c.Alerts.Telegram.Timeout
		} else {
			c.Alerts.Telegram.CommandBot.Timeout = 60 * time.Second
		}
	}
	if c.Alerts.Telegram.CommandBot.PollTimeout == 0 {
		c.Alerts.Telegram.CommandBot.PollTimeout = 25 * time.Second
	}
	if c.Alerts.Telegram.CommandBot.ErrorBackoff == 0 {
		c.Alerts.Telegram.CommandBot.ErrorBackoff = 2 * time.Second
	}
	if c.Alerts.Telegram.CommandBot.LeaseName == "" {
		c.Alerts.Telegram.CommandBot.LeaseName = "telegram-command-bot"
	}
	if c.Alerts.Telegram.CommandBot.LeaseTTL == 0 {
		c.Alerts.Telegram.CommandBot.LeaseTTL = 45 * time.Second
	}
	if c.Alerts.Telegram.CommandBot.RenewInterval == 0 {
		c.Alerts.Telegram.CommandBot.RenewInterval = 15 * time.Second
	}
	if c.Alerts.Telegram.CommandBot.Command == "" {
		c.Alerts.Telegram.CommandBot.Command = "/q"
	}
	if c.Alerts.Telegram.CommandBot.ParseMode == "" {
		c.Alerts.Telegram.CommandBot.ParseMode = "HTML"
	}
	if c.Alerts.Telegram.CommandBot.IPInfoToken == "" {
		c.Alerts.Telegram.CommandBot.IPInfoToken = c.IPInfo.Token
	}
	if c.Alerts.Telegram.CommandBot.MaxIPsPerRequest == 0 {
		c.Alerts.Telegram.CommandBot.MaxIPsPerRequest = 10
	}
	if c.Alerts.Telegram.CommandBot.MaxConcurrentLookups == 0 {
		c.Alerts.Telegram.CommandBot.MaxConcurrentLookups = 5
	}
	if c.Alerts.Telegram.CommandBot.MessageChunkSize == 0 {
		c.Alerts.Telegram.CommandBot.MessageChunkSize = 3500
	}
	if c.Alerts.Telegram.CommandBot.Templates.Usage == "" {
		c.Alerts.Telegram.CommandBot.Templates.Usage = "用法：%s <IP1> <IP2> ...\n例如：%s 114.114.114.114 8.8.8.8\n支持 IPv6：%s 2001:4860:4860::8888"
	}
	if c.Alerts.Telegram.CommandBot.Templates.UnauthorizedChat == "" {
		c.Alerts.Telegram.CommandBot.Templates.UnauthorizedChat = "此机器人仅允许在指定群内使用。"
	}
	if c.Alerts.Telegram.CommandBot.Templates.UnauthorizedUser == "" {
		c.Alerts.Telegram.CommandBot.Templates.UnauthorizedUser = "你没有权限使用此机器人命令。"
	}
	if c.Alerts.Telegram.CommandBot.Templates.TooManyIPs == "" {
		c.Alerts.Telegram.CommandBot.Templates.TooManyIPs = "本次最多查询 %d 个 IP，已自动截断超出部分。"
	}
	if c.Alerts.Telegram.CommandBot.Templates.EmptyResult == "" {
		c.Alerts.Telegram.CommandBot.Templates.EmptyResult = "没有可展示的查询结果。"
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
	if c.Reports.TimeZoneMode == "" {
		c.Reports.TimeZoneMode = "config"
	}
	if c.Reports.TimeZone == "" {
		c.Reports.TimeZone = "UTC"
	}
	if c.Reports.Title == "" {
		c.Reports.Title = c.Branding.DisplayName + " 日报"
	}
	if c.Reports.DailySendTime == "" {
		c.Reports.DailySendTime = "09:00"
	}
	if c.Reports.PeriodMode == "" {
		c.Reports.PeriodMode = "lookback"
	}
	if c.Reports.Lookback == 0 {
		c.Reports.Lookback = 24 * time.Hour
	}
	if c.Reports.RetryInterval == 0 {
		c.Reports.RetryInterval = 15 * time.Minute
	}
	if c.Reports.MaxBackfillDays == 0 {
		c.Reports.MaxBackfillDays = 7
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
	if !c.Reports.Output.TelegramEnabled && !c.Reports.Output.FileEnabled && c.Reports.Enabled && c.Alerts.Telegram.Enabled {
		c.Reports.Output.TelegramEnabled = true
	}
	if c.Reports.Filename.Prefix == "" {
		c.Reports.Filename.Prefix = "gw-report"
	}
	if c.Reports.Filename.DateFormat == "" {
		c.Reports.Filename.DateFormat = "2006-01-02"
	}
	if !c.Reports.Filename.AppendDate && c.Reports.Filename.Prefix == "gw-report" && c.Reports.Filename.DateFormat == "2006-01-02" {
		c.Reports.Filename.AppendDate = true
	}

	if c.Storage.LocalPath == "" {
		c.Storage.LocalPath = "/data/shared/gw-ipinfo-nginx.db"
	}
	if c.V3Defaults.HealthCheck.Interval == 0 {
		c.V3Defaults.HealthCheck.Interval = 30 * time.Second
	}
	if c.V3Defaults.HealthCheck.Timeout == 0 {
		c.V3Defaults.HealthCheck.Timeout = 3 * time.Second
	}
	if c.V3Defaults.HealthCheck.HealthyThreshold == 0 {
		c.V3Defaults.HealthCheck.HealthyThreshold = 2
	}
	if c.V3Defaults.HealthCheck.UnhealthyThreshold == 0 {
		c.V3Defaults.HealthCheck.UnhealthyThreshold = 2
	}
	if c.V4.Sync.Interval == 0 {
		c.V4.Sync.Interval = time.Minute
	}
	if c.V4.Sync.LeaseName == "" {
		c.V4.Sync.LeaseName = "v4-snapshot-sync"
	}
	if c.V4.Sync.LeaseTTL == 0 {
		c.V4.Sync.LeaseTTL = 45 * time.Second
	}
	if c.V4.Sync.RenewInterval == 0 {
		c.V4.Sync.RenewInterval = 15 * time.Second
	}
	if c.V4.Passthrough.Service == "" {
		c.V4.Passthrough.Service = c.Routing.DefaultService
	}
	if c.V4.IPEnrichment.Mode == "" {
		c.V4.IPEnrichment.Mode = "disabled"
	}
	if c.V4.ProbeDefaults.Interval == 0 {
		c.V4.ProbeDefaults.Interval = 30 * time.Second
	}
	if c.V4.ProbeDefaults.Timeout == 0 {
		c.V4.ProbeDefaults.Timeout = 3 * time.Second
	}
	if c.V4.ProbeDefaults.HealthyThreshold == 0 {
		c.V4.ProbeDefaults.HealthyThreshold = 2
	}
	if c.V4.ProbeDefaults.UnhealthyThreshold == 0 {
		c.V4.ProbeDefaults.UnhealthyThreshold = 2
	}
	if c.V4.ProbeDefaults.MinSwitchInterval == 0 {
		c.V4.ProbeDefaults.MinSwitchInterval = 2 * time.Minute
	}
	if c.V4.ProbeDefaults.UserAgent == "" {
		c.V4.ProbeDefaults.UserAgent = "gw-ipinfo-nginx-v4-probe/1.0"
	}
	if c.V4.Telegram.Command == "" {
		c.V4.Telegram.Command = "/routes"
	}
	if c.V4.Telegram.MaxHosts == 0 {
		c.V4.Telegram.MaxHosts = 3
	}
	if c.V4.Telegram.DedupeWindow == 0 {
		c.V4.Telegram.DedupeWindow = 15 * time.Minute
	}
	if c.V4.Telegram.SilentWindow == 0 {
		c.V4.Telegram.SilentWindow = time.Hour
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
	if c.Server.Prefork.Processes < 0 {
		errs = append(errs, errors.New("server.prefork.processes must be >= 0"))
	}
	if c.Server.Prefork.Enabled && c.Server.Prefork.Processes <= 0 {
		errs = append(errs, errors.New("server.prefork.processes must be > 0 when server.prefork.enabled is true"))
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
	if c.RouteSets.RedirectStatusCode < 300 || c.RouteSets.RedirectStatusCode > 399 {
		errs = append(errs, errors.New("route_sets.redirect_status_code must be a 3xx code"))
	}
	if c.RouteSets.V1Grant.TTL <= 0 {
		errs = append(errs, errors.New("route_sets.v1_grant.ttl must be > 0"))
	}
	if c.RouteSets.V1Grant.BindClientIPv4Prefix < 0 || c.RouteSets.V1Grant.BindClientIPv4Prefix > 32 {
		errs = append(errs, errors.New("route_sets.v1_grant.bind_client_ip_v4_prefix must be between 0 and 32"))
	}
	if c.RouteSets.V1Grant.BindClientIPv6Prefix < 0 || c.RouteSets.V1Grant.BindClientIPv6Prefix > 128 {
		errs = append(errs, errors.New("route_sets.v1_grant.bind_client_ip_v6_prefix must be between 0 and 128"))
	}
	if c.RouteSets.V1.Enabled && strings.TrimSpace(c.RouteSets.V1Grant.SigningKey) == "" {
		errs = append(errs, errors.New("route_sets.v1_grant.signing_key is required when route_sets.v1.enabled is true"))
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
	if c.Mongo.Timeout < 0 {
		errs = append(errs, errors.New("mongo.timeout must be >= 0"))
	}
	if c.Mongo.MaxPoolSize > 0 && c.Mongo.MinPoolSize > c.Mongo.MaxPoolSize {
		errs = append(errs, errors.New("mongo.minPoolSize must be <= mongo.maxPoolSize"))
	}
	if c.Mongo.MaxConnecting > 0 && c.Mongo.MaxPoolSize > 0 && c.Mongo.MaxConnecting > c.Mongo.MaxPoolSize {
		errs = append(errs, errors.New("mongo.maxConnecting must be <= mongo.maxPoolSize"))
	}
	if c.Mongo.MaxConnIdleTime < 0 {
		errs = append(errs, errors.New("mongo.maxConnIdleTime must be >= 0"))
	}
	if c.Alerts.Telegram.Enabled {
		if strings.TrimSpace(c.Alerts.Telegram.BotToken) == "" {
			errs = append(errs, errors.New("alerts.telegram.bot_token is required when alerts.telegram.enabled is true"))
		}
		if strings.TrimSpace(c.Alerts.Telegram.ChatID) == "" {
			errs = append(errs, errors.New("alerts.telegram.chat_id is required when alerts.telegram.enabled is true"))
		}
	}
	if !slices.Contains([]string{"notify", "log_only"}, c.Alerts.Telegram.Lifecycle.NotifyMode) {
		errs = append(errs, errors.New("alerts.telegram.lifecycle.notify_mode must be notify or log_only"))
	}
	if c.Alerts.Telegram.Lifecycle.HeartbeatInterval <= 0 {
		errs = append(errs, errors.New("alerts.telegram.lifecycle.heartbeat_interval must be > 0"))
	}
	if c.Alerts.Delivery.WorkerEnabled && !c.Alerts.Telegram.Enabled {
		errs = append(errs, errors.New("alerts.delivery.worker_enabled requires alerts.telegram.enabled to be true"))
	}
	if c.Alerts.Telegram.CommandBot.Enabled {
		if strings.TrimSpace(c.Alerts.Telegram.CommandBot.BotToken) == "" {
			errs = append(errs, errors.New("alerts.telegram.command_bot.bot_token is required when alerts.telegram.command_bot.enabled is true"))
		}
		if strings.TrimSpace(c.Alerts.Telegram.CommandBot.ChatID) == "" {
			errs = append(errs, errors.New("alerts.telegram.command_bot.chat_id is required when alerts.telegram.command_bot.enabled is true"))
		}
		if _, err := strconv.ParseInt(strings.TrimSpace(c.Alerts.Telegram.CommandBot.ChatID), 10, 64); err != nil {
			errs = append(errs, fmt.Errorf("alerts.telegram.command_bot.chat_id must be a valid int64: %w", err))
		}
		if strings.TrimSpace(c.Alerts.Telegram.CommandBot.APIBaseURL) == "" {
			errs = append(errs, errors.New("alerts.telegram.command_bot.api_base_url is required when alerts.telegram.command_bot.enabled is true"))
		}
		if strings.TrimSpace(c.Alerts.Telegram.CommandBot.IPInfoToken) == "" {
			errs = append(errs, errors.New("alerts.telegram.command_bot.ipinfo_token is required when alerts.telegram.command_bot.enabled is true"))
		}
		if c.Alerts.Telegram.CommandBot.Timeout <= 0 {
			errs = append(errs, errors.New("alerts.telegram.command_bot.timeout must be > 0"))
		}
		if c.Alerts.Telegram.CommandBot.PollTimeout <= 0 {
			errs = append(errs, errors.New("alerts.telegram.command_bot.poll_timeout must be > 0"))
		}
		if c.Alerts.Telegram.CommandBot.ErrorBackoff <= 0 {
			errs = append(errs, errors.New("alerts.telegram.command_bot.error_backoff must be > 0"))
		}
		if strings.TrimSpace(c.Alerts.Telegram.CommandBot.LeaseName) == "" {
			errs = append(errs, errors.New("alerts.telegram.command_bot.lease_name is required when alerts.telegram.command_bot.enabled is true"))
		}
		if c.Alerts.Telegram.CommandBot.LeaseTTL <= 0 {
			errs = append(errs, errors.New("alerts.telegram.command_bot.lease_ttl must be > 0"))
		}
		if c.Alerts.Telegram.CommandBot.RenewInterval <= 0 {
			errs = append(errs, errors.New("alerts.telegram.command_bot.renew_interval must be > 0"))
		}
		if c.Alerts.Telegram.CommandBot.RenewInterval >= c.Alerts.Telegram.CommandBot.LeaseTTL {
			errs = append(errs, errors.New("alerts.telegram.command_bot.renew_interval must be less than lease_ttl"))
		}
		if c.Alerts.Telegram.CommandBot.MaxIPsPerRequest <= 0 {
			errs = append(errs, errors.New("alerts.telegram.command_bot.max_ips_per_request must be > 0"))
		}
		if c.Alerts.Telegram.CommandBot.MaxConcurrentLookups <= 0 {
			errs = append(errs, errors.New("alerts.telegram.command_bot.max_concurrent_lookups must be > 0"))
		}
		if c.Alerts.Telegram.CommandBot.MessageChunkSize <= 0 {
			errs = append(errs, errors.New("alerts.telegram.command_bot.message_chunk_size must be > 0"))
		}
		if !strings.HasPrefix(strings.TrimSpace(c.Alerts.Telegram.CommandBot.Command), "/") {
			errs = append(errs, errors.New("alerts.telegram.command_bot.command must start with '/'"))
		}
	}
	if !slices.Contains([]string{"config", "system"}, c.Reports.TimeZoneMode) {
		errs = append(errs, errors.New("reports.timezone_mode must be config or system"))
	}
	if !slices.Contains([]string{"previous_day", "lookback"}, c.Reports.PeriodMode) {
		errs = append(errs, errors.New("reports.period_mode must be previous_day or lookback"))
	}
	if c.Reports.RetryInterval <= 0 {
		errs = append(errs, errors.New("reports.retry_interval must be > 0"))
	}
	if c.Reports.MaxBackfillDays <= 0 {
		errs = append(errs, errors.New("reports.max_backfill_days must be > 0"))
	}
	if c.Reports.Enabled && c.Reports.Output.TelegramEnabled && !c.Alerts.Telegram.Enabled {
		errs = append(errs, errors.New("reports.output.telegram_enabled requires alerts.telegram.enabled to be true"))
	}
	if c.Reports.Enabled && c.Reports.Output.FileEnabled && strings.TrimSpace(c.Reports.Output.OutputDir) == "" {
		errs = append(errs, errors.New("reports.output.output_dir is required when reports.output.file_enabled is true"))
	}
	if c.Reports.TimeZoneMode == "config" && c.Reports.TimeZone != "" {
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
	if c.V3Defaults.HealthCheck.Interval <= 0 {
		errs = append(errs, errors.New("v3_defaults.health_check.interval must be > 0"))
	}
	if c.V3Defaults.HealthCheck.Timeout <= 0 {
		errs = append(errs, errors.New("v3_defaults.health_check.timeout must be > 0"))
	}
	if c.V3Defaults.HealthCheck.HealthyThreshold <= 0 {
		errs = append(errs, errors.New("v3_defaults.health_check.healthy_threshold must be > 0"))
	}
	if c.V3Defaults.HealthCheck.UnhealthyThreshold <= 0 {
		errs = append(errs, errors.New("v3_defaults.health_check.unhealthy_threshold must be > 0"))
	}
	if c.V4.Enabled {
		if c.V4.Sync.Interval <= 0 {
			errs = append(errs, errors.New("v4.sync.interval must be > 0"))
		}
		if strings.TrimSpace(c.V4.Sync.LeaseName) == "" {
			errs = append(errs, errors.New("v4.sync.lease_name is required when v4.enabled is true"))
		}
		if c.V4.Sync.LeaseTTL <= 0 {
			errs = append(errs, errors.New("v4.sync.lease_ttl must be > 0"))
		}
		if c.V4.Sync.RenewInterval <= 0 {
			errs = append(errs, errors.New("v4.sync.renew_interval must be > 0"))
		}
		if c.V4.Sync.RenewInterval >= c.V4.Sync.LeaseTTL {
			errs = append(errs, errors.New("v4.sync.renew_interval must be less than lease_ttl"))
		}
		if len(c.V4.Ingress.ConfigPaths) == 0 {
			errs = append(errs, errors.New("v4.ingress.config_paths must contain at least one file when v4.enabled is true"))
		}
		if c.RouteSets.V4.Enabled && strings.TrimSpace(c.RouteSets.V4.ConfigPath) == "" {
			errs = append(errs, errors.New("route_sets.v4.config_path is required when route_sets.v4.enabled is true"))
		}
		if strings.TrimSpace(c.V4.Passthrough.Service) == "" {
			errs = append(errs, errors.New("v4.passthrough.service is required when v4.enabled is true"))
		} else if _, ok := seenServices[c.V4.Passthrough.Service]; !ok {
			errs = append(errs, fmt.Errorf("v4.passthrough.service %q is not present in routing.services", c.V4.Passthrough.Service))
		}
		if !slices.Contains([]string{"disabled", "cache_only", "full"}, c.V4.IPEnrichment.Mode) {
			errs = append(errs, errors.New("v4.ip_enrichment.mode must be disabled, cache_only, or full"))
		}
		if c.V4.ProbeDefaults.Interval <= 0 {
			errs = append(errs, errors.New("v4.probe_defaults.interval must be > 0"))
		}
		if c.V4.ProbeDefaults.Timeout <= 0 {
			errs = append(errs, errors.New("v4.probe_defaults.timeout must be > 0"))
		}
		if c.V4.ProbeDefaults.HealthyThreshold <= 0 {
			errs = append(errs, errors.New("v4.probe_defaults.healthy_threshold must be > 0"))
		}
		if c.V4.ProbeDefaults.UnhealthyThreshold <= 0 {
			errs = append(errs, errors.New("v4.probe_defaults.unhealthy_threshold must be > 0"))
		}
		if c.V4.ProbeDefaults.MinSwitchInterval < 0 {
			errs = append(errs, errors.New("v4.probe_defaults.min_switch_interval must be >= 0"))
		}
		if c.V4.Telegram.Enabled && !strings.HasPrefix(strings.TrimSpace(c.V4.Telegram.Command), "/") {
			errs = append(errs, errors.New("v4.telegram.command must start with '/'"))
		}
		for _, override := range c.V4.Overrides {
			if strings.TrimSpace(override.Host) == "" {
				errs = append(errs, errors.New("v4.overrides[].host is required"))
				continue
			}
			if strings.TrimSpace(override.BackendService) != "" {
				if _, ok := seenServices[strings.TrimSpace(override.BackendService)]; !ok {
					errs = append(errs, fmt.Errorf("v4 override backend_service %q is not present in routing.services", override.BackendService))
				}
			}
			if override.IPEnrichmentMode != "" && !slices.Contains([]string{"disabled", "cache_only", "full"}, override.IPEnrichmentMode) {
				errs = append(errs, fmt.Errorf("v4 override ip_enrichment_mode for host %q must be disabled, cache_only, or full", override.Host))
			}
			if override.Probe.Mode != "" && !slices.Contains([]string{"local_js", "html_discovery"}, override.Probe.Mode) {
				errs = append(errs, fmt.Errorf("v4 override probe.mode for host %q must be local_js or html_discovery", override.Host))
			}
		}
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
