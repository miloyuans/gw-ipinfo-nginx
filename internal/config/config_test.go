package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadAllowsStageOneModeWithoutMongo(t *testing.T) {
	content := `
server:
  listen_address: ":8080"
real_ip:
  trusted_proxy_cidrs: ["10.0.0.0/8"]
routing:
  default_service: default
  services:
    - name: default
      target_url: "http://127.0.0.1:8081"
security:
  ua:
    enabled: true
  accept_language:
    require_header: true
  geo:
    default_action: deny
    whitelist:
      US: {}
  privacy:
    deny_by_default: true
ipinfo:
  enabled: false
alerts:
  telegram:
    enabled: false
  delivery:
    worker_enabled: false
`
	path := writeConfig(t, content)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.NeedsMongo() {
		t.Fatalf("NeedsMongo() = true, want false for stage one mode")
	}
}

func TestLoadRejectsInvalidHeaderPriority(t *testing.T) {
	content := `
server:
  listen_address: ":8080"
real_ip:
  trusted_proxy_cidrs: ["10.0.0.0/8"]
  header_priority: ["X-Bad-Header"]
routing:
  default_service: default
  services:
    - name: default
      target_url: "http://127.0.0.1:8081"
security:
  ua:
    enabled: true
  accept_language:
    require_header: true
  geo:
    default_action: deny
    whitelist:
      US: {}
  privacy:
    deny_by_default: true
ipinfo:
  enabled: false
alerts:
  telegram:
    enabled: false
  delivery:
    worker_enabled: false
`
	path := writeConfig(t, content)

	if _, err := Load(path); err == nil {
		t.Fatal("Load() error = nil, want header priority validation failure")
	}
}

func TestLoadAllowsLocalFallbackWhenIPInfoEnabledWithoutMongo(t *testing.T) {
	content := `
server:
  listen_address: ":8080"
real_ip:
  trusted_proxy_cidrs: ["10.0.0.0/8"]
routing:
  default_service: default
  services:
    - name: default
      target_url: "http://127.0.0.1:8081"
security:
  ua:
    enabled: true
  accept_language:
    require_header: true
  geo:
    default_action: deny
    whitelist:
      US: {}
  privacy:
    deny_by_default: true
ipinfo:
  enabled: true
  token: token
alerts:
  telegram:
    enabled: false
  delivery:
    worker_enabled: false
`
	path := writeConfig(t, content)

	if _, err := Load(path); err != nil {
		t.Fatalf("Load() error = %v, want local fallback mode to be allowed", err)
	}
}

func TestLoadDefaultsToTrustAllSourcesWhenNoTrustedCIDRsConfigured(t *testing.T) {
	content := `
server:
  listen_address: ":8080"
routing:
  default_service: default
  services:
    - name: default
      target_url: "http://127.0.0.1:8081"
security:
  ua:
    enabled: true
  accept_language:
    require_header: false
  geo:
    default_action: deny
    whitelist:
      US: {}
  privacy:
    deny_by_default: true
ipinfo:
  enabled: false
alerts:
  telegram:
    enabled: false
  delivery:
    worker_enabled: false
`
	path := writeConfig(t, content)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.RealIP.TrustAllSources {
		t.Fatal("RealIP.TrustAllSources = false, want true by default when trusted_proxy_cidrs is empty")
	}
}

func TestLoadMapsMongoMaxOpenConnsToMaxPoolSize(t *testing.T) {
	content := `
server:
  listen_address: ":8080"
routing:
  default_service: default
  services:
    - name: default
      target_url: "http://127.0.0.1:8081"
security:
  ua:
    enabled: true
  accept_language:
    require_header: false
  geo:
    default_action: deny
    whitelist:
      US: {}
  privacy:
    deny_by_default: true
mongo:
  uri: "mongodb://127.0.0.1:27017"
  database: "gw_ipinfo_nginx"
  maxOpenConns: 200
ipinfo:
  enabled: false
alerts:
  telegram:
    enabled: false
  delivery:
    worker_enabled: false
`
	path := writeConfig(t, content)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Mongo.MaxPoolSize != 200 {
		t.Fatalf("Mongo.MaxPoolSize = %d, want 200", cfg.Mongo.MaxPoolSize)
	}
}

func TestLoadMapsMongoCompatibilityPoolAliases(t *testing.T) {
	content := `
server:
  listen_address: ":8080"
routing:
  default_service: default
  services:
    - name: default
      target_url: "http://127.0.0.1:8081"
security:
  ua:
    enabled: true
  accept_language:
    require_header: false
  geo:
    default_action: deny
    whitelist:
      US: {}
  privacy:
    deny_by_default: true
mongo:
  uri: "mongodb://127.0.0.1:27017"
  database: "gw_ipinfo_nginx"
  maxOpenConns: 200
  maxIdleConns: 50
  connMaxLifetime: 5m
ipinfo:
  enabled: false
alerts:
  telegram:
    enabled: false
  delivery:
    worker_enabled: false
`
	path := writeConfig(t, content)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Mongo.MinPoolSize != 50 {
		t.Fatalf("Mongo.MinPoolSize = %d, want 50", cfg.Mongo.MinPoolSize)
	}
	if cfg.Mongo.MaxConnIdleTime != 5*time.Minute {
		t.Fatalf("Mongo.MaxConnIdleTime = %v, want 5m", cfg.Mongo.MaxConnIdleTime)
	}
}

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}
