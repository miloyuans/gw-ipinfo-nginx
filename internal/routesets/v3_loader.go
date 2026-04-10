package routesets

import (
	"time"

	"gopkg.in/yaml.v3"
)

type v3RouteFile struct {
	Version int       `yaml:"version"`
	Routes  []v3Route `yaml:"routes"`
}

type v3Route struct {
	ID       string           `yaml:"id"`
	Source   passSource       `yaml:"source"`
	Strategy v3StrategyConfig `yaml:"strategy"`
	Pool     []v3PoolEntry    `yaml:"pool"`
}

type v3StrategyConfig struct {
	Mode                  string        `yaml:"mode"`
	SessionTTL            time.Duration `yaml:"session_ttl"`
	SessionIdleTimeout    time.Duration `yaml:"session_idle_timeout"`
	SecurityFilterEnabled bool          `yaml:"security_filter_enabled"`
}

type v3PoolEntry struct {
	ID          string              `yaml:"id"`
	PublicURL   string              `yaml:"public_url"`
	Weight      int                 `yaml:"weight"`
	HealthCheck v3PoolHealthCheck   `yaml:"health_check"`
}

type v3PoolHealthCheck struct {
	Enabled bool   `yaml:"enabled"`
	URL     string `yaml:"url"`
}

func loadV3File(path string) (v3RouteFile, error) {
	content, err := readExpandedFile(path)
	if err != nil {
		return v3RouteFile{}, err
	}
	var file v3RouteFile
	if err := yaml.Unmarshal(content, &file); err != nil {
		return v3RouteFile{}, err
	}
	return file, nil
}
