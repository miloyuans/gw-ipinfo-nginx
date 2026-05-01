package snapshot

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRouteFileParsesDirectRedirectEnabled(t *testing.T) {
	dir := t.TempDir()
	baseConfigPath := filepath.Join(dir, "config.yaml")
	routePath := filepath.Join(dir, "passroute_v4.yaml")
	content := `
routes:
  - host: "promo.example.com"
    enabled: true
    probe:
      enabled: true
      direct_redirect_enabled: true
      redirect_urls:
        - "https://fallback.example.net/"
`
	if err := os.WriteFile(routePath, []byte(content), 0o600); err != nil {
		t.Fatalf("write route file: %v", err)
	}

	entries, err := loadRouteFile(baseConfigPath, "passroute_v4.yaml")
	if err != nil {
		t.Fatalf("loadRouteFile() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("loadRouteFile() len = %d, want 1", len(entries))
	}
	if !entries[0].Probe.DirectRedirectEnabled {
		t.Fatal("DirectRedirectEnabled = false, want true")
	}
}

func TestLoadRouteFileRejectsDirectRedirectWithoutTargets(t *testing.T) {
	dir := t.TempDir()
	baseConfigPath := filepath.Join(dir, "config.yaml")
	routePath := filepath.Join(dir, "passroute_v4.yaml")
	content := `
routes:
  - host: "promo.example.com"
    enabled: true
    probe:
      enabled: true
      direct_redirect_enabled: true
`
	if err := os.WriteFile(routePath, []byte(content), 0o600); err != nil {
		t.Fatalf("write route file: %v", err)
	}

	if _, err := loadRouteFile(baseConfigPath, "passroute_v4.yaml"); err == nil {
		t.Fatal("loadRouteFile() error = nil, want direct redirect validation failure")
	}
}
