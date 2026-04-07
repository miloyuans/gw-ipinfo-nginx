package realip

import (
	"net/http"
	"testing"

	"gw-ipinfo-nginx/internal/config"
)

func TestExtractorUsesTrustedHeaderPriority(t *testing.T) {
	extractor, err := NewExtractor(config.RealIPConfig{
		TrustedProxyCIDRs:    []string{"10.0.0.0/8"},
		HeaderPriority:       []string{"CF-Connecting-IP", "X-Forwarded-For"},
		UntrustedProxyAction: "deny",
	})
	if err != nil {
		t.Fatalf("NewExtractor() error = %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	req.RemoteAddr = "10.1.2.3:1234"
	req.Header.Set("CF-Connecting-IP", "1.1.1.1")
	req.Header.Set("X-Forwarded-For", "8.8.8.8")

	ip, err := extractor.Extract(req)
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}
	if ip != "1.1.1.1" {
		t.Fatalf("Extract() = %s, want 1.1.1.1", ip)
	}
}

func TestExtractorRespectsConfiguredHeaderPriority(t *testing.T) {
	extractor, err := NewExtractor(config.RealIPConfig{
		TrustedProxyCIDRs:    []string{"10.0.0.0/8"},
		HeaderPriority:       []string{"X-Forwarded-For", "CF-Connecting-IP"},
		UntrustedProxyAction: "deny",
	})
	if err != nil {
		t.Fatalf("NewExtractor() error = %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	req.RemoteAddr = "10.1.2.3:1234"
	req.Header.Set("CF-Connecting-IP", "1.1.1.1")
	req.Header.Set("X-Forwarded-For", "8.8.8.8")

	ip, err := extractor.Extract(req)
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}
	if ip != "8.8.8.8" {
		t.Fatalf("Extract() = %s, want 8.8.8.8", ip)
	}
}

func TestExtractorUsesFirstPublicXFF(t *testing.T) {
	extractor, err := NewExtractor(config.RealIPConfig{
		TrustedProxyCIDRs:    []string{"10.0.0.0/8"},
		UntrustedProxyAction: "deny",
	})
	if err != nil {
		t.Fatalf("NewExtractor() error = %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	req.RemoteAddr = "10.1.2.3:1234"
	req.Header.Set("X-Forwarded-For", "10.0.0.8, 8.8.4.4, 203.0.113.3")

	ip, err := extractor.Extract(req)
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}
	if ip != "8.8.4.4" {
		t.Fatalf("Extract() = %s, want 8.8.4.4", ip)
	}
}

func TestExtractorRejectsUntrustedProxy(t *testing.T) {
	extractor, err := NewExtractor(config.RealIPConfig{
		TrustedProxyCIDRs:    []string{"10.0.0.0/8"},
		TrustAllSources:      false,
		UntrustedProxyAction: "deny",
	})
	if err != nil {
		t.Fatalf("NewExtractor() error = %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	req.RemoteAddr = "8.8.8.8:1234"
	req.Header.Set("CF-Connecting-IP", "1.1.1.1")

	if _, err := extractor.Extract(req); err == nil {
		t.Fatal("Extract() error = nil, want rejection for untrusted proxy")
	}
}

func TestExtractorTrustsAllSourcesWhenNoCIDRsConfigured(t *testing.T) {
	extractor, err := NewExtractor(config.RealIPConfig{
		HeaderPriority: []string{"CF-Connecting-IP"},
	})
	if err != nil {
		t.Fatalf("NewExtractor() error = %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	req.RemoteAddr = "172.18.0.5:1234"
	req.Header.Set("CF-Connecting-IP", "1.1.1.1")

	ip, err := extractor.Extract(req)
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}
	if ip != "1.1.1.1" {
		t.Fatalf("Extract() = %s, want 1.1.1.1", ip)
	}
}
