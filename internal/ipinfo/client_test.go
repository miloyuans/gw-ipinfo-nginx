package ipinfo

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gw-ipinfo-nginx/internal/config"
)

func TestClientLookupNormalizesResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"geo":{
				"country_code":"US",
				"country":"United States",
				"region":"California",
				"city":"San Francisco"
			},
			"anonymous":{
				"is_proxy":true,
				"is_relay":false,
				"is_tor":false,
				"is_vpn":true,
				"is_residential_proxy":true,
				"name":"example-service"
			},
			"is_hosting":true
		}`))
	}))
	defer server.Close()

	client, err := NewClient(config.IPInfoConfig{
		BaseURL:            server.URL,
		LookupPathTemplate: "/lookup/%s",
		Timeout:            time.Second,
		MaxRetries:         1,
		RetryBackoff:       10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	result, err := client.Lookup(context.Background(), "1.1.1.1")
	if err != nil {
		t.Fatalf("Lookup() error = %v", err)
	}
	if result.IP != "1.1.1.1" {
		t.Fatalf("Lookup() IP = %q, want 1.1.1.1", result.IP)
	}
	if result.CountryCode != "US" || result.CountryName != "United States" || result.Region != "California" || result.City != "San Francisco" {
		t.Fatalf("Lookup() = %#v, want normalized geo fields", result)
	}
	if !result.Privacy.VPN || !result.Privacy.Proxy || !result.Privacy.Hosting || !result.Privacy.ResidentialProxy {
		t.Fatalf("Lookup() privacy = %#v, want vpn/proxy/hosting/residential_proxy true", result.Privacy)
	}
	if result.Privacy.Tor || result.Privacy.Relay {
		t.Fatalf("Lookup() privacy = %#v, want tor/relay false", result.Privacy)
	}
	if result.Privacy.Service != "example-service" {
		t.Fatalf("Lookup() service = %q, want example-service", result.Privacy.Service)
	}
	if result.LookupTime.IsZero() {
		t.Fatal("Lookup() LookupTime is zero")
	}
}
