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
			"country":"us",
			"country_name":"United States",
			"region":"California",
			"city":"San Francisco",
			"privacy":{
				"vpn":true,
				"proxy":false,
				"tor":false,
				"relay":false,
				"hosting":true,
				"service":"example-service",
				"residential_proxy":true
			}
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
	if result.CountryCode != "US" || result.City != "San Francisco" {
		t.Fatalf("Lookup() = %#v, want normalized country/city", result)
	}
	if !result.Privacy.VPN || !result.Privacy.Hosting || !result.Privacy.ResidentialProxy {
		t.Fatalf("Lookup() privacy = %#v, want vpn/hosting/residential_proxy true", result.Privacy)
	}
}
