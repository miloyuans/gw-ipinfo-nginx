package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"gw-ipinfo-nginx/internal/config"
	"gw-ipinfo-nginx/internal/ipctx"
)

func TestManagerSetsHeaders(t *testing.T) {
	var gotClientIP string
	var gotCountry string
	var gotService string

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotClientIP = r.Header.Get("X-Client-Real-IP")
		gotCountry = r.Header.Get("X-IP-Country-Code")
		gotService = r.Header.Get("X-Gateway-Service")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer backend.Close()

	manager, err := NewManager([]config.ServiceConfig{{
		Name:         "default",
		TargetURL:    backend.URL,
		PreserveHost: true,
	}}, config.PerformanceConfig{}, nil, nil)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://gateway.local/test", nil)
	rec := httptest.NewRecorder()

	ipContext := &ipctx.Context{
		CountryCode: "US",
		Privacy:     ipctx.PrivacyFlags{VPN: true},
	}

	manager.ServeHTTP(rec, req, config.ServiceConfig{Name: "default", TargetURL: backend.URL, PreserveHost: true}, "1.1.1.1", ipContext)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("ServeHTTP() status = %d, want 204", rec.Code)
	}
	if gotClientIP != "1.1.1.1" || gotCountry != "US" || gotService != "default" {
		t.Fatalf("headers = client_ip:%s country:%s service:%s", gotClientIP, gotCountry, gotService)
	}
}
