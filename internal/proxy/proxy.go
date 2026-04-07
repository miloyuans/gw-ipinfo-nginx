package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"gw-ipinfo-nginx/internal/config"
	"gw-ipinfo-nginx/internal/ipctx"
	"gw-ipinfo-nginx/internal/metrics"
)

type contextKey string

const metadataKey contextKey = "proxy_metadata"

type Metadata struct {
	Service  config.ServiceConfig
	ClientIP string
	IPCtx    *ipctx.Context
}

type Manager struct {
	proxies map[string]*httputil.ReverseProxy
	metrics *metrics.GatewayMetrics
	logger  *slog.Logger
	transport *http.Transport
}

func NewManager(services []config.ServiceConfig, perf config.PerformanceConfig, metricsSet *metrics.GatewayMetrics, logger *slog.Logger) (*Manager, error) {
	proxies := make(map[string]*httputil.ReverseProxy, len(services))
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   3 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          perf.ProxyMaxIdleConns,
		MaxIdleConnsPerHost:   perf.ProxyMaxIdleConnsPerHost,
		IdleConnTimeout:       perf.ProxyIdleConnTimeout,
		ResponseHeaderTimeout: perf.ProxyResponseHeaderTimeout,
		ExpectContinueTimeout: perf.ProxyExpectContinueTimeout,
		ForceAttemptHTTP2:     true,
	}
	for _, service := range services {
		target, err := url.Parse(service.TargetURL)
		if err != nil {
			return nil, fmt.Errorf("parse target for service %s: %w", service.Name, err)
		}
		svc := service
		proxies[service.Name] = &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.SetURL(target)
				pr.SetXForwarded()
				meta, _ := pr.In.Context().Value(metadataKey).(Metadata)
				if svc.PreserveHost {
					pr.Out.Host = pr.In.Host
				}
				pr.Out.Header.Set("X-Client-Real-IP", meta.ClientIP)
				pr.Out.Header.Set("X-Gateway-Service", svc.Name)
				if meta.IPCtx != nil {
					pr.Out.Header.Set("X-IP-Country-Code", meta.IPCtx.CountryCode)
					pr.Out.Header.Set("X-IP-City", meta.IPCtx.City)
					pr.Out.Header.Set("X-IP-VPN", boolString(meta.IPCtx.Privacy.VPN))
					pr.Out.Header.Set("X-IP-Proxy", boolString(meta.IPCtx.Privacy.Proxy))
					pr.Out.Header.Set("X-IP-Tor", boolString(meta.IPCtx.Privacy.Tor))
					pr.Out.Header.Set("X-IP-Relay", boolString(meta.IPCtx.Privacy.Relay))
					pr.Out.Header.Set("X-IP-Hosting", boolString(meta.IPCtx.Privacy.Hosting))
					pr.Out.Header.Set("X-IP-ResProxy", boolString(meta.IPCtx.Privacy.ResidentialProxy))
				}
			},
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				if metricsSet != nil {
					metricsSet.ProxyErrors.Inc(metrics.Labels{"service": svc.Name})
				}
				if logger != nil {
					logger.Error("proxy_upstream_error",
						"event", "proxy_upstream_error",
						"service_name", svc.Name,
						"upstream_url", svc.TargetURL,
						"path", r.URL.Path,
						"error", err,
					)
				}
				http.Error(w, "bad gateway", http.StatusBadGateway)
			},
			Transport: transport,
		}
	}
	return &Manager{proxies: proxies, metrics: metricsSet, logger: logger, transport: transport}, nil
}

func (m *Manager) ServeHTTP(w http.ResponseWriter, r *http.Request, service config.ServiceConfig, clientIP string, context *ipctx.Context) {
	proxy := m.proxies[service.Name]
	if proxy == nil {
		http.Error(w, "upstream not configured", http.StatusBadGateway)
		return
	}
	meta := Metadata{
		Service:  service,
		ClientIP: clientIP,
		IPCtx:    context,
	}
	ctx := contextWithMetadata(r.Context(), meta)
	proxy.ServeHTTP(w, r.WithContext(ctx))
}

func contextWithMetadata(ctx context.Context, meta Metadata) context.Context {
	return context.WithValue(ctx, metadataKey, meta)
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
