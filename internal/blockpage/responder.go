package blockpage

import (
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"gw-ipinfo-nginx/internal/config"
)

const (
	headerDenyProxy    = "X-Gateway-Deny-Proxy"
	headerRequestID    = "X-Gateway-Request-ID"
	headerDenyStatus   = "X-Gateway-Deny-Status"
	headerReasonCode   = "X-Gateway-Reason-Code"
	headerServiceName  = "X-Gateway-Service"
	headerClientIP     = "X-Gateway-Client-IP"
	headerOriginalHost = "X-Gateway-Original-Host"
	headerOriginalPath = "X-Gateway-Original-Path"
	headerOriginalURL  = "X-Gateway-Original-URL"
)

type Responder struct {
	cfg    config.DenyPageConfig
	logger *slog.Logger
	proxy  *httputil.ReverseProxy
}

func NewResponder(cfg config.DenyPageConfig, perf config.PerformanceConfig, logger *slog.Logger) (*Responder, error) {
	responder := &Responder{
		cfg:    cfg,
		logger: logger,
	}

	targetURL := strings.TrimSpace(cfg.TargetURL)
	if targetURL == "" {
		return responder, nil
	}

	target, err := url.ParseRequestURI(targetURL)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          maxInt(perf.ProxyMaxIdleConns/8, 64),
		MaxIdleConnsPerHost:   maxInt(perf.ProxyMaxIdleConnsPerHost/8, 32),
		IdleConnTimeout:       durationOrDefault(perf.ProxyIdleConnTimeout, 90*time.Second),
		ResponseHeaderTimeout: durationOrDefault(perf.ProxyResponseHeaderTimeout, 5*time.Second),
		ExpectContinueTimeout: durationOrDefault(perf.ProxyExpectContinueTimeout, time.Second),
	}

	responder.proxy = &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = target.Scheme
			pr.Out.URL.Host = target.Host
			pr.Out.URL.Path = target.Path
			pr.Out.URL.RawPath = target.RawPath
			pr.Out.URL.RawQuery = target.RawQuery
			pr.Out.Host = target.Host

			pr.SetXForwarded()

			if cfg.PreserveHost {
				pr.Out.Host = pr.In.Host
			}

			pr.Out.Header.Set(headerDenyProxy, "1")
			copyIfPresent(pr.Out.Header, headerRequestID, pr.In.Header.Get(headerRequestID))
			copyIfPresent(pr.Out.Header, headerDenyStatus, pr.In.Header.Get(headerDenyStatus))
			copyIfPresent(pr.Out.Header, headerReasonCode, pr.In.Header.Get(headerReasonCode))
			copyIfPresent(pr.Out.Header, headerServiceName, pr.In.Header.Get(headerServiceName))
			copyIfPresent(pr.Out.Header, headerClientIP, pr.In.Header.Get(headerClientIP))
			copyIfPresent(pr.Out.Header, headerOriginalHost, pr.In.Header.Get(headerOriginalHost))
			copyIfPresent(pr.Out.Header, headerOriginalPath, pr.In.Header.Get(headerOriginalPath))
			copyIfPresent(pr.Out.Header, headerOriginalURL, pr.In.Header.Get(headerOriginalURL))
		},
		ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
			if logger != nil {
				logger.Warn(
					"deny_page_proxy_fallback",
					"event", "deny_page_proxy_fallback",
					"target_url", cfg.TargetURL,
					"error", err,
				)
			}

			Write(w, denyStatusFromRequest(req), cfg, req.Header.Get(headerRequestID))
		},
	}

	return responder, nil
}

func (r *Responder) ServeHTTP(
	w http.ResponseWriter,
	req *http.Request,
	denyStatus int,
	requestID string,
	reasonCode string,
	serviceName string,
	clientIP string,
) {
	if r == nil || r.proxy == nil || req.Header.Get(headerDenyProxy) == "1" {
		Write(w, denyStatus, r.cfg, requestID)
		return
	}

	cloned := req.Clone(req.Context())
	cloned.Header = req.Header.Clone()
	cloned.Header.Set(headerDenyProxy, "1")
	cloned.Header.Set(headerRequestID, requestID)
	cloned.Header.Set(headerDenyStatus, strconv.Itoa(denyStatus))
	cloned.Header.Set(headerReasonCode, reasonCode)
	cloned.Header.Set(headerServiceName, serviceName)
	cloned.Header.Set(headerClientIP, clientIP)
	cloned.Header.Set(headerOriginalHost, req.Host)
	cloned.Header.Set(headerOriginalPath, req.URL.Path)
	cloned.Header.Set(headerOriginalURL, req.URL.RequestURI())

	r.proxy.ServeHTTP(w, cloned)
}

func denyStatusFromRequest(req *http.Request) int {
	if req == nil {
		return http.StatusForbidden
	}

	raw := strings.TrimSpace(req.Header.Get(headerDenyStatus))
	if raw == "" {
		return http.StatusForbidden
	}

	code, err := strconv.Atoi(raw)
	if err != nil || code < 400 || code > 599 {
		return http.StatusForbidden
	}

	return code
}

func copyIfPresent(h http.Header, key, value string) {
	if strings.TrimSpace(value) != "" {
		h.Set(key, value)
	}
}

func durationOrDefault(v time.Duration, fallback time.Duration) time.Duration {
	if v > 0 {
		return v
	}
	return fallback
}

func maxInt(v, fallback int) int {
	if v > 0 {
		return v
	}
	return fallback
}