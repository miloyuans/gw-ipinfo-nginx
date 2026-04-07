package ipinfo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"gw-ipinfo-nginx/internal/config"
	"gw-ipinfo-nginx/internal/ipctx"
)

type Client struct {
	baseURL            *url.URL
	lookupPathTemplate string
	token              string
	httpClient         *http.Client
	maxRetries         int
	retryBackoff       time.Duration
}

func NewClient(cfg config.IPInfoConfig) (*Client, error) {
	baseURL, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse ipinfo base url: %w", err)
	}

	return &Client{
		baseURL:            baseURL,
		lookupPathTemplate: cfg.LookupPathTemplate,
		token:              cfg.Token,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
		maxRetries:   cfg.MaxRetries,
		retryBackoff: cfg.RetryBackoff,
	}, nil
}

func (c *Client) Lookup(ctx context.Context, ip string) (ipctx.Context, error) {
	var lastErr error

	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ipctx.Context{}, ctx.Err()
			case <-time.After(time.Duration(attempt) * c.retryBackoff):
			}
		}

		value, err := c.doLookup(ctx, ip)
		if err == nil {
			return value, nil
		}

		lastErr = err
		if !isRetryable(err) {
			break
		}
	}

	if lastErr == nil {
		lastErr = errors.New("ipinfo lookup failed")
	}

	return ipctx.Context{}, lastErr
}

func (c *Client) doLookup(ctx context.Context, ip string) (ipctx.Context, error) {
	requestURL := c.baseURL.ResolveReference(&url.URL{
		Path: fmt.Sprintf(c.lookupPathTemplate, ip),
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return ipctx.Context{}, fmt.Errorf("build ipinfo request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "gw-ipinfo-nginx/1.0")

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return ipctx.Context{}, fmt.Errorf("send ipinfo request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return ipctx.Context{}, fmt.Errorf("read ipinfo response: %w", err)
	}

	if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
		return ipctx.Context{}, retryableError{err: fmt.Errorf("ipinfo http %d", resp.StatusCode)}
	}

	if resp.StatusCode >= 400 {
		return ipctx.Context{}, fmt.Errorf("ipinfo http %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var raw response
	if err := json.Unmarshal(body, &raw); err != nil {
		return ipctx.Context{}, fmt.Errorf("decode ipinfo response: %w", err)
	}

	return raw.normalize(ip), nil
}

type response struct {
	Geo              geoResponse       `json:"geo"`
	Anonymous        anonymousResponse `json:"anonymous"`
	IsHosting        bool              `json:"is_hosting"`
	ResidentialProxy bool              `json:"residential_proxy"`
	ResProxy         bool              `json:"res_proxy"`
	ResProxyCamel    bool              `json:"resProxy"`
}

type geoResponse struct {
	CountryCode string `json:"country_code"`
	Country     string `json:"country"`
	Region      string `json:"region"`
	City        string `json:"city"`
}

type anonymousResponse struct {
	Proxy            bool   `json:"is_proxy"`
	Relay            bool   `json:"is_relay"`
	Tor              bool   `json:"is_tor"`
	VPN              bool   `json:"is_vpn"`
	ResidentialProxy bool   `json:"is_residential_proxy"`
	Service          string `json:"name"`
}

func (r response) normalize(ip string) ipctx.Context {
	return ipctx.Context{
		IP:          ip,
		CountryCode: strings.ToUpper(strings.TrimSpace(r.Geo.CountryCode)),
		CountryName: strings.TrimSpace(r.Geo.Country),
		Region:      strings.TrimSpace(r.Geo.Region),
		City:        strings.TrimSpace(r.Geo.City),
		Privacy: ipctx.PrivacyFlags{
			VPN:              r.Anonymous.VPN,
			Proxy:            r.Anonymous.Proxy,
			Tor:              r.Anonymous.Tor,
			Relay:            r.Anonymous.Relay,
			Hosting:          r.IsHosting,
			Service:          strings.TrimSpace(r.Anonymous.Service),
			ResidentialProxy: r.ResidentialProxy || r.ResProxy || r.ResProxyCamel || r.Anonymous.ResidentialProxy,
		},
		LookupTime: time.Now().UTC(),
	}
}

type retryableError struct {
	err error
}

func (e retryableError) Error() string {
	return e.err.Error()
}

func isRetryable(err error) bool {
	var value retryableError
	return errors.As(err, &value)
}
