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
		httpClient:         &http.Client{Timeout: cfg.Timeout},
		maxRetries:         cfg.MaxRetries,
		retryBackoff:       cfg.RetryBackoff,
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
	requestURL := c.baseURL.ResolveReference(&url.URL{Path: fmt.Sprintf(c.lookupPathTemplate, ip)})
	query := requestURL.Query()
	if c.token != "" {
		query.Set("token", c.token)
	}
	requestURL.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return ipctx.Context{}, fmt.Errorf("build ipinfo request: %w", err)
	}
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
	Country           string           `json:"country"`
	CountryCode       string           `json:"country_code"`
	CountryName       string           `json:"country_name"`
	Region            string           `json:"region"`
	RegionName        string           `json:"region_name"`
	City              string           `json:"city"`
	Privacy           privacyResponse  `json:"privacy"`
	Anonymous         anonymousResponse `json:"anonymous"`
	ResidentialProxy  bool             `json:"residential_proxy"`
	ResProxy          bool             `json:"res_proxy"`
	ResProxyCamel     bool             `json:"resProxy"`
}

type privacyResponse struct {
	VPN              bool   `json:"vpn"`
	Proxy            bool   `json:"proxy"`
	Tor              bool   `json:"tor"`
	Relay            bool   `json:"relay"`
	Hosting          bool   `json:"hosting"`
	Service          string `json:"service"`
	ResidentialProxy bool   `json:"residential_proxy"`
	ResProxy         bool   `json:"res_proxy"`
}

type anonymousResponse struct {
	ResidentialProxy bool `json:"is_residential_proxy"`
}

func (r response) normalize(ip string) ipctx.Context {
	countryCode := strings.ToUpper(strings.TrimSpace(r.CountryCode))
	if countryCode == "" {
		countryCode = strings.ToUpper(strings.TrimSpace(r.Country))
	}
	region := strings.TrimSpace(r.Region)
	if region == "" {
		region = strings.TrimSpace(r.RegionName)
	}

	return ipctx.Context{
		IP:          ip,
		CountryCode: countryCode,
		CountryName: strings.TrimSpace(r.CountryName),
		Region:      region,
		City:        strings.TrimSpace(r.City),
		Privacy: ipctx.PrivacyFlags{
			VPN:              r.Privacy.VPN,
			Proxy:            r.Privacy.Proxy,
			Tor:              r.Privacy.Tor,
			Relay:            r.Privacy.Relay,
			Hosting:          r.Privacy.Hosting,
			Service:          strings.TrimSpace(r.Privacy.Service),
			ResidentialProxy: r.ResidentialProxy || r.ResProxy || r.ResProxyCamel || r.Privacy.ResidentialProxy || r.Privacy.ResProxy || r.Anonymous.ResidentialProxy,
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
