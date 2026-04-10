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

type LookupDetails struct {
	IP          string             `json:"ip"`
	Hostname    string             `json:"hostname,omitempty"`
	Geo         *LookupGeo         `json:"geo,omitempty"`
	AS          *LookupAS          `json:"as,omitempty"`
	Mobile      *LookupMobile      `json:"mobile,omitempty"`
	Anonymous   *LookupAnonymous   `json:"anonymous,omitempty"`
	IsAnonymous bool               `json:"is_anonymous"`
	IsAnycast   bool               `json:"is_anycast"`
	IsHosting   bool               `json:"is_hosting"`
	IsMobile    bool               `json:"is_mobile"`
	IsSatellite bool               `json:"is_satellite"`
	Privacy     ipctx.PrivacyFlags `json:"privacy"`
	LookupTime  time.Time          `json:"lookup_time"`
}

type LookupGeo struct {
	City          string  `json:"city,omitempty"`
	Region        string  `json:"region,omitempty"`
	RegionCode    string  `json:"region_code,omitempty"`
	Country       string  `json:"country,omitempty"`
	CountryCode   string  `json:"country_code,omitempty"`
	Continent     string  `json:"continent,omitempty"`
	ContinentCode string  `json:"continent_code,omitempty"`
	Latitude      float64 `json:"latitude,omitempty"`
	Longitude     float64 `json:"longitude,omitempty"`
	Timezone      string  `json:"timezone,omitempty"`
	PostalCode    string  `json:"postal_code,omitempty"`
	GeonameID     string  `json:"geoname_id,omitempty"`
	Radius        int     `json:"radius,omitempty"`
	LastChanged   string  `json:"last_changed,omitempty"`
}

type LookupAS struct {
	ASN         string `json:"asn,omitempty"`
	Name        string `json:"name,omitempty"`
	Domain      string `json:"domain,omitempty"`
	Type        string `json:"type,omitempty"`
	LastChanged string `json:"last_changed,omitempty"`
}

type LookupMobile struct {
	Name string `json:"name,omitempty"`
	MCC  string `json:"mcc,omitempty"`
	MNC  string `json:"mnc,omitempty"`
}

type LookupAnonymous struct {
	Name            string `json:"name,omitempty"`
	LastSeen        string `json:"last_seen,omitempty"`
	PercentDaysSeen int    `json:"percent_days_seen,omitempty"`
	IsProxy         bool   `json:"is_proxy"`
	IsRelay         bool   `json:"is_relay"`
	IsTor           bool   `json:"is_tor"`
	IsVPN           bool   `json:"is_vpn"`
	IsResProxy      bool   `json:"is_res_proxy"`
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

func (c *Client) LookupDetails(ctx context.Context, ip string) (LookupDetails, error) {
	var lastErr error

	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return LookupDetails{}, ctx.Err()
			case <-time.After(time.Duration(attempt) * c.retryBackoff):
			}
		}

		value, err := c.doLookupDetails(ctx, ip)
		if err == nil {
			return value, nil
		}

		lastErr = err
		if !isRetryable(err) {
			break
		}
	}

	if lastErr == nil {
		lastErr = errors.New("ipinfo details lookup failed")
	}

	return LookupDetails{}, lastErr
}

func (c *Client) doLookup(ctx context.Context, ip string) (ipctx.Context, error) {
	raw, err := c.lookupResponse(ctx, ip)
	if err != nil {
		return ipctx.Context{}, err
	}
	return raw.normalize(ip), nil
}

func (c *Client) doLookupDetails(ctx context.Context, ip string) (LookupDetails, error) {
	raw, err := c.lookupResponse(ctx, ip)
	if err != nil {
		return LookupDetails{}, err
	}
	return raw.details(ip), nil
}

func (c *Client) lookupResponse(ctx context.Context, ip string) (response, error) {
	requestURL := c.baseURL.ResolveReference(&url.URL{
		Path: fmt.Sprintf(c.lookupPathTemplate, ip),
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return response{}, fmt.Errorf("build ipinfo request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "gw-ipinfo-nginx/1.0")

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return response{}, fmt.Errorf("send ipinfo request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return response{}, fmt.Errorf("read ipinfo response: %w", err)
	}

	if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
		return response{}, retryableError{err: fmt.Errorf("ipinfo http %d", resp.StatusCode)}
	}

	if resp.StatusCode >= 400 {
		return response{}, fmt.Errorf("ipinfo http %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var raw response
	if err := json.Unmarshal(body, &raw); err != nil {
		return response{}, fmt.Errorf("decode ipinfo response: %w", err)
	}

	return raw, nil
}

type response struct {
	IP               string            `json:"ip"`
	Hostname         string            `json:"hostname"`
	Geo              geoResponse       `json:"geo"`
	As               *asResponse       `json:"as"`
	Mobile           *mobileResponse   `json:"mobile"`
	Anonymous        anonymousResponse `json:"anonymous"`
	IsAnonymous      bool              `json:"is_anonymous"`
	IsAnycast        bool              `json:"is_anycast"`
	IsHosting        bool              `json:"is_hosting"`
	IsMobile         bool              `json:"is_mobile"`
	IsSatellite      bool              `json:"is_satellite"`
	ResidentialProxy bool              `json:"residential_proxy"`
	ResProxy         bool              `json:"res_proxy"`
	ResProxyCamel    bool              `json:"resProxy"`
}

type geoResponse struct {
	City          string  `json:"city"`
	Region        string  `json:"region"`
	RegionCode    string  `json:"region_code"`
	Country       string  `json:"country"`
	CountryCode   string  `json:"country_code"`
	Continent     string  `json:"continent"`
	ContinentCode string  `json:"continent_code"`
	Latitude      float64 `json:"latitude"`
	Longitude     float64 `json:"longitude"`
	Timezone      string  `json:"timezone"`
	PostalCode    string  `json:"postal_code"`
	GeonameID     string  `json:"geoname_id"`
	Radius        int     `json:"radius"`
	LastChanged   string  `json:"last_changed"`
}

type asResponse struct {
	ASN         string `json:"asn"`
	Name        string `json:"name"`
	Domain      string `json:"domain"`
	Type        string `json:"type"`
	LastChanged string `json:"last_changed"`
}

type mobileResponse struct {
	Name string `json:"name"`
	MCC  string `json:"mcc"`
	MNC  string `json:"mnc"`
}

type anonymousResponse struct {
	Name            string `json:"name"`
	LastSeen        string `json:"last_seen"`
	PercentDaysSeen int    `json:"percent_days_seen"`
	Proxy           bool   `json:"is_proxy"`
	Relay           bool   `json:"is_relay"`
	Tor             bool   `json:"is_tor"`
	VPN             bool   `json:"is_vpn"`
	IsResProxy      bool   `json:"is_res_proxy"`
	ResidentialProxy bool  `json:"is_residential_proxy"`
	Service         string `json:"service"`
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
			Service:          firstNonEmpty(r.Anonymous.Service, r.Anonymous.Name),
			ResidentialProxy: r.ResidentialProxy || r.ResProxy || r.ResProxyCamel || r.Anonymous.ResidentialProxy || r.Anonymous.IsResProxy,
		},
		LookupTime: time.Now().UTC(),
	}
}

func (r response) details(ip string) LookupDetails {
	lookupTime := time.Now().UTC()
	details := LookupDetails{
		IP:          firstNonEmpty(strings.TrimSpace(r.IP), strings.TrimSpace(ip)),
		Hostname:    strings.TrimSpace(r.Hostname),
		IsAnonymous: r.IsAnonymous,
		IsAnycast:   r.IsAnycast,
		IsHosting:   r.IsHosting,
		IsMobile:    r.IsMobile,
		IsSatellite: r.IsSatellite,
		Privacy: ipctx.PrivacyFlags{
			VPN:              r.Anonymous.VPN,
			Proxy:            r.Anonymous.Proxy,
			Tor:              r.Anonymous.Tor,
			Relay:            r.Anonymous.Relay,
			Hosting:          r.IsHosting,
			Service:          firstNonEmpty(r.Anonymous.Service, r.Anonymous.Name),
			ResidentialProxy: r.ResidentialProxy || r.ResProxy || r.ResProxyCamel || r.Anonymous.ResidentialProxy || r.Anonymous.IsResProxy,
		},
		LookupTime: lookupTime,
	}
	if geo := r.geoDetails(); geo != nil {
		details.Geo = geo
	}
	if as := r.asDetails(); as != nil {
		details.AS = as
	}
	if mobile := r.mobileDetails(); mobile != nil {
		details.Mobile = mobile
	}
	if anonymous := r.anonymousDetails(); anonymous != nil {
		details.Anonymous = anonymous
	}
	return details
}

func (r response) geoDetails() *LookupGeo {
	if strings.TrimSpace(r.Geo.CountryCode) == "" &&
		strings.TrimSpace(r.Geo.Country) == "" &&
		strings.TrimSpace(r.Geo.Region) == "" &&
		strings.TrimSpace(r.Geo.City) == "" &&
		strings.TrimSpace(r.Geo.Timezone) == "" &&
		r.Geo.Latitude == 0 &&
		r.Geo.Longitude == 0 &&
		r.Geo.Radius == 0 {
		return nil
	}
	return &LookupGeo{
		City:          strings.TrimSpace(r.Geo.City),
		Region:        strings.TrimSpace(r.Geo.Region),
		RegionCode:    strings.TrimSpace(r.Geo.RegionCode),
		Country:       strings.TrimSpace(r.Geo.Country),
		CountryCode:   strings.ToUpper(strings.TrimSpace(r.Geo.CountryCode)),
		Continent:     strings.TrimSpace(r.Geo.Continent),
		ContinentCode: strings.TrimSpace(r.Geo.ContinentCode),
		Latitude:      r.Geo.Latitude,
		Longitude:     r.Geo.Longitude,
		Timezone:      strings.TrimSpace(r.Geo.Timezone),
		PostalCode:    strings.TrimSpace(r.Geo.PostalCode),
		GeonameID:     strings.TrimSpace(r.Geo.GeonameID),
		Radius:        r.Geo.Radius,
		LastChanged:   strings.TrimSpace(r.Geo.LastChanged),
	}
}

func (r response) asDetails() *LookupAS {
	if r.As == nil {
		return nil
	}
	if strings.TrimSpace(r.As.ASN) == "" &&
		strings.TrimSpace(r.As.Name) == "" &&
		strings.TrimSpace(r.As.Domain) == "" &&
		strings.TrimSpace(r.As.Type) == "" &&
		strings.TrimSpace(r.As.LastChanged) == "" {
		return nil
	}
	return &LookupAS{
		ASN:         strings.TrimSpace(r.As.ASN),
		Name:        strings.TrimSpace(r.As.Name),
		Domain:      strings.TrimSpace(r.As.Domain),
		Type:        strings.TrimSpace(r.As.Type),
		LastChanged: strings.TrimSpace(r.As.LastChanged),
	}
}

func (r response) mobileDetails() *LookupMobile {
	if r.Mobile == nil {
		return nil
	}
	if strings.TrimSpace(r.Mobile.Name) == "" && strings.TrimSpace(r.Mobile.MCC) == "" && strings.TrimSpace(r.Mobile.MNC) == "" {
		return nil
	}
	return &LookupMobile{
		Name: strings.TrimSpace(r.Mobile.Name),
		MCC:  strings.TrimSpace(r.Mobile.MCC),
		MNC:  strings.TrimSpace(r.Mobile.MNC),
	}
}

func (r response) anonymousDetails() *LookupAnonymous {
	if strings.TrimSpace(r.Anonymous.Name) == "" &&
		strings.TrimSpace(r.Anonymous.LastSeen) == "" &&
		r.Anonymous.PercentDaysSeen == 0 &&
		!r.Anonymous.Proxy &&
		!r.Anonymous.Relay &&
		!r.Anonymous.Tor &&
		!r.Anonymous.VPN &&
		!r.Anonymous.IsResProxy &&
		!r.Anonymous.ResidentialProxy {
		return nil
	}
	return &LookupAnonymous{
		Name:            firstNonEmpty(r.Anonymous.Name, r.Anonymous.Service),
		LastSeen:        strings.TrimSpace(r.Anonymous.LastSeen),
		PercentDaysSeen: r.Anonymous.PercentDaysSeen,
		IsProxy:         r.Anonymous.Proxy,
		IsRelay:         r.Anonymous.Relay,
		IsTor:           r.Anonymous.Tor,
		IsVPN:           r.Anonymous.VPN,
		IsResProxy:      r.Anonymous.IsResProxy || r.Anonymous.ResidentialProxy,
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func (d LookupDetails) ToContext() ipctx.Context {
	return ipctx.Context{
		IP:          strings.TrimSpace(d.IP),
		CountryCode: strings.ToUpper(strings.TrimSpace(valueOrEmpty(d.Geo, func(v *LookupGeo) string { return v.CountryCode }))),
		CountryName: strings.TrimSpace(valueOrEmpty(d.Geo, func(v *LookupGeo) string { return v.Country })),
		Region:      strings.TrimSpace(valueOrEmpty(d.Geo, func(v *LookupGeo) string { return v.Region })),
		City:        strings.TrimSpace(valueOrEmpty(d.Geo, func(v *LookupGeo) string { return v.City })),
		Privacy:     d.Privacy,
		LookupTime:  d.LookupTime,
	}
}

func DetailsFromContext(ctx ipctx.Context) LookupDetails {
	return LookupDetails{
		IP: ctx.IP,
		Geo: &LookupGeo{
			City:        ctx.City,
			Region:      ctx.Region,
			Country:     ctx.CountryName,
			CountryCode: ctx.CountryCode,
		},
		Privacy:    ctx.Privacy,
		LookupTime: ctx.LookupTime,
	}
}

func valueOrEmpty[T any](value *T, fn func(*T) string) string {
	if value == nil {
		return ""
	}
	return fn(value)
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
