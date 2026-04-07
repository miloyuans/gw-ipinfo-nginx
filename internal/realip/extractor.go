package realip

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"gw-ipinfo-nginx/internal/config"
)

type Extractor struct {
	trustedCIDRs         []netip.Prefix
	headerPriority       []string
	trustAllSources      bool
	untrustedProxyAction string
}

func NewExtractor(cfg config.RealIPConfig) (*Extractor, error) {
	prefixes := make([]netip.Prefix, 0, len(cfg.TrustedProxyCIDRs))
	for _, cidr := range cfg.TrustedProxyCIDRs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("parse trusted cidr %q: %w", cidr, err)
		}
		prefixes = append(prefixes, prefix)
	}
	headerPriority := append([]string(nil), cfg.HeaderPriority...)
	if len(headerPriority) == 0 {
		headerPriority = []string{
			"CF-Connecting-IP",
			"True-Client-IP",
			"X-Real-IP",
			"X-Forwarded-For",
		}
	}

	return &Extractor{
		trustedCIDRs:         prefixes,
		headerPriority:       headerPriority,
		trustAllSources:      cfg.TrustAllSources || len(prefixes) == 0,
		untrustedProxyAction: cfg.UntrustedProxyAction,
	}, nil
}

func (e *Extractor) Extract(r *http.Request) (string, error) {
	remoteAddr, err := remoteIP(r.RemoteAddr)
	if err != nil {
		return "", err
	}

	if e.trustAllSources || e.isTrusted(remoteAddr) {
		for _, header := range e.headerPriority {
			value := r.Header.Get(header)
			if value == "" {
				continue
			}
			ip, err := parseHeaderValue(header, value)
			if err == nil {
				return ip.String(), nil
			}
		}
		if isPublicIP(remoteAddr) {
			return remoteAddr.String(), nil
		}
		return "", errors.New("no valid public client ip found in request headers or remote address")
	}

	if e.untrustedProxyAction == "use_remote_addr" && isPublicIP(remoteAddr) {
		return remoteAddr.String(), nil
	}

	return "", errors.New("no valid public client ip found in request headers or remote address")
}

func parseHeaderValue(header, value string) (netip.Addr, error) {
	switch header {
	case "CF-Connecting-IP", "True-Client-IP", "X-Real-IP":
		addr, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil || !isPublicIP(addr) {
			return netip.Addr{}, fmt.Errorf("header %s did not contain a public ip", header)
		}
		return addr, nil
	case "X-Forwarded-For":
		parts := strings.Split(value, ",")
		for _, part := range parts {
			addr, err := netip.ParseAddr(strings.TrimSpace(part))
			if err == nil && isPublicIP(addr) {
				return addr, nil
			}
		}
		return netip.Addr{}, errors.New("x-forwarded-for did not include a valid public ip")
	default:
		return netip.Addr{}, fmt.Errorf("unsupported header %s", header)
	}
}

func (e *Extractor) isTrusted(addr netip.Addr) bool {
	for _, prefix := range e.trustedCIDRs {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func remoteIP(remoteAddr string) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("parse remote address %q: %w", remoteAddr, err)
	}
	return addr, nil
}
