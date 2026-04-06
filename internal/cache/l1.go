package cache

import (
	"sync"
	"time"

	"gw-ipinfo-nginx/internal/ipctx"
)

type Entry struct {
	IPContext         ipctx.Context `bson:"ip_context"`
	Failure           string        `bson:"failure"`
	GeoExpiresAt      time.Time     `bson:"geo_expires_at"`
	PrivacyExpiresAt  time.Time     `bson:"privacy_expires_at"`
	ResProxyExpiresAt time.Time     `bson:"resproxy_expires_at"`
	FailureExpiresAt  time.Time     `bson:"failure_expires_at"`
	ExpiresAt         time.Time     `bson:"expires_at"`
	UpdatedAt         time.Time     `bson:"updated_at"`
}

func (e Entry) Fresh(now time.Time, needResidentialProxy bool) bool {
	if e.Failure != "" {
		return now.Before(e.FailureExpiresAt)
	}
	if now.After(e.GeoExpiresAt) || now.After(e.PrivacyExpiresAt) {
		return false
	}
	if needResidentialProxy && now.After(e.ResProxyExpiresAt) {
		return false
	}
	return true
}

type L1 struct {
	enabled    bool
	maxEntries int
	mu         sync.RWMutex
	values     map[string]Entry
}

func NewL1(enabled bool, maxEntries int) *L1 {
	return &L1{
		enabled:    enabled,
		maxEntries: maxEntries,
		values:     make(map[string]Entry),
	}
}

func (c *L1) Get(ip string, now time.Time, needResidentialProxy bool) (Entry, bool) {
	if !c.enabled {
		return Entry{}, false
	}
	c.mu.RLock()
	entry, ok := c.values[ip]
	c.mu.RUnlock()
	if !ok {
		return Entry{}, false
	}
	if !entry.Fresh(now, needResidentialProxy) {
		c.mu.Lock()
		delete(c.values, ip)
		c.mu.Unlock()
		return Entry{}, false
	}
	return entry, true
}

func (c *L1) Set(ip string, entry Entry) {
	if !c.enabled {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.values) >= c.maxEntries {
		for key := range c.values {
			delete(c.values, key)
			break
		}
	}
	c.values[ip] = entry
}
