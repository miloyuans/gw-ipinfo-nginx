package cache

import (
	"hash/fnv"
	"sync"
	"time"

	"gw-ipinfo-nginx/internal/ipctx"
)

type Entry struct {
	IPContext         ipctx.Context `bson:"ip_context" json:"ip_context"`
	Failure           string        `bson:"failure" json:"failure"`
	GeoExpiresAt      time.Time     `bson:"geo_expires_at" json:"geo_expires_at"`
	PrivacyExpiresAt  time.Time     `bson:"privacy_expires_at" json:"privacy_expires_at"`
	ResProxyExpiresAt time.Time     `bson:"resproxy_expires_at" json:"resproxy_expires_at"`
	FailureExpiresAt  time.Time     `bson:"failure_expires_at" json:"failure_expires_at"`
	ExpiresAt         time.Time     `bson:"expires_at" json:"expires_at"`
	UpdatedAt         time.Time     `bson:"updated_at" json:"updated_at"`
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

type shard struct {
	mu     sync.RWMutex
	values map[string]Entry
}

type L1 struct {
	enabled    bool
	maxEntries int
	shards     []shard
}

func NewL1(enabled bool, maxEntries int, shardCount int) *L1 {
	if shardCount <= 0 {
		shardCount = 64
	}
	shards := make([]shard, shardCount)
	for idx := range shards {
		shards[idx].values = make(map[string]Entry)
	}
	return &L1{
		enabled:    enabled,
		maxEntries: maxEntries,
		shards:     shards,
	}
}

func (c *L1) Get(ip string, now time.Time, needResidentialProxy bool) (Entry, bool) {
	if !c.enabled {
		return Entry{}, false
	}
	shard := c.shardFor(ip)
	shard.mu.RLock()
	entry, ok := shard.values[ip]
	shard.mu.RUnlock()
	if !ok {
		return Entry{}, false
	}
	if !entry.Fresh(now, needResidentialProxy) {
		shard.mu.Lock()
		delete(shard.values, ip)
		shard.mu.Unlock()
		return Entry{}, false
	}
	return entry, true
}

func (c *L1) Set(ip string, entry Entry) {
	if !c.enabled {
		return
	}
	shard := c.shardFor(ip)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if c.maxEntries > 0 && len(shard.values) >= maxPerShard(c.maxEntries, len(c.shards)) {
		for key := range shard.values {
			delete(shard.values, key)
			break
		}
	}
	shard.values[ip] = entry
}

func (c *L1) shardFor(key string) *shard {
	sum := fnv.New32a()
	_, _ = sum.Write([]byte(key))
	return &c.shards[sum.Sum32()%uint32(len(c.shards))]
}

func maxPerShard(total, shards int) int {
	if shards <= 0 {
		return total
	}
	if total <= shards {
		return 1
	}
	value := total / shards
	if value <= 0 {
		return 1
	}
	return value
}
