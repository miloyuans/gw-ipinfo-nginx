package shortcircuit

import (
	"hash/fnv"
	"sync"
	"time"
)

type l1Shard struct {
	mu     sync.RWMutex
	values map[string]Record
}

type L1 struct {
	enabled    bool
	maxEntries int
	shards     []l1Shard
}

func NewL1(enabled bool, maxEntries, shardCount int) *L1 {
	if shardCount <= 0 {
		shardCount = 64
	}
	shards := make([]l1Shard, shardCount)
	for idx := range shards {
		shards[idx].values = make(map[string]Record)
	}
	return &L1{
		enabled:    enabled,
		maxEntries: maxEntries,
		shards:     shards,
	}
}

func (c *L1) Get(key string, now time.Time) (Record, bool) {
	if !c.enabled {
		return Record{}, false
	}
	shard := c.shardFor(key)
	shard.mu.RLock()
	record, ok := shard.values[key]
	shard.mu.RUnlock()
	if !ok {
		return Record{}, false
	}
	if !record.Fresh(now) {
		shard.mu.Lock()
		delete(shard.values, key)
		shard.mu.Unlock()
		return Record{}, false
	}
	return record, true
}

func (c *L1) Set(key string, record Record) {
	if !c.enabled {
		return
	}
	shard := c.shardFor(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if c.maxEntries > 0 && len(shard.values) >= maxPerShard(c.maxEntries, len(c.shards)) {
		for existing := range shard.values {
			delete(shard.values, existing)
			break
		}
	}
	shard.values[key] = record
}

func (c *L1) shardFor(key string) *l1Shard {
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
