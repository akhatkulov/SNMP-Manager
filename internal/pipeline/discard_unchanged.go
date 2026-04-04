package pipeline

import (
	"fmt"
	"sync"
	"time"
)

// metricKey uniquely identifies a single metric stream: one device × one OID.
type metricKey struct {
	IP  string
	OID string
}

type cachedValue struct {
	value    any
	lastSeen time.Time
	lastSent time.Time
}

// DiscardUnchangedFilter suppresses repeated identical metric values.
type DiscardUnchangedFilter struct {
	mu           sync.RWMutex
	cache        map[metricKey]*cachedValue
	heartbeatTTL time.Duration
}

func NewDiscardUnchangedFilter(heartbeat time.Duration) *DiscardUnchangedFilter {
	if heartbeat <= 0 {
		heartbeat = 5 * time.Minute
	}
	return &DiscardUnchangedFilter{
		cache:        make(map[metricKey]*cachedValue),
		heartbeatTTL: heartbeat,
	}
}

// ShouldForward returns (true, reason) or (false, "unchanged").
func (f *DiscardUnchangedFilter) ShouldForward(event *SNMPEvent) (bool, string) {
	key := metricKey{IP: event.DeviceIP, OID: event.OID}
	now := time.Now()

	f.mu.Lock()
	defer f.mu.Unlock()

	cached, exists := f.cache[key]
	if !exists {
		f.cache[key] = &cachedValue{
			value:    event.Value,
			lastSeen: now,
			lastSent: now,
		}
		return true, "new"
	}

	cached.lastSeen = now

	if !valuesEqual(cached.value, event.Value) {
		cached.value = event.Value
		cached.lastSent = now
		return true, "changed"
	}

	if now.Sub(cached.lastSent) >= f.heartbeatTTL {
		cached.lastSent = now
		return true, "heartbeat"
	}

	return false, "unchanged"
}

func (f *DiscardUnchangedFilter) Cleanup(maxAge time.Duration) int {
	f.mu.Lock()
	defer f.mu.Unlock()

	now := time.Now()
	removed := 0
	for k, v := range f.cache {
		if now.Sub(v.lastSeen) > maxAge {
			delete(f.cache, k)
			removed++
		}
	}
	return removed
}

func (f *DiscardUnchangedFilter) Size() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.cache)
}

func valuesEqual(a, b any) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}
