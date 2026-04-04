// Package cache provides a sharded, high-throughput in-memory buffer for
// SNMP metric events.  Events are held in RAM briefly and flushed to a
// BatchFlusher (e.g. TimescaleDB via COPY) in large batches to maximise
// database write throughput and minimise per-row overhead.
package cache

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"

	"github.com/me262/snmp-manager/internal/pipeline"
)

const (
	defaultShards    = 16              // number of independent shards (reduces lock contention)
	defaultBatchSize = 2000            // flush when a shard accumulates this many events
	defaultFlushTTL  = 2 * time.Second // also flush every 2 s even if batch is not full
)

// BatchFlusher is implemented by the database writer.
// FlushBatch must be safe to call concurrently from multiple goroutines.
type BatchFlusher interface {
	FlushBatch(ctx context.Context, events []*pipeline.SNMPEvent) error
}

// HistoryCache is a sharded ring-buffer that decouples the event ingestion
// rate from the database write rate.
//
// Architecture:
//   - Events are routed to one of N shards by FNV-1a hash of (IP+OID).
//   - Each shard has its own mutex, so only 1/N of events contend on any lock.
//   - When a shard's buffer reaches batchSize OR defaultFlushTTL elapses,
//     the buffer is swapped atomically and flushed asynchronously.
type HistoryCache struct {
	log     zerolog.Logger
	shards  []*cacheShard
	flusher BatchFlusher

	// Metrics — accessed with atomic ops, no lock needed.
	TotalBuffered atomic.Int64
	TotalFlushed  atomic.Int64
	TotalDropped  atomic.Int64
	FlushErrors   atomic.Int64
}

type cacheShard struct {
	mu        sync.Mutex
	buf       []*pipeline.SNMPEvent
	cap       int
	lastFlush time.Time
}

// NewHistoryCache creates a cache with the given number of shards and per-shard
// batch size.  Pass 0 for either to use the defaults.
func NewHistoryCache(log zerolog.Logger, flusher BatchFlusher, shards, batchSize int) *HistoryCache {
	if shards <= 0 {
		shards = defaultShards
	}
	if batchSize <= 0 {
		batchSize = defaultBatchSize
	}

	h := &HistoryCache{
		log:     log.With().Str("component", "history-cache").Logger(),
		shards:  make([]*cacheShard, shards),
		flusher: flusher,
	}
	for i := range h.shards {
		h.shards[i] = &cacheShard{
			buf:       make([]*pipeline.SNMPEvent, 0, batchSize),
			cap:       batchSize,
			lastFlush: time.Now(),
		}
	}

	h.log.Info().
		Int("shards", shards).
		Int("batch_size", batchSize).
		Dur("flush_ttl", defaultFlushTTL).
		Msg("history cache initialised")
	return h
}

// Push routes an event to its shard and, if the flush threshold is met,
// triggers an asynchronous flush (non-blocking).
func (h *HistoryCache) Push(ctx context.Context, event *pipeline.SNMPEvent) {
	idx := h.shardIndex(event.DeviceIP + event.OID)
	shard := h.shards[idx]

	shard.mu.Lock()
	shard.buf = append(shard.buf, event)
	h.TotalBuffered.Add(1)
	shouldFlush := len(shard.buf) >= shard.cap ||
		time.Since(shard.lastFlush) >= defaultFlushTTL
	shard.mu.Unlock()

	if shouldFlush {
		go h.flushShard(ctx, idx)
	}
}

// flushShard atomically steals the shard's buffer and calls FlushBatch.
// The buffer-swap pattern ensures the hot path never blocks on I/O.
func (h *HistoryCache) flushShard(ctx context.Context, idx int) {
	shard := h.shards[idx]

	shard.mu.Lock()
	if len(shard.buf) == 0 {
		shard.mu.Unlock()
		return
	}
	// Swap: steal the filled slice, replace with a fresh one.
	batch := shard.buf
	shard.buf = make([]*pipeline.SNMPEvent, 0, shard.cap)
	shard.lastFlush = time.Now()
	shard.mu.Unlock()

	if err := h.flusher.FlushBatch(ctx, batch); err != nil {
		h.FlushErrors.Add(1)
		h.TotalDropped.Add(int64(len(batch)))
		h.log.Error().Err(err).Int("batch_size", len(batch)).Msg("batch flush failed — events dropped")
		return
	}
	h.TotalFlushed.Add(int64(len(batch)))
}

// RunFlusher starts a background goroutine that force-flushes all shards
// every defaultFlushTTL.  This guarantees that even low-traffic shards are
// written within the TTL window.
//
// Returns when ctx is cancelled.  Before returning it performs a final
// synchronous flush of all remaining events.
func (h *HistoryCache) RunFlusher(ctx context.Context) {
	ticker := time.NewTicker(defaultFlushTTL)
	defer ticker.Stop()

	h.log.Info().Msg("history cache flusher started")

	for {
		select {
		case <-ctx.Done():
			h.log.Info().Msg("history cache flusher shutting down — draining shards")
			for i := range h.shards {
				h.flushShard(context.Background(), i)
			}
			h.log.Info().
				Int64("flushed", h.TotalFlushed.Load()).
				Int64("dropped", h.TotalDropped.Load()).
				Msg("history cache flusher stopped")
			return

		case <-ticker.C:
			for i := range h.shards {
				go h.flushShard(ctx, i)
			}
		}
	}
}

// Stats returns a snapshot of cache metrics.
func (h *HistoryCache) Stats() CacheStats {
	buffered := int64(0)
	for _, s := range h.shards {
		s.mu.Lock()
		buffered += int64(len(s.buf))
		s.mu.Unlock()
	}
	return CacheStats{
		Shards:        len(h.shards),
		TotalBuffered: h.TotalBuffered.Load(),
		TotalFlushed:  h.TotalFlushed.Load(),
		TotalDropped:  h.TotalDropped.Load(),
		FlushErrors:   h.FlushErrors.Load(),
		CurrentBuffer: buffered,
	}
}

// CacheStats is a point-in-time snapshot of HistoryCache metrics.
type CacheStats struct {
	Shards        int   `json:"shards"`
	TotalBuffered int64 `json:"total_buffered"`
	TotalFlushed  int64 `json:"total_flushed"`
	TotalDropped  int64 `json:"total_dropped"`
	FlushErrors   int64 `json:"flush_errors"`
	CurrentBuffer int64 `json:"current_buffer"`
}

// shardIndex maps a string key to a shard index using FNV-1a hashing.
// FNV-1a is chosen for its speed and good distribution on short strings.
func (h *HistoryCache) shardIndex(key string) int {
	var hash uint64 = 14695981039346656037
	for i := 0; i < len(key); i++ {
		hash ^= uint64(key[i])
		hash *= 1099511628211
	}
	return int(hash % uint64(len(h.shards)))
}
