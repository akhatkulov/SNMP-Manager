package output

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"

	"github.com/me262/snmp-manager/internal/formatter"
	"github.com/me262/snmp-manager/internal/pipeline"
)

// BufferedOutput wraps any Output with disk-backed buffering.
// When the downstream output is unreachable, events are spooled to disk.
// A background goroutine periodically retries flushing, using exponential
// backoff and rate-limiting so reconnection is gentle.
type BufferedOutput struct {
	log     zerolog.Logger
	inner   pipeline.Output // the real output being wrapped
	jsonFmt *formatter.JSONFormatter

	// ── Buffer state ─────────────────────────────────────────────
	mu          sync.Mutex
	memBuf      []*pipeline.SNMPEvent // in-memory buffer (unlimited)
	bufDir      string // directory for disk spool files
	spoolFile   string // active spool file path
	spoolWriter *bufio.Writer
	spoolFd     *os.File

	// ── Circuit breaker ──────────────────────────────────────────
	circuitOpen atomic.Bool  // true = output is down, buffer writes
	lastCheck   atomic.Int64 // unix timestamp of last health probe

	// ── Metrics ──────────────────────────────────────────────────
	sent       atomic.Int64
	buffered   atomic.Int64
	flushed    atomic.Int64
	dropped    atomic.Int64
	errors     atomic.Int64
	spoolBytes atomic.Int64

	// ── Config ───────────────────────────────────────────────────
	flushInterval   time.Duration
	flushBatchSize  int
	maxSpoolSizeMB  int
	backoffBase     time.Duration
	backoffMax      time.Duration
	currentBackoff  time.Duration

	// ── Lifecycle ────────────────────────────────────────────────
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// BufferedConfig holds buffering configuration.
type BufferedConfig struct {
	MemoryBufferSize int           // initial allocation hint (buffer grows unlimited)
	SpoolDir         string        // disk spool directory (default: /tmp/snmp-buffer)
	MaxSpoolSizeMB   int           // max disk spool size in MB (default: 100)
	FlushInterval    time.Duration // how often to try flushing (default: 5s)
	FlushBatchSize   int           // events per flush batch (default: 50)
	BackoffBase      time.Duration // initial retry backoff (default: 2s)
	BackoffMax       time.Duration // max backoff between retries (default: 60s)
}

// NewBufferedOutput wraps an output with store-and-forward buffering.
func NewBufferedOutput(log zerolog.Logger, inner pipeline.Output, cfg BufferedConfig) *BufferedOutput {
	if cfg.MemoryBufferSize <= 0 {
		cfg.MemoryBufferSize = 4096 // initial slice capacity hint
	}
	if cfg.SpoolDir == "" {
		cfg.SpoolDir = "/tmp/snmp-buffer"
	}
	if cfg.MaxSpoolSizeMB <= 0 {
		cfg.MaxSpoolSizeMB = 100
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 5 * time.Second
	}
	if cfg.FlushBatchSize <= 0 {
		cfg.FlushBatchSize = 50
	}
	if cfg.BackoffBase <= 0 {
		cfg.BackoffBase = 2 * time.Second
	}
	if cfg.BackoffMax <= 0 {
		cfg.BackoffMax = 60 * time.Second
	}

	ctx, cancel := context.WithCancel(context.Background())

	b := &BufferedOutput{
		log:            log.With().Str("component", "buffered-output").Str("target", inner.Name()).Logger(),
		inner:          inner,
		jsonFmt:        formatter.NewJSONFormatter(false),
		memBuf:         make([]*pipeline.SNMPEvent, 0, cfg.MemoryBufferSize),
		bufDir:         cfg.SpoolDir,
		flushInterval:  cfg.FlushInterval,
		flushBatchSize: cfg.FlushBatchSize,
		maxSpoolSizeMB: cfg.MaxSpoolSizeMB,
		backoffBase:    cfg.BackoffBase,
		backoffMax:     cfg.BackoffMax,
		currentBackoff: cfg.BackoffBase,
		ctx:            ctx,
		cancel:         cancel,
	}

	// Ensure spool directory exists
	os.MkdirAll(cfg.SpoolDir, 0o755)

	// Open spool file
	b.spoolFile = filepath.Join(cfg.SpoolDir, fmt.Sprintf("spool-%s.jsonl", sanitizeName(inner.Name())))
	b.openSpool()

	// Count existing spool entries
	b.countSpoolEntries()

	// Start background flusher
	b.wg.Add(1)
	go b.flushLoop()

	b.log.Info().
		Str("mem_cap", "unlimited").
		Str("spool_dir", cfg.SpoolDir).
		Int("max_spool_mb", cfg.MaxSpoolSizeMB).
		Dur("flush_interval", cfg.FlushInterval).
		Msg("buffered output started")

	return b
}

// Name returns the wrapped output name with buffer indicator.
func (b *BufferedOutput) Name() string {
	return fmt.Sprintf("buffered(%s)", b.inner.Name())
}

// Write tries to send the event to the real output. If it fails,
// the event is buffered (memory first, then disk spool).
func (b *BufferedOutput) Write(ctx context.Context, event *pipeline.SNMPEvent) error {
	// Fast path — circuit is closed (output is healthy)
	if !b.circuitOpen.Load() {
		err := b.inner.Write(ctx, event)
		if err == nil {
			b.sent.Add(1)
			return nil
		}
		// Output failed — open circuit
		b.log.Warn().Err(err).Msg("output failed, opening circuit breaker — buffering events")
		b.circuitOpen.Store(true)
		b.currentBackoff = b.backoffBase
	}

	// Circuit is open — buffer the event
	b.bufferEvent(event)
	return nil // never return error to pipeline, we handle it
}

// Close flushes remaining buffer and closes the output.
func (b *BufferedOutput) Close() error {
	b.log.Info().
		Int64("sent", b.sent.Load()).
		Int64("buffered", b.buffered.Load()).
		Int64("flushed", b.flushed.Load()).
		Int64("dropped", b.dropped.Load()).
		Msg("closing buffered output")

	b.cancel()
	b.wg.Wait()

	b.mu.Lock()
	if b.spoolFd != nil {
		b.spoolWriter.Flush()
		b.spoolFd.Close()
	}
	b.mu.Unlock()

	return b.inner.Close()
}

// Stats returns buffer metrics for the dashboard.
func (b *BufferedOutput) Stats() map[string]interface{} {
	return map[string]interface{}{
		"output":         b.inner.Name(),
		"circuit_open":   b.circuitOpen.Load(),
		"sent":           b.sent.Load(),
		"buffered":       b.buffered.Load(),
		"flushed":        b.flushed.Load(),
		"dropped":        b.dropped.Load(),
		"errors":         b.errors.Load(),
		"spool_bytes":    b.spoolBytes.Load(),
		"spool_file":     b.spoolFile,
		"mem_buf_len":    len(b.memBuf),
		"mem_buf_cap":    -1, // unlimited
		"backoff":        b.currentBackoff.String(),
	}
}

// ── Internal Methods ─────────────────────────────────────────────────

func (b *BufferedOutput) bufferEvent(event *pipeline.SNMPEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Always buffer to memory (unlimited)
	b.memBuf = append(b.memBuf, event)
	b.buffered.Add(1)
}

func (b *BufferedOutput) writeToSpool(event *pipeline.SNMPEvent) {
	// Check spool size limit
	if b.spoolBytes.Load() > int64(b.maxSpoolSizeMB)*1024*1024 {
		b.dropped.Add(1)
		return
	}

	data, err := b.jsonFmt.Format(event)
	if err != nil {
		b.errors.Add(1)
		return
	}

	if b.spoolWriter != nil {
		n, err := b.spoolWriter.WriteString(data + "\n")
		if err != nil {
			b.errors.Add(1)
			return
		}
		b.spoolWriter.Flush()
		b.spoolBytes.Add(int64(n))
		b.buffered.Add(1)
	}
}

func (b *BufferedOutput) openSpool() {
	fd, err := os.OpenFile(b.spoolFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		b.log.Error().Err(err).Msg("failed to open spool file")
		return
	}
	b.spoolFd = fd
	b.spoolWriter = bufio.NewWriterSize(fd, 64*1024)

	// Get current spool size
	if info, err := fd.Stat(); err == nil {
		b.spoolBytes.Store(info.Size())
	}
}

func (b *BufferedOutput) countSpoolEntries() {
	fd, err := os.Open(b.spoolFile)
	if err != nil {
		return
	}
	defer fd.Close()

	count := int64(0)
	scanner := bufio.NewScanner(fd)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		count++
	}
	if count > 0 {
		b.buffered.Add(count)
		b.log.Info().Int64("pending", count).Msg("found pending events in spool file")
	}
}

// flushLoop runs in background and periodically flushes buffered events.
func (b *BufferedOutput) flushLoop() {
	defer b.wg.Done()

	for {
		select {
		case <-b.ctx.Done():
			// Final flush attempt before exit
			b.tryFlush()
			return
		case <-time.After(b.currentBackoff):
			if !b.circuitOpen.Load() && b.buffered.Load() == 0 {
				continue
			}
			b.tryFlush()
		}
	}
}

func (b *BufferedOutput) tryFlush() {
	// First, try a health probe to see if the output is back
	if b.circuitOpen.Load() {
		probeEvent := &pipeline.SNMPEvent{
			ID:        "health-probe",
			Timestamp: time.Now(),
			Source:    pipeline.SourceInfo{IP: "0.0.0.0"},
			EventType: pipeline.EventTypeDiscovery,
		}
		err := b.inner.Write(b.ctx, probeEvent)
		if err != nil {
			// Still down — increase backoff
			b.currentBackoff = min64(b.currentBackoff*2, b.backoffMax)
			b.log.Debug().
				Dur("next_retry", b.currentBackoff).
				Msg("output still unreachable, backing off")
			return
		}
		// Output is back!
		b.circuitOpen.Store(false)
		b.currentBackoff = b.backoffBase
		b.log.Info().Msg("output recovered — starting to flush buffered events")
	}

	// Flush memory buffer first
	b.flushMemory()

	// Then flush disk spool
	b.flushSpool()
}

func (b *BufferedOutput) flushMemory() {
	b.mu.Lock()
	if len(b.memBuf) == 0 {
		b.mu.Unlock()
		return
	}

	// Take a batch from memory buffer
	batchSize := b.flushBatchSize
	if batchSize > len(b.memBuf) {
		batchSize = len(b.memBuf)
	}
	batch := make([]*pipeline.SNMPEvent, batchSize)
	copy(batch, b.memBuf[:batchSize])
	b.mu.Unlock()

	sent := 0
	for _, event := range batch {
		if err := b.inner.Write(b.ctx, event); err != nil {
			// Output failed again — re-open circuit
			b.circuitOpen.Store(true)
			b.currentBackoff = b.backoffBase
			b.log.Warn().Int("sent_before_fail", sent).Msg("output failed during flush, re-opening circuit")
			break
		}
		sent++
		b.flushed.Add(1)
		// Rate limit: small delay between events to not overwhelm the destination
		time.Sleep(10 * time.Millisecond)
	}

	// Remove sent events from memory buffer
	if sent > 0 {
		b.mu.Lock()
		b.memBuf = b.memBuf[sent:]
		b.buffered.Add(-int64(sent))
		b.mu.Unlock()
		b.log.Info().Int("flushed", sent).Int("remaining", len(b.memBuf)).Msg("flushed events from memory buffer")
	}
}

func (b *BufferedOutput) flushSpool() {
	if b.circuitOpen.Load() {
		return
	}

	b.mu.Lock()
	// Close the write handle so we can read
	if b.spoolWriter != nil {
		b.spoolWriter.Flush()
	}
	b.mu.Unlock()

	// Read spool file
	fd, err := os.Open(b.spoolFile)
	if err != nil {
		return
	}
	defer fd.Close()

	info, _ := fd.Stat()
	if info.Size() == 0 {
		return
	}

	scanner := bufio.NewScanner(fd)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	sent := 0
	var remaining []string

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		if b.circuitOpen.Load() || sent >= b.flushBatchSize {
			remaining = append(remaining, line)
			continue
		}

		// Parse the JSON event and send it via the inner output
		var event pipeline.SNMPEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			// Skip corrupted lines
			continue
		}

		if err := b.inner.Write(b.ctx, &event); err != nil {
			b.circuitOpen.Store(true)
			b.currentBackoff = b.backoffBase
			remaining = append(remaining, line)
			b.log.Warn().Int("sent_before_fail", sent).Msg("output failed during spool flush")
			continue
		}

		sent++
		b.flushed.Add(1)
		b.buffered.Add(-1)
		time.Sleep(10 * time.Millisecond) // rate limit
	}

	// Collect remaining lines
	for scanner.Scan() {
		if line := scanner.Text(); line != "" {
			remaining = append(remaining, line)
		}
	}
	fd.Close()

	// Rewrite spool file with remaining events
	b.mu.Lock()
	if b.spoolFd != nil {
		b.spoolFd.Close()
	}

	newFd, err := os.Create(b.spoolFile)
	if err == nil {
		writer := bufio.NewWriterSize(newFd, 64*1024)
		totalBytes := int64(0)
		for _, line := range remaining {
			n, _ := writer.WriteString(line + "\n")
			totalBytes += int64(n)
		}
		writer.Flush()
		b.spoolFd = newFd
		b.spoolWriter = bufio.NewWriterSize(newFd, 64*1024)
		b.spoolBytes.Store(totalBytes)
	}
	b.mu.Unlock()

	if sent > 0 {
		b.log.Info().
			Int("flushed", sent).
			Int("remaining", len(remaining)).
			Msg("flushed events from disk spool")
	}
}

func min64(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func sanitizeName(name string) string {
	result := make([]byte, 0, len(name))
	for _, c := range name {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			result = append(result, byte(c))
		} else {
			result = append(result, '_')
		}
	}
	return string(result)
}
