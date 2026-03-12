package pipeline

import (
	"context"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// Pipeline orchestrates the event processing chain:
// Raw Events → Normalize → Enrich → Filter → Format → Output
type Pipeline struct {
	log     zerolog.Logger
	cfg     PipelineConfig

	// Channels connect pipeline stages
	rawCh        chan *SNMPEvent
	normalizedCh chan *SNMPEvent
	enrichedCh   chan *SNMPEvent
	outputCh     chan *SNMPEvent

	// Stage processors
	normalizer *Normalizer
	enricher   *Enricher
	outputs    []Output

	// Metrics
	mu             sync.RWMutex
	eventsIn       int64
	eventsOut      int64
	eventsDropped  int64
	eventsErrored  int64
	avgProcessTime time.Duration
}

// PipelineConfig controls pipeline behavior.
type PipelineConfig struct {
	BufferSize    int
	Workers       int
	FlushInterval time.Duration
}

// Output is the interface for event destinations.
type Output interface {
	Name() string
	Write(ctx context.Context, event *SNMPEvent) error
	Close() error
}

// NewPipeline creates a new event processing pipeline.
func NewPipeline(log zerolog.Logger, cfg PipelineConfig, normalizer *Normalizer, enricher *Enricher, outputs []Output) *Pipeline {
	bufSize := cfg.BufferSize
	if bufSize <= 0 {
		bufSize = 10000
	}
	workers := cfg.Workers
	if workers <= 0 {
		workers = 4
	}

	return &Pipeline{
		log:          log.With().Str("component", "pipeline").Logger(),
		cfg:          PipelineConfig{BufferSize: bufSize, Workers: workers, FlushInterval: cfg.FlushInterval},
		rawCh:        make(chan *SNMPEvent, bufSize),
		normalizedCh: make(chan *SNMPEvent, bufSize),
		enrichedCh:   make(chan *SNMPEvent, bufSize),
		outputCh:     make(chan *SNMPEvent, bufSize),
		normalizer:   normalizer,
		enricher:     enricher,
		outputs:      outputs,
	}
}

// Submit adds a raw event to the pipeline for processing.
// Blocks briefly if the buffer is full rather than dropping events immediately.
func (p *Pipeline) Submit(event *SNMPEvent) bool {
	// Try non-blocking first
	select {
	case p.rawCh <- event:
		p.mu.Lock()
		p.eventsIn++
		p.mu.Unlock()
		return true
	default:
	}

	// Buffer full — block briefly, then drop
	timer := time.NewTimer(200 * time.Millisecond)
	defer timer.Stop()

	select {
	case p.rawCh <- event:
		p.mu.Lock()
		p.eventsIn++
		p.mu.Unlock()
		return true
	case <-timer.C:
		p.mu.Lock()
		p.eventsDropped++
		p.mu.Unlock()
		return false
	}
}

// Run starts all pipeline stages. Blocks until context is cancelled.
func (p *Pipeline) Run(ctx context.Context) {
	var wg sync.WaitGroup

	// Start normalizer workers
	for i := 0; i < p.cfg.Workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			p.runNormalizer(ctx, id)
		}(i)
	}

	// Start enricher workers
	for i := 0; i < p.cfg.Workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			p.runEnricher(ctx, id)
		}(i)
	}

	// Start output workers
	for i := 0; i < p.cfg.Workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			p.runOutput(ctx, id)
		}(i)
	}

	p.log.Info().
		Int("workers", p.cfg.Workers).
		Int("buffer_size", p.cfg.BufferSize).
		Msg("pipeline started")

	// Wait for all workers to finish
	<-ctx.Done()
	p.log.Info().Msg("pipeline shutting down...")

	// Close channels in order to drain remaining events
	close(p.rawCh)
	wg.Wait()

	// Close outputs
	for _, out := range p.outputs {
		if err := out.Close(); err != nil {
			p.log.Error().Err(err).Str("output", out.Name()).Msg("error closing output")
		}
	}

	p.log.Info().
		Int64("events_in", p.eventsIn).
		Int64("events_out", p.eventsOut).
		Int64("events_dropped", p.eventsDropped).
		Msg("pipeline stopped")
}

// runNormalizer processes raw events through the normalizer.
func (p *Pipeline) runNormalizer(ctx context.Context, id int) {
	for event := range p.rawCh {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if p.normalizer != nil {
			p.normalizer.Process(event)
		}

		select {
		case p.normalizedCh <- event:
		case <-ctx.Done():
			return
		}
	}
}

// runEnricher adds enrichment data to events.
func (p *Pipeline) runEnricher(ctx context.Context, id int) {
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-p.normalizedCh:
			if !ok {
				return
			}
			if p.enricher != nil {
				p.enricher.Process(event)
			}

			event.ProcessedAt = time.Now()
			event.PipelineMs = time.Since(event.Timestamp).Milliseconds()

			select {
			case p.outputCh <- event:
			case <-ctx.Done():
				return
			}
		}
	}
}

// runOutput sends processed events to all configured outputs.
func (p *Pipeline) runOutput(ctx context.Context, id int) {
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-p.outputCh:
			if !ok {
				return
			}

			for _, out := range p.outputs {
				if err := out.Write(ctx, event); err != nil {
					p.mu.Lock()
					p.eventsErrored++
					p.mu.Unlock()
					p.log.Error().
						Err(err).
						Str("output", out.Name()).
						Str("event_id", event.ID).
						Msg("output write error")
				}
			}

			p.mu.Lock()
			p.eventsOut++
			p.mu.Unlock()
		}
	}
}

// Stats returns current pipeline statistics.
func (p *Pipeline) Stats() PipelineStats {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return PipelineStats{
		EventsIn:          p.eventsIn,
		EventsOut:         p.eventsOut,
		EventsDropped:     p.eventsDropped,
		EventsErrored:     p.eventsErrored,
		RawQueueLen:       len(p.rawCh),
		NormalizedQueueLen: len(p.normalizedCh),
		OutputQueueLen:    len(p.outputCh),
		RawQueueCap:       cap(p.rawCh),
	}
}

// PipelineStats holds pipeline performance metrics.
type PipelineStats struct {
	EventsIn          int64 `json:"events_in"`
	EventsOut         int64 `json:"events_out"`
	EventsDropped     int64 `json:"events_dropped"`
	EventsErrored     int64 `json:"events_errored"`
	RawQueueLen       int   `json:"raw_queue_len"`
	NormalizedQueueLen int  `json:"normalized_queue_len"`
	OutputQueueLen    int   `json:"output_queue_len"`
	RawQueueCap       int   `json:"raw_queue_cap"`
}
