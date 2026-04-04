package poller

import (
	"context"
	"time"
)

// SemaphorePool limits concurrent SNMP sessions to avoid OS file-descriptor exhaustion.
// At high device counts (5K+) unbounded goroutine polling causes socket exhaustion;
// the semaphore bounds the concurrency to a safe maximum.
type SemaphorePool struct {
	sem     chan struct{}
	timeout time.Duration
}

// NewSemaphorePool creates a pool that allows up to maxConcurrent simultaneous SNMP sessions.
func NewSemaphorePool(maxConcurrent int, pollTimeout time.Duration) *SemaphorePool {
	if maxConcurrent <= 0 {
		maxConcurrent = 100
	}
	return &SemaphorePool{
		sem:     make(chan struct{}, maxConcurrent),
		timeout: pollTimeout,
	}
}

// Acquire blocks until a semaphore slot is available, or ctx is cancelled.
// Returns an error only if the context is cancelled before a slot becomes free.
func (p *SemaphorePool) Acquire(ctx context.Context) error {
	select {
	case p.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Release frees the semaphore slot, allowing a waiting goroutine to proceed.
func (p *SemaphorePool) Release() {
	<-p.sem
}

// Available returns the number of free slots in the pool.
func (p *SemaphorePool) Available() int {
	return cap(p.sem) - len(p.sem)
}

// InUse returns the number of currently active SNMP sessions.
func (p *SemaphorePool) InUse() int {
	return len(p.sem)
}
