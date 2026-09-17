package abuse

import (
	"errors"
	"log/slog"
	"sync/atomic"
)

var (
	ErrGlobalCapacityReached = errors.New("global anonymous sandbox capacity reached")
)

// ConcurrencyLimiter provides a hard ceiling on concurrently running anonymous sandboxes.
type ConcurrencyLimiter struct {
	maxConcurrent int64
	active        int64
	totalRejected int64
}

// NewConcurrencyLimiter creates a limiter with the specified maximum ceiling.
func NewConcurrencyLimiter(maxConcurrent int) *ConcurrencyLimiter {
	if maxConcurrent <= 0 {
		maxConcurrent = 12
	}
	return &ConcurrencyLimiter{
		maxConcurrent: int64(maxConcurrent),
	}
}

// TryAcquire attempts to reserve a slot for a new anonymous sandbox.
// Returns true if acquired, false if the global ceiling is reached.
func (c *ConcurrencyLimiter) TryAcquire() bool {
	for {
		current := atomic.LoadInt64(&c.active)
		if current >= c.maxConcurrent {
			atomic.AddInt64(&c.totalRejected, 1)
			slog.Warn("Global anonymous concurrency cap reached (aggregate capacity exhausted)",
				"active", current,
				"limit", c.maxConcurrent,
				"total_rejected", atomic.LoadInt64(&c.totalRejected),
			)
			return false
		}
		if atomic.CompareAndSwapInt64(&c.active, current, current+1) {
			slog.Debug("Anonymous sandbox slot acquired", "active", current+1, "limit", c.maxConcurrent)
			return true
		}
	}
}

// Release frees an allocated slot.
func (c *ConcurrencyLimiter) Release() {
	newActive := atomic.AddInt64(&c.active, -1)
	if newActive < 0 {
		atomic.StoreInt64(&c.active, 0)
		newActive = 0
	}
	slog.Debug("Anonymous sandbox slot released", "active", newActive, "limit", c.maxConcurrent)
}

// Active returns the number of currently active anonymous slots.
func (c *ConcurrencyLimiter) Active() int64 {
	return atomic.LoadInt64(&c.active)
}

// Max returns the maximum allowed concurrent sandboxes.
func (c *ConcurrencyLimiter) Max() int64 {
	return c.maxConcurrent
}
