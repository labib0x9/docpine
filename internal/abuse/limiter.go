package abuse

import (
	"context"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type entry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// RateLimiter implements a token bucket rate limiter keyed on client IP and device cookie pairs.
type RateLimiter struct {
	burst      int
	refillRate time.Duration
	mu         sync.Mutex
	pairs      map[string]*entry // keyed on "ip:cookie"
	ipOnly     map[string]*entry // keyed on "ip"
	stopChan   chan struct{}
}

// NewRateLimiter creates a token bucket rate limiter using golang.org/x/time/rate.
func NewRateLimiter(burst int, refillRate time.Duration) *RateLimiter {
	rl := &RateLimiter{
		burst:      burst,
		refillRate: refillRate,
		pairs:      make(map[string]*entry),
		ipOnly:     make(map[string]*entry),
		stopChan:   make(chan struct{}),
	}

	go rl.evictStaleEntries()
	return rl
}

// Allow checks if a request is allowed for the given IP and device cookie.
// It verifies both the combined (IP, cookie) pair and the raw IP bucket.
func (rl *RateLimiter) Allow(ip, cookieID string) (bool, time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	pairKey := ip + ":" + cookieID
	pairE, exists := rl.pairs[pairKey]
	if !exists {
		pairE = &entry{
			limiter:  rate.NewLimiter(rate.Every(rl.refillRate), rl.burst),
			lastSeen: now,
		}
		rl.pairs[pairKey] = pairE
	} else {
		pairE.lastSeen = now
	}

	ipE, exists := rl.ipOnly[ip]
	if !exists {
		ipE = &entry{
			limiter:  rate.NewLimiter(rate.Every(rl.refillRate/2), rl.burst*2),
			lastSeen: now,
		}
		rl.ipOnly[ip] = ipE
	} else {
		ipE.lastSeen = now
	}

	rPair := pairE.limiter.Reserve()
	if !rPair.OK() || rPair.Delay() > 0 {
		delay := rPair.Delay()
		rPair.Cancel()
		return false, delay
	}

	rIP := ipE.limiter.Reserve()
	if !rIP.OK() || rIP.Delay() > 0 {
		delay := rIP.Delay()
		rPair.Cancel()
		rIP.Cancel()
		return false, delay
	}

	return true, 0
}

// Close stops the background eviction goroutine.
func (rl *RateLimiter) Close(ctx context.Context) {
	close(rl.stopChan)
}

func (rl *RateLimiter) evictStaleEntries() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-rl.stopChan:
			return
		case <-ticker.C:
			rl.mu.Lock()
			now := time.Now()
			for k, e := range rl.pairs {
				if now.Sub(e.lastSeen) > 1*time.Hour {
					delete(rl.pairs, k)
				}
			}
			for k, e := range rl.ipOnly {
				if now.Sub(e.lastSeen) > 1*time.Hour {
					delete(rl.ipOnly, k)
				}
			}
			rl.mu.Unlock()
		}
	}
}
