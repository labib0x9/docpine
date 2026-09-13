package abuse

import (
	"context"
	"math"
	"sync"
	"time"
)

// RateLimiterConfig configures token bucket parameters.
type RateLimiterConfig struct {
	Burst      int           // Maximum token capacity per bucket (e.g. 5)
	RefillRate time.Duration // Interval per single token refill (e.g. 30s)
}

type bucket struct {
	tokens     float64
	lastRefill time.Time
}

// RateLimiter implements a token bucket rate limiter keyed on client IP and device cookie pairs.
type RateLimiter struct {
	cfg      RateLimiterConfig
	mu       sync.Mutex
	pairs    map[string]*bucket // keyed on "ip:cookie"
	ipOnly   map[string]*bucket // keyed on "ip"
	stopChan chan struct{}
}

// NewRateLimiter creates a token bucket rate limiter with automated stale bucket eviction.
func NewRateLimiter(cfg RateLimiterConfig) *RateLimiter {
	if cfg.Burst <= 0 {
		cfg.Burst = 5
	}
	if cfg.RefillRate <= 0 {
		cfg.RefillRate = 30 * time.Second
	}

	rl := &RateLimiter{
		cfg:      cfg,
		pairs:    make(map[string]*bucket),
		ipOnly:   make(map[string]*bucket),
		stopChan: make(chan struct{}),
	}

	go rl.evictStaleBuckets()
	return rl
}

// Allow checks if a request is allowed for the given IP and device cookie.
// It verifies both the combined (IP, cookie) pair and the raw IP bucket.
func (rl *RateLimiter) Allow(ip, cookieID string) (bool, time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	refillPerSec := 1.0 / rl.cfg.RefillRate.Seconds()

	// 1. Check combined pair bucket
	pairKey := ip + ":" + cookieID
	pairB, exists := rl.pairs[pairKey]
	if !exists {
		pairB = &bucket{
			tokens:     float64(rl.cfg.Burst),
			lastRefill: now,
		}
		rl.pairs[pairKey] = pairB
	} else {
		elapsed := now.Sub(pairB.lastRefill).Seconds()
		pairB.tokens = math.Min(float64(rl.cfg.Burst), pairB.tokens+elapsed*refillPerSec)
		pairB.lastRefill = now
	}

	// 2. Check IP-only bucket (secondary line of defense against cookie deletion)
	ipB, exists := rl.ipOnly[ip]
	if !exists {
		// Allow IP bucket 2x burst of single pair
		ipB = &bucket{
			tokens:     float64(rl.cfg.Burst * 2),
			lastRefill: now,
		}
		rl.ipOnly[ip] = ipB
	} else {
		elapsed := now.Sub(ipB.lastRefill).Seconds()
		ipB.tokens = math.Min(float64(rl.cfg.Burst*2), ipB.tokens+elapsed*(refillPerSec*2))
		ipB.lastRefill = now
	}

	if pairB.tokens < 1.0 {
		needed := 1.0 - pairB.tokens
		retrySec := time.Duration(needed/refillPerSec) * time.Second
		if retrySec < time.Second {
			retrySec = time.Second
		}
		return false, retrySec
	}

	if ipB.tokens < 1.0 {
		needed := 1.0 - ipB.tokens
		retrySec := time.Duration(needed/(refillPerSec*2)) * time.Second
		if retrySec < time.Second {
			retrySec = time.Second
		}
		return false, retrySec
	}

	pairB.tokens -= 1.0
	ipB.tokens -= 1.0
	return true, 0
}

// Close stops the background eviction goroutine.
func (rl *RateLimiter) Close(ctx context.Context) {
	close(rl.stopChan)
}

func (rl *RateLimiter) evictStaleBuckets() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-rl.stopChan:
			return
		case <-ticker.C:
			rl.mu.Lock()
			now := time.Now()
			for k, b := range rl.pairs {
				if now.Sub(b.lastRefill) > 1*time.Hour {
					delete(rl.pairs, k)
				}
			}
			for k, b := range rl.ipOnly {
				if now.Sub(b.lastRefill) > 1*time.Hour {
					delete(rl.ipOnly, k)
				}
			}
			rl.mu.Unlock()
		}
	}
}
