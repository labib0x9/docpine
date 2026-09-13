package abuse

import (
	"sync"
	"testing"
)

func TestConcurrencyLimiter(t *testing.T) {
	limiter := NewConcurrencyLimiter(3)

	// Acquire up to max
	if !limiter.TryAcquire() || !limiter.TryAcquire() || !limiter.TryAcquire() {
		t.Fatal("expected 3 slots to be acquired successfully")
	}

	if limiter.Active() != 3 {
		t.Fatalf("expected 3 active, got %d", limiter.Active())
	}

	// 4th acquire should fail
	if limiter.TryAcquire() {
		t.Fatal("expected 4th acquire to be rejected")
	}

	// Release 1 slot
	limiter.Release()
	if limiter.Active() != 2 {
		t.Fatalf("expected 2 active, got %d", limiter.Active())
	}

	// Re-acquire should now succeed
	if !limiter.TryAcquire() {
		t.Fatal("expected acquire to succeed after slot release")
	}

	// Concurrent test
	var wg sync.WaitGroup
	acquired := 0
	var mu sync.Mutex
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if limiter.TryAcquire() {
				mu.Lock()
				acquired++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	// Should not exceed max
	if limiter.Active() > limiter.Max() {
		t.Fatalf("active %d exceeded max %d", limiter.Active(), limiter.Max())
	}
}
