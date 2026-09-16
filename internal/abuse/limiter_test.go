package abuse

import (
	"context"
	"testing"
	"time"
)

func TestRateLimiter(t *testing.T) {
	rl := NewRateLimiter(3, 100*time.Millisecond)
	defer rl.Close(context.Background())

	ip := "198.51.100.1"
	cookie := "device-123"

	// 1. Consume burst tokens (3 tokens)
	for i := 0; i < 3; i++ {
		allowed, delay := rl.Allow(ip, cookie)
		if !allowed {
			t.Fatalf("expected request %d to be allowed under burst, got delay: %v", i+1, delay)
		}
	}

	// 2. Exceed burst -> rejected with Retry-After
	allowed, retryAfter := rl.Allow(ip, cookie)
	if allowed {
		t.Fatal("expected request 4 to be throttled")
	}
	if retryAfter <= 0 {
		t.Fatalf("expected positive retry-after duration, got %v", retryAfter)
	}

	// 3. Different device on same IP has separate pair bucket (up to IP bucket limit)
	allowed2, _ := rl.Allow(ip, "device-456")
	if !allowed2 {
		t.Fatal("expected second device on same IP to have available burst")
	}

	// 4. Wait for refill
	time.Sleep(150 * time.Millisecond)
	allowedAfterRefill, _ := rl.Allow(ip, cookie)
	if !allowedAfterRefill {
		t.Fatal("expected request to be allowed after token refill")
	}
}
