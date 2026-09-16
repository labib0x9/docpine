package abuse

import (
	"context"
	"testing"
)

func TestTurnstileValidator(t *testing.T) {
	ctx := context.Background()

	// 1. Dev mode (empty secret) -> bypasses
	devVal := NewTurnstileValidator("")
	if err := devVal.Verify(ctx, "", "198.51.100.1"); err != nil {
		t.Fatalf("expected bypass in dev mode, got: %v", err)
	}

	// 2. Dummy test pass token (using Cloudflare standard test pass secret: 1x0000000000000000000000000000000AA)
	passVal := NewTurnstileValidator("1x0000000000000000000000000000000AA")
	if err := passVal.Verify(ctx, "1x0000000000000000000000000000000AA", "198.51.100.1"); err != nil {
		t.Fatalf("expected test pass token to succeed, got: %v", err)
	}

	// 3. Dummy test fail token (using Cloudflare standard test fail secret: 2x0000000000000000000000000000000AA)
	failVal := NewTurnstileValidator("2x0000000000000000000000000000000AA")
	if err := failVal.Verify(ctx, "2x0000000000000000000000000000000AA", "198.51.100.1"); err == nil {
		t.Fatal("expected test fail token to fail")
	}

	// 4. Missing token check
	if err := passVal.Verify(ctx, "", "198.51.100.1"); err == nil {
		t.Fatal("expected empty token to fail")
	}
}
