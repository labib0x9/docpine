package abuse

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTurnstileValidator(t *testing.T) {
	ctx := context.Background()

	// 1. Dev mode (empty secret) -> bypasses
	devVal := NewTurnstileValidator("")
	if err := devVal.Verify(ctx, "", "198.51.100.1"); err != nil {
		t.Fatalf("expected bypass in dev mode, got: %v", err)
	}

	// 2. Dummy test pass token
	val := NewTurnstileValidator("0x4AAAAAAtestsecret")
	if err := val.Verify(ctx, "1x0000000000000000000000000000000AA", "198.51.100.1"); err != nil {
		t.Fatalf("expected test pass token to succeed, got: %v", err)
	}

	// 3. Dummy test fail token
	if err := val.Verify(ctx, "2x0000000000000000000000000000000AA", "198.51.100.1"); err == nil {
		t.Fatal("expected test fail token to fail")
	}

	// 4. Mocked API server response
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success": true, "challenge_ts": "2026-09-14T00:00:00Z"}`))
	}))
	defer mockServer.Close()

	mockClient := &http.Client{
		Transport: &http.Transport{
			Proxy: nil,
		},
	}
	// We can test mock round-trip
	_ = mockClient
}
