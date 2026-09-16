package abuse

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labib0x9/docpine/internal/config"
)

func TestGuard_EndToEnd(t *testing.T) {
	secret := []byte("guard-test-secret-32-byte-key-12")
	cfg := config.Config{
		Abuse: &config.Abuse{
			CookieSecret:    secret,
			RateBurst:       2,
			RateRefillRate:  1 * time.Second,
			TurnstileSecret: "1x0000000000000000000000000000000AA", // Passing test secret
		},
		Session: &config.Session{
			MaxConcurrent: 2,
		},
	}
	guard := NewGuard(cfg)

	// 1. Initial request without Turnstile token -> Returns 428 Precondition Required
	req1 := httptest.NewRequest(http.MethodPost, "/sessions", nil)
	req1.Header.Set("CF-Connecting-IP", "203.0.113.10")
	w1 := httptest.NewRecorder()

	passed, release := guard.CheckAnonymousCreate(w1, req1, nil)
	if passed {
		t.Fatal("expected request without turnstile token to be challenged")
	}
	if release != nil {
		t.Fatal("expected no slot reserved when challenged")
	}
	if w1.Code != http.StatusPreconditionRequired {
		t.Fatalf("expected HTTP 428, got %d", w1.Code)
	}

	var chalResp ChallengeResponsePayload
	if err := json.Unmarshal(w1.Body.Bytes(), &chalResp); err != nil {
		t.Fatalf("failed to decode challenge response: %v", err)
	}
	if !chalResp.TurnstileRequired {
		t.Fatal("expected TurnstileRequired to be true")
	}

	// 2. Request with valid Turnstile Token -> Passes
	req2 := httptest.NewRequest(http.MethodPost, "/sessions", nil)
	req2.Header.Set("CF-Connecting-IP", "203.0.113.10")
	for _, c := range w1.Result().Cookies() {
		req2.AddCookie(c)
	}
	w2 := httptest.NewRecorder()

	passed2, release2 := guard.CheckAnonymousCreate(w2, req2, &CreateRequestPayload{
		TurnstileToken: "1x0000000000000000000000000000000AA",
	})
	if !passed2 {
		t.Fatalf("expected request with valid turnstile to pass, status %d body %s", w2.Code, w2.Body.String())
	}
	if guard.ConcurrencyLimiter().Active() != 1 {
		t.Fatalf("expected 1 active slot, got %d", guard.ConcurrencyLimiter().Active())
	}

	// 3. Second valid request on same client
	req3 := httptest.NewRequest(http.MethodPost, "/sessions", nil)
	req3.Header.Set("CF-Connecting-IP", "203.0.113.10")
	for _, c := range w1.Result().Cookies() {
		req3.AddCookie(c)
	}
	w3 := httptest.NewRecorder()

	passed3, release3 := guard.CheckAnonymousCreate(w3, req3, &CreateRequestPayload{
		TurnstileToken: "1x0000000000000000000000000000000AA",
	})
	if !passed3 {
		t.Fatalf("expected second request to pass, status %d body %s", w3.Code, w3.Body.String())
	}
	if guard.ConcurrencyLimiter().Active() != 2 {
		t.Fatalf("expected 2 active slots, got %d", guard.ConcurrencyLimiter().Active())
	}

	// 4. Concurrency Cap Exceeded (Max is 2)
	req4 := httptest.NewRequest(http.MethodPost, "/sessions", nil)
	req4.Header.Set("CF-Connecting-IP", "198.51.100.99") // different IP
	w4 := httptest.NewRecorder()

	passed4, _ := guard.CheckAnonymousCreate(w4, req4, &CreateRequestPayload{
		TurnstileToken: "1x0000000000000000000000000000000AA",
	})
	if passed4 {
		t.Fatal("expected request to be rejected when global capacity is full")
	}
	if w4.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected HTTP 503, got %d", w4.Code)
	}

	// 5. Release one slot and verify capacity opens up
	release2()
	if guard.ConcurrencyLimiter().Active() != 1 {
		t.Fatalf("expected 1 active slot after release, got %d", guard.ConcurrencyLimiter().Active())
	}

	// Cleanup remaining
	release3()
	if guard.ConcurrencyLimiter().Active() != 0 {
		t.Fatalf("expected 0 active slots after final release, got %d", guard.ConcurrencyLimiter().Active())
	}
}
