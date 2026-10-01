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

	passed, _, release := guard.CheckAnonymousCreate(w1, req1, nil)
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

	passed2, devID2, release2 := guard.CheckAnonymousCreate(w2, req2, &CreateRequestPayload{
		TurnstileToken: "1x0000000000000000000000000000000AA",
	})
	if !passed2 {
		t.Fatalf("expected request with valid turnstile to pass, status %d body %s", w2.Code, w2.Body.String())
	}
	if guard.ConcurrencyLimiter().Active() != 1 {
		t.Fatalf("expected 1 active slot, got %d", guard.ConcurrencyLimiter().Active())
	}
	guard.RegisterSession(devID2, "session-test-1")

	// 3. Second request from SAME device while session is active -> Rejected with 409 Conflict
	req3 := httptest.NewRequest(http.MethodPost, "/sessions", nil)
	req3.Header.Set("CF-Connecting-IP", "203.0.113.10")
	for _, c := range w1.Result().Cookies() {
		req3.AddCookie(c)
	}
	w3 := httptest.NewRecorder()

	passed3, _, _ := guard.CheckAnonymousCreate(w3, req3, &CreateRequestPayload{
		TurnstileToken: "1x0000000000000000000000000000000AA",
	})
	if passed3 {
		t.Fatal("expected duplicate create from same device with active session to be rejected")
	}
	if w3.Code != http.StatusConflict {
		t.Fatalf("expected HTTP 409 Conflict for duplicate device session, got %d", w3.Code)
	}

	// 4. Second valid request on a DIFFERENT client/device -> Passes
	req4 := httptest.NewRequest(http.MethodPost, "/sessions", nil)
	req4.Header.Set("CF-Connecting-IP", "203.0.113.20")
	w4 := httptest.NewRecorder()

	passed4, devID4, release4 := guard.CheckAnonymousCreate(w4, req4, &CreateRequestPayload{
		TurnstileToken: "1x0000000000000000000000000000000AA",
	})
	if !passed4 {
		t.Fatalf("expected second client to pass, status %d body %s", w4.Code, w4.Body.String())
	}
	if guard.ConcurrencyLimiter().Active() != 2 {
		t.Fatalf("expected 2 active slots, got %d", guard.ConcurrencyLimiter().Active())
	}
	guard.RegisterSession(devID4, "session-test-2")

	// 5. Concurrency Cap Exceeded (Max is 2)
	req5 := httptest.NewRequest(http.MethodPost, "/sessions", nil)
	req5.Header.Set("CF-Connecting-IP", "198.51.100.99") // third IP
	w5 := httptest.NewRecorder()

	passed5, _, _ := guard.CheckAnonymousCreate(w5, req5, &CreateRequestPayload{
		TurnstileToken: "1x0000000000000000000000000000000AA",
	})
	if passed5 {
		t.Fatal("expected request to be rejected when global capacity is full")
	}
	if w5.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected HTTP 503, got %d", w5.Code)
	}

	// 6. Release first session and verify device can create a new session
	guard.ReleaseSession("session-test-1")
	release2()
	if guard.ConcurrencyLimiter().Active() != 1 {
		t.Fatalf("expected 1 active slot after release, got %d", guard.ConcurrencyLimiter().Active())
	}

	// Device 1 retries and now succeeds
	req6 := httptest.NewRequest(http.MethodPost, "/sessions", nil)
	req6.Header.Set("CF-Connecting-IP", "203.0.113.10")
	for _, c := range w1.Result().Cookies() {
		req6.AddCookie(c)
	}
	w6 := httptest.NewRecorder()

	passed6, devID6, release6 := guard.CheckAnonymousCreate(w6, req6, &CreateRequestPayload{
		TurnstileToken: "1x0000000000000000000000000000000AA",
	})
	if !passed6 {
		t.Fatalf("expected retry after session release to pass, status %d body %s", w6.Code, w6.Body.String())
	}
	if devID6 != devID2 {
		t.Fatalf("expected same device ID %s, got %s", devID2, devID6)
	}
	guard.RegisterSession(devID6, "session-test-3")

	// Cleanup
	guard.ReleaseSession("session-test-2")
	release4()
	guard.ReleaseSession("session-test-3")
	release6()
	if guard.ConcurrencyLimiter().Active() != 0 {
		t.Fatalf("expected 0 active slots after final release, got %d", guard.ConcurrencyLimiter().Active())
	}
}
