package abuse

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGuard_EndToEnd(t *testing.T) {
	secret := []byte("guard-test-secret-32-byte-key-12")
	guard := NewGuard(GuardConfig{
		CookieSecret: secret,
		RateLimiter: RateLimiterConfig{
			Burst:      2,
			RefillRate: 1 * time.Second,
		},
		PoWDifficulty:      8, // fast for testing
		TurnstileSecretKey: "",
		MaxConcurrent:      2,
		RequirePoW:         true,
	})

	// 1. Initial request without PoW -> Returns 428 Precondition Required with PoW challenge
	req1 := httptest.NewRequest(http.MethodPost, "/sessions", nil)
	req1.Header.Set("CF-Connecting-IP", "203.0.113.10")
	w1 := httptest.NewRecorder()

	passed, release := guard.CheckAnonymousCreate(w1, req1, nil)
	if passed {
		t.Fatal("expected request without PoW solution to be challenged")
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
	if chalResp.PoWChallenge.Challenge == "" {
		t.Fatal("expected non-empty PoW challenge")
	}

	// 2. Solve the PoW challenge
	nonce := Solve(chalResp.PoWChallenge.Challenge, chalResp.PoWChallenge.Salt, chalResp.PoWChallenge.Difficulty)
	sol := &PoWSolution{
		Challenge:  chalResp.PoWChallenge.Challenge,
		Salt:       chalResp.PoWChallenge.Salt,
		Difficulty: chalResp.PoWChallenge.Difficulty,
		ExpiresAt:  chalResp.PoWChallenge.ExpiresAt,
		Signature:  chalResp.PoWChallenge.Signature,
		Nonce:      nonce,
	}

	req2 := httptest.NewRequest(http.MethodPost, "/sessions", nil)
	req2.Header.Set("CF-Connecting-IP", "203.0.113.10")
	// Carry forward the device cookie from w1
	for _, c := range w1.Result().Cookies() {
		req2.AddCookie(c)
	}
	w2 := httptest.NewRecorder()

	passed2, release2 := guard.CheckAnonymousCreate(w2, req2, &CreateRequestPayload{PoWSolution: sol})
	if !passed2 {
		t.Fatalf("expected request with valid PoW to pass, status %d body %s", w2.Code, w2.Body.String())
	}
	if guard.ConcurrencyLimiter().Active() != 1 {
		t.Fatalf("expected 1 active slot, got %d", guard.ConcurrencyLimiter().Active())
	}

	// 3. Second valid request on same client
	chal2 := guard.IssuePoWChallenge()
	nonce2 := Solve(chal2.Challenge, chal2.Salt, chal2.Difficulty)
	sol2 := &PoWSolution{
		Challenge:  chal2.Challenge,
		Salt:       chal2.Salt,
		Difficulty: chal2.Difficulty,
		ExpiresAt:  chal2.ExpiresAt,
		Signature:  chal2.Signature,
		Nonce:      nonce2,
	}

	req3 := httptest.NewRequest(http.MethodPost, "/sessions", nil)
	req3.Header.Set("CF-Connecting-IP", "203.0.113.10")
	for _, c := range w1.Result().Cookies() {
		req3.AddCookie(c)
	}
	w3 := httptest.NewRecorder()

	passed3, release3 := guard.CheckAnonymousCreate(w3, req3, &CreateRequestPayload{PoWSolution: sol2})
	if !passed3 {
		t.Fatalf("expected second request to pass, status %d body %s", w3.Code, w3.Body.String())
	}
	if guard.ConcurrencyLimiter().Active() != 2 {
		t.Fatalf("expected 2 active slots, got %d", guard.ConcurrencyLimiter().Active())
	}

	// 4. Concurrency Cap Exceeded (Max is 2)
	chal3 := guard.IssuePoWChallenge()
	nonce3 := Solve(chal3.Challenge, chal3.Salt, chal3.Difficulty)
	sol3 := &PoWSolution{
		Challenge:  chal3.Challenge,
		Salt:       chal3.Salt,
		Difficulty: chal3.Difficulty,
		ExpiresAt:  chal3.ExpiresAt,
		Signature:  chal3.Signature,
		Nonce:      nonce3,
	}

	req4 := httptest.NewRequest(http.MethodPost, "/sessions", nil)
	req4.Header.Set("CF-Connecting-IP", "198.51.100.99") // different IP
	w4 := httptest.NewRecorder()

	passed4, _ := guard.CheckAnonymousCreate(w4, req4, &CreateRequestPayload{PoWSolution: sol3})
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
