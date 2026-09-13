package abuse

import (
	"testing"
	"time"
)

func TestPoWEngine(t *testing.T) {
	secret := []byte("test-pow-secret-key-1234567890")
	// Use difficulty = 8 for fast unit testing (1 full zero byte)
	engine := NewPoWEngine(secret, 8)

	// 1. Generate challenge
	chal := engine.GenerateChallenge()
	if chal.Challenge == "" || chal.Signature == "" {
		t.Fatal("expected non-empty challenge and signature")
	}

	// 2. Solve challenge
	nonce := Solve(chal.Challenge, chal.Salt, chal.Difficulty)
	sol := PoWSolution{
		Challenge:  chal.Challenge,
		Salt:       chal.Salt,
		Difficulty: chal.Difficulty,
		ExpiresAt:  chal.ExpiresAt,
		Signature:  chal.Signature,
		Nonce:      nonce,
	}

	// 3. Verify valid solution
	if err := engine.Verify(sol); err != nil {
		t.Fatalf("expected valid PoW solution, got error: %v", err)
	}

	// 4. Replay attack prevention -> should fail
	if err := engine.Verify(sol); err != ErrPoWReplayed {
		t.Fatalf("expected ErrPoWReplayed on replay, got: %v", err)
	}

	// 5. Tampered signature -> should fail
	solTampered := sol
	solTampered.Signature = "badsignature"
	solTampered.Nonce = "differentnonce"
	if err := engine.Verify(solTampered); err != ErrPoWTampered {
		t.Fatalf("expected ErrPoWTampered on invalid signature, got: %v", err)
	}

	// 6. Expired challenge -> should fail
	solExpired := sol
	solExpired.ExpiresAt = time.Now().Add(-10 * time.Second).Unix()
	if err := engine.Verify(solExpired); err != ErrPoWExpired {
		t.Fatalf("expected ErrPoWExpired on expired challenge, got: %v", err)
	}
}
