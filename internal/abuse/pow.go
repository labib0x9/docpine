package abuse

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"
)

var (
	ErrPoWExpired   = errors.New("proof-of-work challenge has expired")
	ErrPoWTampered  = errors.New("proof-of-work challenge signature invalid")
	ErrPoWInvalid   = errors.New("proof-of-work solution does not meet difficulty")
	ErrPoWReplayed  = errors.New("proof-of-work solution already used (replay detected)")
)

// PoWChallenge represents the payload issued to the client.
type PoWChallenge struct {
	Challenge  string `json:"challenge"`
	Salt       string `json:"salt"`
	Difficulty int    `json:"difficulty"` // number of leading zero bits required
	ExpiresAt  int64  `json:"expires_at"` // Unix timestamp in seconds
	Signature  string `json:"signature"`
}

// PoWSolution represents the client's answer.
type PoWSolution struct {
	Challenge  string `json:"challenge"`
	Salt       string `json:"salt"`
	Difficulty int    `json:"difficulty"`
	ExpiresAt  int64  `json:"expires_at"`
	Signature  string `json:"signature"`
	Nonce      string `json:"nonce"`
}

// PoWEngine manages generation, signing, and O(1) verification of Proof-of-Work puzzles.
type PoWEngine struct {
	secret         []byte
	difficulty     int
	ttl            time.Duration
	mu             sync.Mutex
	consumedNonces map[string]time.Time
}

// NewPoWEngine constructs a new Proof-of-Work engine.
func NewPoWEngine(secret []byte, defaultDifficulty int) *PoWEngine {
	if len(secret) == 0 {
		secret = []byte("docpine-pow-default-secret-32-byte-key")
	}
	if defaultDifficulty <= 0 {
		defaultDifficulty = 16 // 16 bits = 2 leading 0x00 bytes (~65k SHA256 hashes, ~10-50ms in JS)
	}

	engine := &PoWEngine{
		secret:         secret,
		difficulty:     defaultDifficulty,
		ttl:            60 * time.Second,
		consumedNonces: make(map[string]time.Time),
	}

	go engine.evictExpiredNonces()
	return engine
}

// sign creates an HMAC-SHA256 signature for a challenge tuple.
func (p *PoWEngine) sign(challenge, salt string, difficulty int, expiresAt int64) string {
	payload := fmt.Sprintf("%s|%s|%d|%d", challenge, salt, difficulty, expiresAt)
	mac := hmac.New(sha256.New, p.secret)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// GenerateChallenge creates a fresh, signed Proof-of-Work challenge.
func (p *PoWEngine) GenerateChallenge() PoWChallenge {
	challengeBytes := make([]byte, 16)
	saltBytes := make([]byte, 8)
	_, _ = rand.Read(challengeBytes)
	_, _ = rand.Read(saltBytes)

	challenge := hex.EncodeToString(challengeBytes)
	salt := hex.EncodeToString(saltBytes)
	expiresAt := time.Now().Add(p.ttl).Unix()

	sig := p.sign(challenge, salt, p.difficulty, expiresAt)

	return PoWChallenge{
		Challenge:  challenge,
		Salt:       salt,
		Difficulty: p.difficulty,
		ExpiresAt:  expiresAt,
		Signature:  sig,
	}
}

// Verify validates a client's solution in O(1) time.
func (p *PoWEngine) Verify(sol PoWSolution) error {
	now := time.Now().Unix()
	if now > sol.ExpiresAt {
		return ErrPoWExpired
	}

	// 1. Verify signature authenticity
	expectedSig := p.sign(sol.Challenge, sol.Salt, sol.Difficulty, sol.ExpiresAt)
	if !hmac.Equal([]byte(sol.Signature), []byte(expectedSig)) {
		return ErrPoWTampered
	}

	// 2. Prevent replay attacks
	nonceKey := fmt.Sprintf("%s:%s:%s", sol.Challenge, sol.Salt, sol.Nonce)
	p.mu.Lock()
	if _, used := p.consumedNonces[nonceKey]; used {
		p.mu.Unlock()
		return ErrPoWReplayed
	}
	p.consumedNonces[nonceKey] = time.Unix(sol.ExpiresAt, 0)
	p.mu.Unlock()

	// 3. Verify hash meets leading zero bits requirement
	hasher := sha256.New()
	hasher.Write([]byte(sol.Challenge))
	hasher.Write([]byte(sol.Salt))
	hasher.Write([]byte(sol.Nonce))
	hash := hasher.Sum(nil)

	if !hasLeadingZeroBits(hash, sol.Difficulty) {
		return ErrPoWInvalid
	}

	return nil
}

// Solve is a helper to solve a challenge (used by tests or clients).
func Solve(challenge, salt string, difficulty int) string {
	var nonce uint64
	for {
		nonceStr := strconv.FormatUint(nonce, 10)
		hasher := sha256.New()
		hasher.Write([]byte(challenge))
		hasher.Write([]byte(salt))
		hasher.Write([]byte(nonceStr))
		hash := hasher.Sum(nil)

		if hasLeadingZeroBits(hash, difficulty) {
			return nonceStr
		}
		nonce++
	}
}

// hasLeadingZeroBits checks whether the byte slice begins with at least `bitsRequired` zero bits.
func hasLeadingZeroBits(hash []byte, bitsRequired int) bool {
	if bitsRequired <= 0 {
		return true
	}
	if bitsRequired > len(hash)*8 {
		return false
	}

	fullBytes := bitsRequired / 8
	remainingBits := bitsRequired % 8

	for i := 0; i < fullBytes; i++ {
		if hash[i] != 0 {
			return false
		}
	}

	if remainingBits > 0 {
		mask := byte(0xFF << (8 - remainingBits))
		if (hash[fullBytes] & mask) != 0 {
			return false
		}
	}

	return true
}

func (p *PoWEngine) evictExpiredNonces() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		p.mu.Lock()
		now := time.Now()
		for k, exp := range p.consumedNonces {
			if now.After(exp) {
				delete(p.consumedNonces, k)
			}
		}
		p.mu.Unlock()
	}
}
