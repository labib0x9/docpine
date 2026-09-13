package config

import (
	"os"
	"testing"
	"time"
)

func TestConfig_LoadDefaults(t *testing.T) {
	cfg := LoadFromEnv()

	if cfg.Addr != ":8080" {
		t.Fatalf("expected default addr :8080, got %s", cfg.Addr)
	}
	if cfg.RuntimeName != "docker" {
		t.Fatalf("expected default runtime 'docker', got %s", cfg.RuntimeName)
	}
	if cfg.SessionTTL != 5*time.Minute {
		t.Fatalf("expected default TTL 5m, got %v", cfg.SessionTTL)
	}
	if cfg.MaxConcurrent != 20 {
		t.Fatalf("expected default max concurrent 20, got %d", cfg.MaxConcurrent)
	}
	if cfg.PoWDifficulty != 16 {
		t.Fatalf("expected default PoW difficulty 16, got %d", cfg.PoWDifficulty)
	}
	if len(cfg.CookieSecret) == 0 {
		t.Fatal("expected auto-generated cookie secret")
	}
}

func TestConfig_CustomEnv(t *testing.T) {
	os.Setenv("DOCPINE_RUNTIME", "gvisor")
	os.Setenv("DOCPINE_PORT", "9090")
	os.Setenv("DOCPINE_SESSION_TTL", "10m")
	os.Setenv("DOCPINE_MAX_SESSIONS", "50")
	os.Setenv("DOCPINE_POW_DIFFICULTY", "20")
	os.Setenv("DOCPINE_REQUIRE_POW", "true")
	defer func() {
		os.Unsetenv("DOCPINE_RUNTIME")
		os.Unsetenv("DOCPINE_PORT")
		os.Unsetenv("DOCPINE_SESSION_TTL")
		os.Unsetenv("DOCPINE_MAX_SESSIONS")
		os.Unsetenv("DOCPINE_POW_DIFFICULTY")
		os.Unsetenv("DOCPINE_REQUIRE_POW")
	}()

	cfg := LoadFromEnv()

	if cfg.RuntimeName != "gvisor" {
		t.Fatalf("expected runtime gvisor, got %s", cfg.RuntimeName)
	}
	if cfg.Addr != ":9090" {
		t.Fatalf("expected addr :9090, got %s", cfg.Addr)
	}
	if cfg.SessionTTL != 10*time.Minute {
		t.Fatalf("expected TTL 10m, got %v", cfg.SessionTTL)
	}
	if cfg.MaxConcurrent != 50 {
		t.Fatalf("expected max concurrent 50, got %d", cfg.MaxConcurrent)
	}
	if cfg.PoWDifficulty != 20 {
		t.Fatalf("expected PoW difficulty 20, got %d", cfg.PoWDifficulty)
	}
	if !cfg.RequirePoW {
		t.Fatal("expected RequirePoW to be true")
	}
}
