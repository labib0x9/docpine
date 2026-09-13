package config

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"strconv"
	"time"

	"github.com/labib0x9/docpine/internal/abuse"
	"github.com/labib0x9/docpine/internal/runtime"
)

// AppConfig represents global configuration loaded from environment variables.
type AppConfig struct {
	Addr           string
	RuntimeName    string
	SessionTTL     time.Duration
	MaxConcurrent  int
	RequirePoW     bool
	PoWDifficulty  int
	TurnstileKey   string
	CookieSecret   []byte
	RateBurst      int
	RateRefillRate time.Duration
	Runtime        runtime.Config
}

// LoadFromEnv loads configuration from environment variables with production-ready defaults.
func LoadFromEnv() *AppConfig {
	addr := getEnv("DOCPINE_ADDR", ":8080")
	if port := os.Getenv("DOCPINE_PORT"); port != "" {
		addr = ":" + port
	}

	runtimeName := getEnv("DOCPINE_RUNTIME", "docker")

	ttl := 5 * time.Minute
	if ttlStr := os.Getenv("DOCPINE_SESSION_TTL"); ttlStr != "" {
		if parsed, err := time.ParseDuration(ttlStr); err == nil {
			ttl = parsed
		}
	}

	maxConcurrent := getEnvInt("DOCPINE_MAX_SESSIONS", 20)
	powDifficulty := getEnvInt("DOCPINE_POW_DIFFICULTY", 16)
	requirePoW := os.Getenv("DOCPINE_REQUIRE_POW") == "true" || os.Getenv("DOCPINE_REQUIRE_POW") == "1"
	turnstileKey := os.Getenv("DOCPINE_TURNSTILE_SECRET")

	var cookieSecret []byte
	if secretStr := os.Getenv("DOCPINE_COOKIE_SECRET"); secretStr != "" {
		cookieSecret = []byte(secretStr)
	} else {
		// Auto-generate ephemeral 32-byte secret if not provided
		randomBytes := make([]byte, 32)
		_, _ = rand.Read(randomBytes)
		cookieSecret = []byte(hex.EncodeToString(randomBytes))
	}

	rateBurst := getEnvInt("DOCPINE_RATE_LIMIT_BURST", 5)
	rateRefill := 30 * time.Second
	if refillStr := os.Getenv("DOCPINE_RATE_LIMIT_REFILL"); refillStr != "" {
		if parsed, err := time.ParseDuration(refillStr); err == nil {
			rateRefill = parsed
		}
	}

	memLimit := getEnvInt64("DOCPINE_SANDBOX_MEMORY", 128*1024*1024) // 128MB default

	return &AppConfig{
		Addr:           addr,
		RuntimeName:    runtimeName,
		SessionTTL:     ttl,
		MaxConcurrent:  maxConcurrent,
		RequirePoW:     requirePoW,
		PoWDifficulty:  powDifficulty,
		TurnstileKey:   turnstileKey,
		CookieSecret:   cookieSecret,
		RateBurst:      rateBurst,
		RateRefillRate: rateRefill,
		Runtime: runtime.Config{
			Image:          getEnv("DOCPINE_IMAGE", "alpine:3.20"),
			NetworkMode:    getEnv("DOCPINE_NETWORK_MODE", "none"),
			MemoryLimit:    memLimit,
			RunscPath:      getEnv("DOCPINE_RUNSC_PATH", "runsc"),
			FirecrackerBin: getEnv("DOCPINE_FIRECRACKER_BIN", "firecracker"),
			KernelPath:     getEnv("DOCPINE_KERNEL_PATH", "/var/lib/docpine/vmlinux"),
			RootFSPath:     getEnv("DOCPINE_ROOTFS_PATH", "/var/lib/docpine/rootfs.ext4"),
		},
	}
}

// ToGuardConfig transforms AppConfig into abuse GuardConfig.
func (c *AppConfig) ToGuardConfig() abuse.GuardConfig {
	return abuse.GuardConfig{
		CookieSecret: c.CookieSecret,
		RateLimiter: abuse.RateLimiterConfig{
			Burst:      c.RateBurst,
			RefillRate: c.RateRefillRate,
		},
		PoWDifficulty:      c.PoWDifficulty,
		TurnstileSecretKey: c.TurnstileKey,
		MaxConcurrent:      c.MaxConcurrent,
		RequirePoW:         c.RequirePoW,
	}
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func getEnvInt(key string, defaultVal int) int {
	if val := os.Getenv(key); val != "" {
		if n, err := strconv.Atoi(val); err == nil {
			return n
		}
	}
	return defaultVal
}

func getEnvInt64(key string, defaultVal int64) int64 {
	if val := os.Getenv(key); val != "" {
		if n, err := strconv.ParseInt(val, 10, 64); err == nil {
			return n
		}
	}
	return defaultVal
}
