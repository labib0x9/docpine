package abuse

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/labib0x9/docpine/internal/config"
	"github.com/labib0x9/docpine/jsonio"
)

// Guard coordinates the multi-layered abuse protection pipeline for anonymous sessions.
type Guard struct {
	cookieMgr   *DeviceCookieManager
	rateLimiter *RateLimiter
	turnstile   *TurnstileValidator
	concurrency *ConcurrencyLimiter
}

// NewGuard constructs a fully configured Guard.
func NewGuard(cfg config.Config) *Guard {
	return &Guard{
		cookieMgr:   NewDeviceCookieManager(cfg.Abuse.CookieSecret),
		rateLimiter: NewRateLimiter(cfg.Abuse.RateBurst, cfg.Abuse.RateRefillRate),
		turnstile:   NewTurnstileValidator(cfg.Abuse.TurnstileSecret),
		concurrency: NewConcurrencyLimiter(cfg.Session.MaxConcurrent),
	}
}

// CreateRequestPayload represents client-submitted abuse prevention tokens during session creation.
type CreateRequestPayload struct {
	TurnstileToken string `json:"turnstile_token,omitempty"`
}

// ChallengeResponsePayload is returned when a client must solve a challenge before creation.
type ChallengeResponsePayload struct {
	Error             string `json:"error"`
	Message           string `json:"message"`
	TurnstileRequired bool   `json:"turnstile_required"`
}

// CheckAnonymousCreate evaluates all abuse layers for an incoming anonymous create request.
// Returns (proceed, releaseSlotFunc).
func (g *Guard) CheckAnonymousCreate(w http.ResponseWriter, r *http.Request, payload *CreateRequestPayload) (bool, func()) {
	clientIP := GetClientIP(r)
	deviceID := g.cookieMgr.GetOrSet(w, r)

	// Layer 6: Global Concurrency Cap (Hard Backstop against Aggregate Host Load)
	if !g.concurrency.TryAcquire() {
		slog.Warn("Session create rejected: aggregate capacity exhausted",
			"client_ip", clientIP,
			"device_id", deviceID,
			"active", g.concurrency.Active(),
			"max", g.concurrency.Max(),
		)
		w.Header().Set("Retry-After", "30")
		jsonio.SendJson(w, map[string]any{
			"error":   "global_capacity_reached",
			"message": "Docpine sandbox host capacity is temporarily full. Please retry in a few moments.",
			"code":    http.StatusServiceUnavailable,
		}, http.StatusServiceUnavailable)
		return false, nil
	}

	// Slot acquired - ensure it gets released if any subsequent check fails
	slotReleased := false
	release := func() {
		if !slotReleased {
			slotReleased = true
			g.concurrency.Release()
		}
	}

	// Layer 4 & 5: Cloudflare Turnstile Challenge Verification
	needsTurnstile := g.turnstile.IsEnabled()

	// Check Turnstile token if configured
	if needsTurnstile {
		token := ""
		if payload != nil {
			token = payload.TurnstileToken
		}
		if token == "" {
			token = r.Header.Get("CF-Turnstile-Response")
		}

		if token == "" {
			release()
			g.sendChallengeResponse(w, "Cloudflare Turnstile verification required before creating a sandbox.")
			return false, nil
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		if err := g.turnstile.Verify(ctx, token, clientIP); err != nil {
			release()
			slog.Warn("Session create Turnstile verification failed",
				"client_ip", clientIP,
				"device_id", deviceID,
				"error", err,
			)
			g.sendChallengeResponse(w, fmt.Sprintf("Cloudflare Turnstile verification failed: %v", err))
			return false, nil
		}
	}

	// Layer 1-3: Per-IP + Signed Device Cookie Token Bucket Rate Limiting (Single Abusive Client Defense)
	allowed, retryAfter := g.rateLimiter.Allow(clientIP, deviceID)
	if !allowed {
		release()
		retrySec := int(retryAfter.Seconds())
		if retrySec <= 0 {
			retrySec = 1
		}
		slog.Warn("Session create throttled: per-client rate limit exceeded",
			"client_ip", clientIP,
			"device_id", deviceID,
			"retry_after_sec", retrySec,
		)
		w.Header().Set("Retry-After", fmt.Sprintf("%d", retrySec))
		jsonio.SendJson(w, map[string]any{
			"error":       "rate_limited",
			"message":     "Too many session creation requests. Please slow down.",
			"retry_after": retrySec,
			"code":        http.StatusTooManyRequests,
		}, http.StatusTooManyRequests)
		return false, nil
	}

	slog.Info("Anonymous session create passed abuse protection checks",
		"client_ip", clientIP,
		"device_id", deviceID,
		"active_sandboxes", g.concurrency.Active(),
	)

	return true, release
}

// ConcurrencyLimiter returns the concurrency limiter.
func (g *Guard) ConcurrencyLimiter() *ConcurrencyLimiter {
	return g.concurrency
}

func (g *Guard) sendChallengeResponse(w http.ResponseWriter, message string) {
	resp := ChallengeResponsePayload{
		Error:             "challenge_required",
		Message:           message,
		TurnstileRequired: g.turnstile.IsEnabled(),
	}
	jsonio.SendJson(w, resp, http.StatusPreconditionRequired)
}
