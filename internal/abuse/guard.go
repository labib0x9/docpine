package abuse

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/labib0x9/docpine/internal/config"
	"github.com/labib0x9/docpine/jsonio"
)

// Guard coordinates the multi-layered abuse protection pipeline for anonymous sessions.
type Guard struct {
	cookieMgr      *DeviceCookieManager
	rateLimiter    *RateLimiter
	turnstile      *TurnstileValidator
	concurrency    *ConcurrencyLimiter
	mu             sync.Mutex
	deviceSessions map[string]string
	sessionDevices map[string]string
}

// NewGuard constructs a fully configured Guard.
func NewGuard(cfg config.Config) *Guard {
	return &Guard{
		cookieMgr:      NewDeviceCookieManager(cfg.Abuse.CookieSecret),
		rateLimiter:    NewRateLimiter(cfg.Abuse.RateBurst, cfg.Abuse.RateRefillRate),
		turnstile:      NewTurnstileValidator(cfg.Abuse.TurnstileSecret),
		concurrency:    NewConcurrencyLimiter(cfg.Session.MaxConcurrent),
		deviceSessions: make(map[string]string),
		sessionDevices: make(map[string]string),
	}
}

// CreateRequestPayload represents client-submitted abuse prevention tokens during session creation.
type CreateRequestPayload struct {
	TurnstileToken string `json:"cf-turnstile-response,omitempty"`
}

// ChallengeResponsePayload is returned when a client must solve a challenge before creation.
type ChallengeResponsePayload struct {
	Error             string `json:"error"`
	Message           string `json:"message"`
	TurnstileRequired bool   `json:"turnstile_required"`
}

// CheckAnonymousCreate evaluates all abuse layers for an incoming anonymous create request.
// Returns (proceed, deviceID, releaseSlotFunc).
func (g *Guard) CheckAnonymousCreate(w http.ResponseWriter, r *http.Request, payload *CreateRequestPayload) (bool, string, func()) {
	clientIP := GetClientIP(r)
	deviceID := g.cookieMgr.GetOrSet(w, r)

	if g.HasActiveDeviceSession(deviceID) {
		slog.Warn("Session create rejected: active session already exists for device",
			"client_ip", clientIP,
			"device_id", deviceID,
		)
		jsonio.SendJson(w, map[string]any{
			"error":   "device_session_active",
			"message": "An active sandbox session already exists for this device. Please wait until your current session expires or terminates.",
			"code":    http.StatusConflict,
		}, http.StatusConflict)
		return false, deviceID, nil
	}

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
		return false, deviceID, nil
	}

	slotReleased := false
	release := func() {
		if !slotReleased {
			slotReleased = true
			g.concurrency.Release()
		}
	}

	needsTurnstile := g.turnstile.IsEnabled()

	if needsTurnstile {
		token := ""
		if payload != nil {
			token = payload.TurnstileToken
		}

		if token == "" {
			release()
			g.sendChallengeResponse(w, "Cloudflare Turnstile verification required before creating a sandbox.")
			return false, deviceID, nil
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
			return false, deviceID, nil
		}
	}

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
		return false, deviceID, nil
	}

	slog.Info("Anonymous session create passed abuse protection checks",
		"client_ip", clientIP,
		"device_id", deviceID,
		"active_sandboxes", g.concurrency.Active(),
	)

	return true, deviceID, release
}

// HasActiveDeviceSession checks if a device currently has an active bound sandbox session.
func (g *Guard) HasActiveDeviceSession(deviceID string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	_, exists := g.deviceSessions[deviceID]
	return exists
}

// RegisterSession binds an active session ID to a device ID.
func (g *Guard) RegisterSession(deviceID, sessionID string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.deviceSessions[deviceID] = sessionID
	g.sessionDevices[sessionID] = deviceID
	slog.Info("Bound device to session", "device_id", deviceID, "session_id", sessionID)
}

// ReleaseSession unbinds an active session from its associated device.
func (g *Guard) ReleaseSession(sessionID string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if devID, exists := g.sessionDevices[sessionID]; exists {
		delete(g.deviceSessions, devID)
		delete(g.sessionDevices, sessionID)
		slog.Info("Released device session binding", "device_id", devID, "session_id", sessionID)
	}
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
