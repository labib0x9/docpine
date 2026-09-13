package abuse

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	ErrTurnstileFailed = errors.New("cloudflare turnstile verification failed")
	ErrTurnstileMissing = errors.New("turnstile token is required")
)

const turnstileVerifyEndpoint = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

// TurnstileResponse represents the verification response from Cloudflare.
type TurnstileResponse struct {
	Success     bool     `json:"success"`
	ChallengeTS string   `json:"challenge_ts"`
	Hostname    string   `json:"hostname"`
	ErrorCodes  []string `json:"error-codes"`
	Action      string   `json:"action"`
	Cdata       string   `json:"cdata"`
}

// TurnstileValidator verifies Turnstile tokens with Cloudflare's siteverify API.
type TurnstileValidator struct {
	secretKey  string
	httpClient *http.Client
}

// NewTurnstileValidator creates a validator. If secretKey is empty, dev bypass is enabled.
func NewTurnstileValidator(secretKey string, httpClient ...*http.Client) *TurnstileValidator {
	client := &http.Client{Timeout: 5 * time.Second}
	if len(httpClient) > 0 && httpClient[0] != nil {
		client = httpClient[0]
	}
	return &TurnstileValidator{
		secretKey:  strings.TrimSpace(secretKey),
		httpClient: client,
	}
}

// IsEnabled returns true if a Turnstile secret key is configured.
func (v *TurnstileValidator) IsEnabled() bool {
	return v.secretKey != ""
}

// Verify validates a Turnstile token submitted by the client.
func (v *TurnstileValidator) Verify(ctx context.Context, token, clientIP string) error {
	// If secret key is not set, allow in development mode with log
	if !v.IsEnabled() {
		slog.Debug("Turnstile validation skipped: DOCPINE_TURNSTILE_SECRET not configured")
		return nil
	}

	if token == "" {
		return ErrTurnstileMissing
	}

	// Support Cloudflare test dummy tokens
	if token == "1x0000000000000000000000000000000AA" {
		return nil
	}
	if token == "2x0000000000000000000000000000000AA" {
		return fmt.Errorf("%w: test token always-fail", ErrTurnstileFailed)
	}

	form := url.Values{
		"secret":   {v.secretKey},
		"response": {token},
	}
	if clientIP != "" {
		form.Set("remoteip", clientIP)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, turnstileVerifyEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create turnstile verify request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("turnstile verification request failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read turnstile response: %w", err)
	}

	var res TurnstileResponse
	if err := json.Unmarshal(bodyBytes, &res); err != nil {
		return fmt.Errorf("failed to parse turnstile response: %w", err)
	}

	if !res.Success {
		return fmt.Errorf("%w: %v", ErrTurnstileFailed, res.ErrorCodes)
	}

	return nil
}
