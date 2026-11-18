package abuse

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type verifyRoundTripper func(*http.Request) (*http.Response, error)

func (f verifyRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func turnstileResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

func TestTurnstileValidator(t *testing.T) {
	ctx := context.Background()

	devValidator := NewTurnstileValidator("")
	if devValidator.IsEnabled() {
		t.Fatal("empty secret should disable validation")
	}
	if err := devValidator.Verify(ctx, "", "198.51.100.1"); err != nil {
		t.Fatalf("dev bypass failed: %v", err)
	}

	passValidator := NewTurnstileValidator("secret", &http.Client{Transport: verifyRoundTripper(func(request *http.Request) (*http.Response, error) {
		if err := request.ParseForm(); err != nil {
			return nil, err
		}
		if request.PostForm.Get("secret") != "secret" || request.PostForm.Get("response") != "pass" || request.PostForm.Get("remoteip") != "198.51.100.1" {
			t.Fatalf("unexpected verification form: %v", request.PostForm)
		}
		return turnstileResponse(`{"success":true}`), nil
	})})
	if err := passValidator.Verify(ctx, "pass", "198.51.100.1"); err != nil {
		t.Fatalf("valid token failed: %v", err)
	}
	if err := passValidator.Verify(ctx, "", "198.51.100.1"); !errors.Is(err, ErrTurnstileMissing) {
		t.Fatalf("missing token error = %v; want ErrTurnstileMissing", err)
	}

	failValidator := NewTurnstileValidator("secret", &http.Client{Transport: verifyRoundTripper(func(request *http.Request) (*http.Response, error) {
		return turnstileResponse(`{"success":false,"error-codes":["invalid-input-response"]}`), nil
	})})
	if err := failValidator.Verify(ctx, "bad", "198.51.100.1"); !errors.Is(err, ErrTurnstileFailed) {
		t.Fatalf("failed token error = %v; want ErrTurnstileFailed", err)
	}
}
