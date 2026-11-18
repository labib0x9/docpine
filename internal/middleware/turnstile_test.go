package middleware_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/labib0x9/docpine/internal/abuse"
	"github.com/labib0x9/docpine/internal/middleware"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func turnstileEngine(validator *abuse.TurnstileValidator) *gin.Engine {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.Use(middleware.Turnstile(validator))
	engine.POST("/", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})
	return engine
}

func TestTurnstileDevBypass(t *testing.T) {
	recorder := httptest.NewRecorder()
	turnstileEngine(abuse.NewTurnstileValidator("")).ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/", nil))
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d; want 204", recorder.Code)
	}
}

func TestTurnstileRequiresToken(t *testing.T) {
	validator := abuse.NewTurnstileValidator("secret")
	recorder := httptest.NewRecorder()
	turnstileEngine(validator).ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/", nil))
	if recorder.Code != http.StatusPreconditionRequired {
		t.Fatalf("status = %d; want 428", recorder.Code)
	}
}

func TestTurnstileVerifiesToken(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if err := request.ParseForm(); err != nil {
			return nil, err
		}
		if request.PostForm.Get("secret") != "secret" || request.PostForm.Get("response") != "valid-token" {
			t.Fatalf("unexpected form: %v", request.PostForm)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"success":true}`)),
			Header:     make(http.Header),
		}, nil
	})}
	validator := abuse.NewTurnstileValidator("secret", client)

	request := httptest.NewRequest(http.MethodPost, "/", nil)
	request.Header.Set("CF-Turnstile-Response", "valid-token")
	request.Header.Set("CF-Connecting-IP", "203.0.113.7, 10.0.0.1")
	recorder := httptest.NewRecorder()
	turnstileEngine(validator).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d; want 204", recorder.Code)
	}
}

func TestTurnstileRejectsFailedVerification(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"success":false,"error-codes":["invalid-input-response"]}`)),
			Header:     make(http.Header),
		}, nil
	})}
	validator := abuse.NewTurnstileValidator("secret", client)

	request := httptest.NewRequest(http.MethodPost, "/?cf-turnstile-response=bad-token", nil)
	recorder := httptest.NewRecorder()
	turnstileEngine(validator).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400", recorder.Code)
	}
}
