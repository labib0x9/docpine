package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/labib0x9/docpine/internal/middleware"
)

func newCorsEngine(origins []string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.Use(middleware.Cors(origins))
	engine.GET("/", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	return engine
}

func TestCorsAllowsConfiguredOrigin(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Origin", "https://example.com")
	recorder := httptest.NewRecorder()
	newCorsEngine([]string{" https://example.com "}).ServeHTTP(recorder, request)

	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "https://example.com" {
		t.Fatalf("allow origin = %q", got)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("allow credentials = %q", got)
	}
	if got := recorder.Header().Get("Vary"); got != "Origin" {
		t.Fatalf("vary = %q", got)
	}
}

func TestCorsRejectsUnknownOrigin(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Origin", "https://evil.example")
	recorder := httptest.NewRecorder()
	newCorsEngine([]string{"https://example.com"}).ServeHTTP(recorder, request)

	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("allow origin = %q; want empty", got)
	}
}

func TestCorsHandlesPreflight(t *testing.T) {
	request := httptest.NewRequest(http.MethodOptions, "/", nil)
	request.Header.Set("Origin", "https://example.com")
	recorder := httptest.NewRecorder()
	newCorsEngine([]string{"https://example.com"}).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d; want 204", recorder.Code)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Methods"); got == "" {
		t.Fatal("missing allow methods")
	}
}
