package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/labib0x9/docpine/internal/middleware"
)

func TestRequestIDGeneratesAndPropagates(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.Use(middleware.RequestID())
	engine.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, middleware.GetRequestID(c))
	})

	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	generated := recorder.Header().Get(middleware.RequestIDHeader)
	if generated == "" {
		t.Fatal("missing request id header")
	}
	if recorder.Body.String() != generated {
		t.Fatalf("context id = %q; header = %q", recorder.Body.String(), generated)
	}
}

func TestRequestIDPreservesIncomingHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.Use(middleware.RequestID())
	engine.GET("/", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set(middleware.RequestIDHeader, "client-request-id")
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, request)
	if got := recorder.Header().Get(middleware.RequestIDHeader); got != "client-request-id" {
		t.Fatalf("request id = %q; want client-request-id", got)
	}
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d", recorder.Code)
	}
}
