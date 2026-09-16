package http_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	transporthttp "github.com/labib0x9/docpine/internal/transport/http"
)

func TestRequestIdMiddleware_GeneratesNewId(t *testing.T) {
	var capturedID string
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedID = transporthttp.GetRequestID(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler := transporthttp.RequestId(nextHandler)
	handler.ServeHTTP(rec, req)

	respHeaderID := rec.Header().Get("X-Request-Id")
	if respHeaderID == "" {
		t.Errorf("expected X-Request-Id header to be set in response")
	}
	if capturedID == "" {
		t.Errorf("expected request ID to be injected in request context")
	}
	if respHeaderID != capturedID {
		t.Errorf("expected response header ID (%s) to match context ID (%s)", respHeaderID, capturedID)
	}
}

func TestRequestIdMiddleware_PreservesExistingHeader(t *testing.T) {
	customID := "custom-req-id-12345"
	var capturedID string
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedID = transporthttp.GetRequestID(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Request-Id", customID)
	rec := httptest.NewRecorder()

	handler := transporthttp.RequestId(nextHandler)
	handler.ServeHTTP(rec, req)

	respHeaderID := rec.Header().Get("X-Request-Id")
	if respHeaderID != customID {
		t.Errorf("expected X-Request-Id %s, got %s", customID, respHeaderID)
	}
	if capturedID != customID {
		t.Errorf("expected context request ID %s, got %s", customID, capturedID)
	}
}
