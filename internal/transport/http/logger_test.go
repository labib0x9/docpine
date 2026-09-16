package http_test

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	transporthttp "github.com/labib0x9/docpine/internal/transport/http"
)

func TestLoggerMiddleware(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	oldLogger := slog.Default()
	slog.SetDefault(logger)
	defer slog.SetDefault(oldLogger)

	handler := transporthttp.RequestId(transporthttp.Logger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("ok"))
	})))

	req := httptest.NewRequest(http.MethodPost, "/test-log", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d", rec.Code)
	}

	logOutput := buf.String()
	if !strings.Contains(logOutput, "method=POST") {
		t.Errorf("expected log to contain method=POST, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, "path=/test-log") {
		t.Errorf("expected log to contain path=/test-log, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, "status=201") {
		t.Errorf("expected log to contain status=201, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, "request_id=") {
		t.Errorf("expected log to contain request_id, got: %s", logOutput)
	}
}
