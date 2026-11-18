package middleware_test

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/labib0x9/docpine/internal/middleware"
)

func TestLoggerRecordsRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&output, nil)))
	defer slog.SetDefault(previous)

	engine := gin.New()
	engine.Use(middleware.RequestID(), middleware.Logger())
	engine.GET("/health", func(c *gin.Context) {
		c.String(http.StatusAccepted, "ok")
	})

	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/health", nil))
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d", recorder.Code)
	}
	logged := output.String()
	for _, want := range []string{"http request", "method=GET", "path=/health", "status=202"} {
		if !strings.Contains(logged, want) {
			t.Fatalf("log missing %q: %s", want, logged)
		}
	}
}
