package http

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labib0x9/docpine/internal/abuse"
	"github.com/labib0x9/docpine/internal/runtime"
	"github.com/labib0x9/docpine/internal/session"
)

type mockTransportSandbox struct {
	id string
}

func (m *mockTransportSandbox) ID() string {
	return m.id
}

func (m *mockTransportSandbox) AttachPTY(ctx context.Context) (io.ReadWriteCloser, error) {
	return nil, nil
}

func (m *mockTransportSandbox) Destroy(ctx context.Context) error {
	return nil
}

type mockTransportRuntime struct{}

func (m *mockTransportRuntime) Name() string {
	return "mock"
}

func (m *mockTransportRuntime) CheckPrerequisites(ctx context.Context) error {
	return nil
}

func (m *mockTransportRuntime) CreateSandbox(ctx context.Context, opts runtime.SandboxOptions) (runtime.Sandbox, error) {
	return &mockTransportSandbox{id: "sb-" + opts.SessionID}, nil
}

func (m *mockTransportRuntime) Close() error {
	return nil
}

func TestSessionHandler_CreateAndHealth(t *testing.T) {
	rt := &mockTransportRuntime{}
	mngr := session.NewManager(rt, 1*time.Minute)
	defer mngr.Close(context.Background())

	guard := abuse.NewGuard(abuse.GuardConfig{
		CookieSecret: []byte("test-transport-secret-32-byte-12"),
		RateLimiter: abuse.RateLimiterConfig{
			Burst:      5,
			RefillRate: 1 * time.Second,
		},
		PoWDifficulty:      8,
		TurnstileSecretKey: "",
		MaxConcurrent:      10,
		RequirePoW:         false,
	})

	handler := NewSessionHandler(mngr, guard)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	// 1. Health check
	reqHealth := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	wHealth := httptest.NewRecorder()
	mux.ServeHTTP(wHealth, reqHealth)

	if wHealth.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 for healthz, got %d", wHealth.Code)
	}

	// 2. PoW challenge fetch
	reqPoW := httptest.NewRequest(http.MethodGet, "/challenges/pow", nil)
	wPoW := httptest.NewRecorder()
	mux.ServeHTTP(wPoW, reqPoW)

	if wPoW.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 for /challenges/pow, got %d", wPoW.Code)
	}

	var chal abuse.PoWChallenge
	if err := json.Unmarshal(wPoW.Body.Bytes(), &chal); err != nil {
		t.Fatalf("failed to parse PoW challenge response: %v", err)
	}
	if chal.Challenge == "" {
		t.Fatal("expected non-empty challenge")
	}

	// 3. Create session
	reqCreate := httptest.NewRequest(http.MethodPost, "/sessions", strings.NewReader(`{}`))
	reqCreate.Header.Set("CF-Connecting-IP", "203.0.113.88")
	wCreate := httptest.NewRecorder()
	mux.ServeHTTP(wCreate, reqCreate)

	if wCreate.Code != http.StatusCreated {
		t.Fatalf("expected HTTP 201 for session create, got %d (body: %s)", wCreate.Code, wCreate.Body.String())
	}

	var createResp map[string]any
	if err := json.Unmarshal(wCreate.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("failed to decode create response: %v", err)
	}

	sessionID, ok := createResp["session_id"].(string)
	if !ok || sessionID == "" {
		t.Fatalf("expected session_id in response, got %v", createResp)
	}
}
