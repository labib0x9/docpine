package session

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/labib0x9/docpine/internal/runtime"
)

type mockSandbox struct {
	id        string
	destroyed bool
	mu        sync.Mutex
}

func (m *mockSandbox) ID() string {
	return m.id
}

func (m *mockSandbox) CgroupID() (uint64, error) {
	return 2000, nil
}

func (m *mockSandbox) AttachPTY(ctx context.Context) (io.ReadWriteCloser, error) {
	return nil, nil
}

func (m *mockSandbox) Destroy(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.destroyed = true
	return nil
}

type mockRuntime struct {
	mu        sync.Mutex
	sandboxes map[string]*mockSandbox
}

func (m *mockRuntime) Name() string {
	return "mock"
}

func (m *mockRuntime) CheckPrerequisites(ctx context.Context) error {
	return nil
}

func (m *mockRuntime) CreateSandbox(ctx context.Context, opts runtime.SandboxOptions) (runtime.Sandbox, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sb := &mockSandbox{id: "sb-" + opts.SessionID}
	m.sandboxes[opts.SessionID] = sb
	return sb, nil
}

func (m *mockRuntime) Close() error {
	return nil
}

func TestSessionManager_Lifecycle(t *testing.T) {
	ctx := context.Background()
	rt := &mockRuntime{sandboxes: make(map[string]*mockSandbox)}
	mngr := NewManager(rt, 1*time.Minute)
	defer mngr.Close(ctx)

	// Create session
	sessionID, err := mngr.Create(ctx)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	if sessionID == "" {
		t.Fatal("expected non-empty session ID")
	}

	if count := mngr.ActiveCount(); count != 1 {
		t.Fatalf("expected 1 active session, got %d", count)
	}

	// Retrieve session
	sess, err := mngr.Get(sessionID)
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	if sess.ID != sessionID {
		t.Fatalf("expected session ID %s, got %s", sessionID, sess.ID)
	}

	// Destroy session
	if err := mngr.Destroy(ctx, sessionID); err != nil {
		t.Fatalf("failed to destroy session: %v", err)
	}

	if count := mngr.ActiveCount(); count != 0 {
		t.Fatalf("expected 0 active sessions after destroy, got %d", count)
	}

	// Verify sandbox was destroyed
	rt.mu.Lock()
	sb := rt.sandboxes[sessionID]
	rt.mu.Unlock()
	if sb == nil || !sb.destroyed {
		t.Fatal("expected sandbox to be destroyed")
	}
}

func TestSessionManager_TTLExpiration(t *testing.T) {
	ctx := context.Background()
	rt := &mockRuntime{sandboxes: make(map[string]*mockSandbox)}
	// Set very short TTL (50ms)
	mngr := NewManager(rt, 50*time.Millisecond)
	defer mngr.Close(ctx)

	sessionID, err := mngr.Create(ctx)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// Wait for TTL to pass
	time.Sleep(100 * time.Millisecond)

	// Get should report expired
	_, err = mngr.Get(sessionID)
	if err != ErrSessionExpired {
		t.Fatalf("expected ErrSessionExpired, got: %v", err)
	}

	// Attach should report expired
	_, err = mngr.Attach(ctx, sessionID)
	if err != ErrSessionExpired {
		t.Fatalf("expected ErrSessionExpired on attach, got: %v", err)
	}
}
