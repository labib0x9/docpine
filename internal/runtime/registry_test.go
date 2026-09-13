package runtime

import (
	"context"
	"errors"
	"io"
	"testing"
)

type mockSandbox struct {
	id        string
	destroyed bool
}

func (m *mockSandbox) ID() string {
	return m.id
}

func (m *mockSandbox) AttachPTY(ctx context.Context) (io.ReadWriteCloser, error) {
	return nil, nil
}

func (m *mockSandbox) Destroy(ctx context.Context) error {
	m.destroyed = true
	return nil
}

type mockRuntime struct {
	name        string
	prereqErr   error
	sandboxes   map[string]*mockSandbox
	closedCalls int
}

func (m *mockRuntime) Name() string {
	return m.name
}

func (m *mockRuntime) CheckPrerequisites(ctx context.Context) error {
	return m.prereqErr
}

func (m *mockRuntime) CreateSandbox(ctx context.Context, opts SandboxOptions) (Sandbox, error) {
	sb := &mockSandbox{id: opts.SessionID}
	m.sandboxes[opts.SessionID] = sb
	return sb, nil
}

func (m *mockRuntime) Close() error {
	m.closedCalls++
	return nil
}

func TestRegistry(t *testing.T) {
	ctx := context.Background()

	mock := &mockRuntime{
		name:      "mock-test",
		sandboxes: make(map[string]*mockSandbox),
	}

	Register("mock-test", func(ctx context.Context, cfg Config) (Runtime, error) {
		return mock, nil
	})

	// 1. Success case
	rt, err := New(ctx, "mock-test", Config{})
	if err != nil {
		t.Fatalf("expected successful instantiation, got: %v", err)
	}
	if rt.Name() != "mock-test" {
		t.Fatalf("expected name 'mock-test', got %q", rt.Name())
	}

	// 2. Unknown runtime
	_, err = New(ctx, "non-existent-backend", Config{})
	if !errors.Is(err, ErrRuntimeNotFound) {
		t.Fatalf("expected ErrRuntimeNotFound, got: %v", err)
	}

	// 3. Prerequisite failure
	failPrereqMock := &mockRuntime{
		name:      "mock-fail-prereq",
		prereqErr: ErrPrerequisiteFailed,
		sandboxes: make(map[string]*mockSandbox),
	}
	Register("mock-fail-prereq", func(ctx context.Context, cfg Config) (Runtime, error) {
		return failPrereqMock, nil
	})

	_, err = New(ctx, "mock-fail-prereq", Config{})
	if !errors.Is(err, ErrPrerequisiteFailed) {
		t.Fatalf("expected ErrPrerequisiteFailed, got: %v", err)
	}
	if failPrereqMock.closedCalls == 0 {
		t.Fatal("expected Close() to be called on prerequisite check failure")
	}
}
