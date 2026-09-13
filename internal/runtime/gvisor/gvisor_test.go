package gvisor

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/labib0x9/docpine/internal/runtime"
)

func TestGvisorRuntime_Integration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	rt, err := New(ctx, runtime.Config{
		Image: "alpine:3.20",
	})
	if err != nil {
		t.Skipf("skipping gvisor integration test: failed to initialize gvisor runtime: %v", err)
	}
	defer rt.Close()

	if err := rt.CheckPrerequisites(ctx); err != nil {
		t.Skipf("skipping gvisor integration test: gvisor host prerequisites not met: %v", err)
	}

	opts := runtime.SandboxOptions{
		SessionID: "test-session-gvisor",
		Image:     "alpine:3.20",
		Command:   []string{"/bin/sh"},
	}

	sb, err := rt.CreateSandbox(ctx, opts)
	if err != nil {
		t.Fatalf("failed to create gvisor sandbox: %v", err)
	}
	defer func() {
		destroyCtx, dCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer dCancel()
		_ = sb.Destroy(destroyCtx)
	}()

	if sb.ID() == "" {
		t.Fatal("expected non-empty sandbox ID")
	}

	pty, err := sb.AttachPTY(ctx)
	if err != nil {
		t.Fatalf("failed to attach PTY: %v", err)
	}
	defer pty.Close()

	testCmd := "echo 'DOCKPINE_GVISOR_OK'\n"
	if _, err := pty.Write([]byte(testCmd)); err != nil {
		t.Fatalf("failed to write to PTY: %v", err)
	}

	buf := make([]byte, 1024)
	var out string
	readDeadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(readDeadline) {
		n, err := pty.Read(buf)
		if n > 0 {
			out += string(buf[:n])
			if strings.Contains(out, "DOCKPINE_GVISOR_OK") {
				break
			}
		}
		if err != nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if !strings.Contains(out, "DOCKPINE_GVISOR_OK") {
		t.Fatalf("expected PTY output to contain 'DOCKPINE_GVISOR_OK', got: %q", out)
	}

	if err := sb.Destroy(ctx); err != nil {
		t.Fatalf("failed to destroy gvisor sandbox: %v", err)
	}
}
