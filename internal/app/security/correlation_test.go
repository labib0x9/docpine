package security

import (
	"context"
	"testing"
	"time"

	"github.com/labib0x9/docpine/internal/domain/security"
	"github.com/labib0x9/docpine/internal/infra/postgres"
)

func TestCorrelationEngine_ShellToExfil(t *testing.T) {
	ctx := context.Background()
	repo := postgres.NewMemoryRepo()
	engine := NewEngine(repo)

	containerID := "test-container-exfil"
	cgroupID := uint64(555)

	err := engine.RegisterContainer(ctx, containerID, cgroupID, security.NamespaceIdentity{}, security.CAP_CHOWN, nil)
	if err != nil {
		t.Fatalf("failed to register container: %v", err)
	}

	// 1. Process fork/exec: shell execution
	pid := uint32(100)
	_ = engine.RecordProcessLifecycle(ctx, security.ProcessState{
		CgroupID:  cgroupID,
		PID:       pid,
		PPID:      1,
		Comm:      "sh",
		StartedAt: time.Now(),
	})

	e1 := security.EventRecord{
		Time:     time.Now(),
		CgroupID: cgroupID,
		PID:      pid,
		Type:     security.EventExec,
		Comm:     "sh",
		Data:     "/bin/sh",
	}
	f1, err := engine.IngestEvent(ctx, e1)
	if err != nil || f1 != nil {
		t.Fatalf("unexpected finding on shell exec alone: %v", f1)
	}

	// 2. Sensitive file access: /etc/shadow
	time.Sleep(10 * time.Millisecond)
	e2 := security.EventRecord{
		Time:     time.Now(),
		CgroupID: cgroupID,
		PID:      pid,
		Type:     security.EventOpenat,
		Comm:     "cat",
		Data:     "/etc/shadow",
	}
	f2, err := engine.IngestEvent(ctx, e2)
	if err != nil {
		t.Fatalf("ingest error: %v", err)
	}
	// At this stage, it's recorded in the temporal state tracker
	_ = f2

	// 3. Outbound network connect: external IP
	time.Sleep(10 * time.Millisecond)
	e3 := security.EventRecord{
		Time:     time.Now(),
		CgroupID: cgroupID,
		PID:      pid,
		Type:     security.EventConnect,
		Comm:     "curl",
		Data:     "203.0.113.50:443",
	}
	f3, err := engine.IngestEvent(ctx, e3)
	if err != nil {
		t.Fatalf("ingest error: %v", err)
	}

	if f3 == nil {
		t.Fatal("expected FindingShellToExfil to be generated for shell -> /etc/shadow -> connect sequence")
	}

	if f3.FindingType != security.FindingShellToExfil {
		t.Fatalf("expected finding type %s, got %s", security.FindingShellToExfil, f3.FindingType)
	}

	if f3.Severity != security.SeverityHigh {
		t.Fatalf("expected high severity, got %s", f3.Severity)
	}

	if len(f3.EventIDs) != 3 {
		t.Fatalf("expected 3 correlated event IDs, got %d: %v", len(f3.EventIDs), f3.EventIDs)
	}

	// Verify finding is persisted and retrievable via GetFindings
	findings, err := engine.GetFindings(ctx, containerID)
	if err != nil || len(findings) == 0 {
		t.Fatalf("expected finding in repository, got %v (err: %v)", findings, err)
	}
}

func TestCorrelationEngine_HostExposureAmplifier(t *testing.T) {
	ctx := context.Background()
	repo := postgres.NewMemoryRepo()
	engine := NewEngine(repo)

	containerID := "privileged-container"
	cgroupID := uint64(888)

	// Container created with privileged mode
	hostExp := map[string]any{"privileged": true}
	_ = engine.RegisterContainer(ctx, containerID, cgroupID, security.NamespaceIdentity{}, security.CAP_CHOWN, hostExp)

	pid := uint32(200)
	_ = engine.RecordProcessLifecycle(ctx, security.ProcessState{
		CgroupID:  cgroupID,
		PID:       pid,
		PPID:      1,
		Comm:      "bash",
		StartedAt: time.Now(),
	})

	_ = engine.RecordProcessLifecycle(ctx, security.ProcessState{CgroupID: cgroupID, PID: pid, Comm: "bash"})
	_, _ = engine.IngestEvent(ctx, security.EventRecord{Time: time.Now(), CgroupID: cgroupID, PID: pid, Type: security.EventExec, Comm: "bash", Data: "/bin/bash"})
	_, _ = engine.IngestEvent(ctx, security.EventRecord{Time: time.Now(), CgroupID: cgroupID, PID: pid, Type: security.EventOpenat, Comm: "cat", Data: "/etc/shadow"})
	f, _ := engine.IngestEvent(ctx, security.EventRecord{Time: time.Now(), CgroupID: cgroupID, PID: pid, Type: security.EventConnect, Comm: "curl", Data: "198.51.100.2:443"})

	if f == nil {
		t.Fatal("expected shell-to-exfil finding")
	}

	// Should be elevated to CRITICAL severity due to privileged container host exposure
	if f.Severity != security.SeverityCritical {
		t.Fatalf("expected critical severity for privileged container, got %s", f.Severity)
	}
}

func TestCorrelationEngine_BenignWorkloadResistance(t *testing.T) {
	ctx := context.Background()
	repo := postgres.NewMemoryRepo()
	engine := NewEngine(repo)

	containerID := "benign-build-container"
	cgroupID := uint64(999)

	_ = engine.RegisterContainer(ctx, containerID, cgroupID, security.NamespaceIdentity{}, security.CAP_CHOWN, nil)

	pid := uint32(300)
	_ = engine.RecordProcessLifecycle(ctx, security.ProcessState{
		CgroupID:  cgroupID,
		PID:       pid,
		PPID:      1,
		Comm:      "go",
		StartedAt: time.Now(),
	})

	// 1. Benign compiler exec
	f1, _ := engine.IngestEvent(ctx, security.EventRecord{Time: time.Now(), CgroupID: cgroupID, PID: pid, Type: security.EventExec, Comm: "go", Data: "/usr/local/go/bin/go"})
	if f1 != nil {
		t.Fatalf("unexpected finding on go compile: %v", f1)
	}

	// 2. Reading normal source files (not sensitive credentials)
	f2, _ := engine.IngestEvent(ctx, security.EventRecord{Time: time.Now(), CgroupID: cgroupID, PID: pid, Type: security.EventOpenat, Comm: "go", Data: "/workspace/src/main.go"})
	if f2 != nil {
		t.Fatalf("unexpected finding on source file open: %v", f2)
	}

	// 3. Legitimate package download
	f3, _ := engine.IngestEvent(ctx, security.EventRecord{Time: time.Now(), CgroupID: cgroupID, PID: pid, Type: security.EventConnect, Comm: "go", Data: "142.250.190.46:443"})
	if f3 != nil {
		t.Fatalf("unexpected finding on benign network download: %v", f3)
	}

	findings, _ := engine.GetFindings(ctx, containerID)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for benign build workload, got %d: %+v", len(findings), findings)
	}
}
