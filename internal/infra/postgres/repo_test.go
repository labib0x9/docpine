package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/labib0x9/docpine/internal/domain/security"
)

func TestMemoryRepo_CRUD(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryRepo()

	// 1. Register container
	containerRec := ContainerRecord{
		ID:           "test-container-1",
		CgroupID:     12345,
		Backend:      "docker",
		CreatedAt:    time.Now(),
		BaselineCaps: security.CAP_CHOWN | security.CAP_SETUID,
		BaselineNS: security.NamespaceIdentity{
			NetNS: 4026531992,
		},
		HostExposure: map[string]any{
			"privileged": false,
		},
	}

	if err := repo.RegisterContainer(ctx, containerRec); err != nil {
		t.Fatalf("failed to register container: %v", err)
	}

	// Lookup by ID
	c, err := repo.GetContainer(ctx, "test-container-1")
	if err != nil || c.CgroupID != 12345 {
		t.Fatalf("failed to get container by ID: %v, got %+v", err, c)
	}

	// Lookup by Cgroup ID
	byCg, err := repo.GetContainerByCgroup(ctx, 12345)
	if err != nil || byCg.ID != "test-container-1" {
		t.Fatalf("failed to get container by cgroup ID: %v, got %+v", err, byCg)
	}

	// 2. Record process
	p := security.ProcessState{
		CgroupID:  12345,
		PID:       42,
		PPID:      1,
		Comm:      "sh",
		StartedAt: time.Now(),
	}
	if err := repo.RecordProcess(ctx, p); err != nil {
		t.Fatalf("failed to record process: %v", err)
	}

	proc, err := repo.GetProcess(ctx, 12345, 42)
	if err != nil || proc.Comm != "sh" {
		t.Fatalf("failed to get process: %v", err)
	}

	// 3. Record event & get timeline
	event := &security.EventRecord{
		Time:     time.Now(),
		CgroupID: 12345,
		PID:      42,
		Type:     security.EventExec,
		Comm:     "sh",
		Data:     "/bin/sh",
	}
	if err := repo.RecordEvent(ctx, event); err != nil {
		t.Fatalf("failed to record event: %v", err)
	}

	timeline, err := repo.GetTimeline(ctx, "test-container-1", 10)
	if err != nil || len(timeline) != 1 {
		t.Fatalf("expected timeline of length 1, got %d (err: %v)", len(timeline), err)
	}

	// 4. Save and fetch findings
	finding := &security.Finding{
		ContainerID: "test-container-1",
		CgroupID:    12345,
		PID:         42,
		Severity:    security.SeverityHigh,
		FindingType: security.FindingShellToExfil,
		Summary:     "Shell exec followed by sensitive file open and network connect",
		EventIDs:    []int64{event.ID},
		CreatedAt:   time.Now(),
	}
	if err := repo.SaveFinding(ctx, finding); err != nil {
		t.Fatalf("failed to save finding: %v", err)
	}

	findings, err := repo.GetFindings(ctx, "test-container-1")
	if err != nil || len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d (err: %v)", len(findings), err)
	}

	// 5. Policy save and fetch
	policy := security.ContainerPolicy{
		ContainerID:         "test-container-1",
		AllowedCapabilities: []string{"CAP_CHOWN"},
		NetworkRules: []security.NetworkRule{
			{DstIP: "1.1.1.1", DstPort: 53, Action: "allow"},
		},
	}
	if err := repo.SetPolicy(ctx, policy); err != nil {
		t.Fatalf("failed to set policy: %v", err)
	}

	pol, err := repo.GetPolicy(ctx, "test-container-1")
	if err != nil || len(pol.NetworkRules) != 1 {
		t.Fatalf("failed to get policy: %v, got %+v", err, pol)
	}

	// 6. Cleanup container
	if err := repo.CleanupContainer(ctx, "test-container-1"); err != nil {
		t.Fatalf("failed to cleanup container: %v", err)
	}
}
