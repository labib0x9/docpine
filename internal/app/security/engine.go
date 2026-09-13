package security

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/labib0x9/docpine/internal/domain/security"
	"github.com/labib0x9/docpine/internal/infra/postgres"
)

// BPFMapWriter defines the interface for injecting compiled policies directly into in-kernel BPF maps.
type BPFMapWriter interface {
	WritePolicy(compiled *CompiledPolicy) error
	RemovePolicy(cgroupID uint64) error
}

// Engine coordinates eBPF event ingestion, behavioral correlation, policy compilation, and persistence.
type Engine struct {
	repo        postgres.Repository
	correlation *CorrelationEngine
	compiler    *PolicyCompiler
	bpfWriter   BPFMapWriter
}

// NewEngine constructs a new runtime security engine.
func NewEngine(repo postgres.Repository, bpfWriter ...BPFMapWriter) *Engine {
	var writer BPFMapWriter
	if len(bpfWriter) > 0 {
		writer = bpfWriter[0]
	}

	return &Engine{
		repo:        repo,
		correlation: NewCorrelationEngine(repo),
		compiler:    NewPolicyCompiler(),
		bpfWriter:   writer,
	}
}

// RegisterContainer registers a newly provisioned container with baseline namespace and capability states.
// Must be called immediately after container creation before guest execution begins.
func (e *Engine) RegisterContainer(ctx context.Context, containerID string, cgroupID uint64, baselineNS security.NamespaceIdentity, baselineCaps uint64, hostExposure map[string]any) error {
	record := postgres.ContainerRecord{
		ID:           containerID,
		CgroupID:     cgroupID,
		CreatedAt:    time.Now(),
		BaselineNS:   baselineNS,
		BaselineCaps: baselineCaps,
		HostExposure: hostExposure,
	}

	if err := e.repo.RegisterContainer(ctx, record); err != nil {
		return fmt.Errorf("failed to register container security baseline: %w", err)
	}

	slog.Info("Registered container for eBPF runtime security monitoring",
		"container_id", containerID,
		"cgroup_id", cgroupID,
		"baseline_caps", baselineCaps,
	)
	return nil
}

// IngestEvent processes an observed kernel event, stores it in the event timeline, and runs behavioral correlation.
func (e *Engine) IngestEvent(ctx context.Context, event security.EventRecord) (*security.Finding, error) {
	if err := e.repo.RecordEvent(ctx, &event); err != nil {
		slog.Warn("Failed to persist event record", "error", err)
	}

	container, err := e.repo.GetContainerByCgroup(ctx, event.CgroupID)
	if err != nil {
		// Event from untracked cgroup
		return nil, nil
	}

	proc, _ := e.repo.GetProcess(ctx, event.CgroupID, event.PID)

	finding, err := e.correlation.IngestEvent(&event, container, proc)
	if err != nil {
		return nil, err
	}

	if finding != nil {
		if err := e.repo.SaveFinding(ctx, finding); err != nil {
			slog.Error("Failed to save security finding", "error", err)
		} else {
			slog.Warn("🚨 SECURITY FINDING GENERATED",
				"finding_type", finding.FindingType,
				"severity", finding.Severity,
				"container_id", finding.ContainerID,
				"summary", finding.Summary,
			)
		}
	}

	return finding, nil
}

// RecordProcessLifecycle updates the in-memory process hierarchy when fork/exec/exit occurs.
func (e *Engine) RecordProcessLifecycle(ctx context.Context, p security.ProcessState) error {
	if p.PPID > 0 {
		parent, err := e.repo.GetProcess(ctx, p.CgroupID, p.PPID)
		if err == nil && parent != nil {
			p.Parent = parent
		}
	}
	return e.repo.RecordProcess(ctx, p)
}

// GetFindings retrieves all correlated findings for a specific container.
func (e *Engine) GetFindings(ctx context.Context, containerID string) ([]security.Finding, error) {
	return e.repo.GetFindings(ctx, containerID)
}

// GetTimeline retrieves the ordered event timeline for a specific container.
func (e *Engine) GetTimeline(ctx context.Context, containerID string, limit int) ([]security.EventRecord, error) {
	return e.repo.GetTimeline(ctx, containerID, limit)
}

// SetPolicy compiles a high-level container policy and applies it to in-kernel BPF maps.
func (e *Engine) SetPolicy(ctx context.Context, p security.ContainerPolicy) error {
	container, err := e.repo.GetContainer(ctx, p.ContainerID)
	if err != nil {
		return fmt.Errorf("container not found: %w", err)
	}

	if err := e.repo.SetPolicy(ctx, p); err != nil {
		return fmt.Errorf("failed to persist policy: %w", err)
	}

	compiled, err := e.compiler.Compile(container.CgroupID, p)
	if err != nil {
		return fmt.Errorf("policy compilation failed: %w", err)
	}

	if e.bpfWriter != nil {
		if err := e.bpfWriter.WritePolicy(compiled); err != nil {
			slog.Error("Failed to write policy to in-kernel BPF maps", "error", err)
			return fmt.Errorf("kernel BPF map policy write failed: %w", err)
		}
		slog.Info("Successfully loaded container policy into kernel BPF maps", "container_id", p.ContainerID, "cgroup_id", container.CgroupID)
	}

	return nil
}

// GetPolicy retrieves the active security policy for a container.
func (e *Engine) GetPolicy(ctx context.Context, containerID string) (*security.ContainerPolicy, error) {
	return e.repo.GetPolicy(ctx, containerID)
}

// UnregisterContainer cleans up container baselines and removes in-kernel BPF map entries upon container exit.
func (e *Engine) UnregisterContainer(ctx context.Context, containerID string) error {
	container, err := e.repo.GetContainer(ctx, containerID)
	if err == nil && container != nil && e.bpfWriter != nil {
		_ = e.bpfWriter.RemovePolicy(container.CgroupID)
	}
	return e.repo.CleanupContainer(ctx, containerID)
}

// Stats returns aggregated security metrics.
func (e *Engine) Stats(ctx context.Context) (map[string]any, error) {
	return e.repo.Stats(ctx)
}
