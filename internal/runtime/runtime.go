package runtime

import (
	"context"
	"errors"
	"io"
)

var (
	// ErrPrerequisiteFailed is returned when a runtime backend's host requirements are not met.
	ErrPrerequisiteFailed = errors.New("runtime prerequisite check failed")
	// ErrRuntimeNotFound is returned when an unknown runtime backend name is requested.
	ErrRuntimeNotFound = errors.New("runtime backend not registered")
	// ErrSandboxNotFound is returned when attempting to access a sandbox that does not exist.
	ErrSandboxNotFound = errors.New("sandbox not found")
	// ErrSandboxDestroyed is returned when attempting an operation on a destroyed sandbox.
	ErrSandboxDestroyed = errors.New("sandbox has been destroyed")
	// ErrNotApplicable is returned when an operation (such as host cgroup ID lookup) is not applicable for a backend (e.g. Firecracker).
	ErrNotApplicable = errors.New("not applicable for this runtime backend")
)

// SandboxOptions specifies the configuration needed to provision a sandbox.
type SandboxOptions struct {
	SessionID   string            // Unique identifier for the session/sandbox.
	Image       string            // Container image or rootfs identifier (e.g. "alpine:3.20").
	Command     []string          // Command to execute in the sandbox (default: ["/bin/sh"]).
	Env         []string          // Environment variables in KEY=VALUE format.
	MemoryLimit int64             // Memory limit in bytes (0 for default).
	CPUShares   int64             // Relative CPU share weight (0 for default).
	Metadata    map[string]string // Arbitrary backend-specific metadata.
}

// Sandbox represents an active, isolated execution environment (container or microVM).
type Sandbox interface {
	// ID returns the unique identifier of the running sandbox.
	ID() string
	// CgroupID returns the host kernel cgroup ID if applicable (Docker, gVisor) or ErrNotApplicable (Firecracker).
	CgroupID() (uint64, error)
	// AttachPTY opens a bidirectional raw pseudo-terminal (PTY) stream to the sandbox process.
	AttachPTY(ctx context.Context) (io.ReadWriteCloser, error)
	// Destroy stops and cleans up the sandbox and all associated host resources.
	Destroy(ctx context.Context) error
}

// Runtime abstracts the underlying isolation technology (Docker, gVisor, Firecracker).
type Runtime interface {
	// Name returns the identifier of the runtime backend (e.g. "docker", "gvisor", "firecracker").
	Name() string
	// CheckPrerequisites verifies that all host requirements (binaries, daemons, /dev/kvm) are satisfied.
	CheckPrerequisites(ctx context.Context) error
	// CreateSandbox provisions and starts a new isolated sandbox instance.
	CreateSandbox(ctx context.Context, opts SandboxOptions) (Sandbox, error)
	// Close releases any persistent client connections or resources held by the runtime.
	Close() error
}
