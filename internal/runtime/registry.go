package runtime

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

// Config carries general runtime configuration parameters.
type Config struct {
	Image          string // Default container image or kernel/rootfs path
	NetworkMode    string // Network isolation mode (e.g. "none", "bridge")
	MemoryLimit    int64  // Memory limit in bytes
	CPUShares      int64  // CPU shares
	RunscPath      string // Path to runsc binary for gVisor
	FirecrackerBin string // Path to firecracker binary
	KernelPath     string // Path to guest kernel vmlinux for Firecracker
	RootFSPath     string // Path to guest rootfs for Firecracker
}

// Factory is a constructor function for a specific runtime backend.
type Factory func(ctx context.Context, cfg Config) (Runtime, error)

var (
	registryMu sync.RWMutex
	factories  = make(map[string]Factory)
)

// Register registers a runtime factory under a given name (case-insensitive).
func Register(name string, f Factory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	factories[strings.ToLower(strings.TrimSpace(name))] = f
}

// Available returns a list of all registered runtime backend names.
func Available() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	list := make([]string, 0, len(factories))
	for name := range factories {
		list = append(list, name)
	}
	return list
}

// New instantiates a runtime backend by name, initializes it, and verifies its host prerequisites.
// It fails fast and loudly if the backend is unknown or prerequisites are missing.
func New(ctx context.Context, name string, cfg Config) (Runtime, error) {
	normalized := strings.ToLower(strings.TrimSpace(name))
	if normalized == "" {
		normalized = "docker"
	}

	registryMu.RLock()
	factory, exists := factories[normalized]
	registryMu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("%w: %q (available: %v)", ErrRuntimeNotFound, normalized, Available())
	}

	rt, err := factory(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize runtime %q: %w", normalized, err)
	}

	// Verify host prerequisites immediately
	if err := rt.CheckPrerequisites(ctx); err != nil {
		_ = rt.Close()
		return nil, fmt.Errorf("runtime prerequisite check failed for %q: %w", normalized, err)
	}

	return rt, nil
}
