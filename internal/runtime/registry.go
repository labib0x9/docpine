package runtime

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/labib0x9/docpine/internal/config"
)

// Factory is a constructor function for a specific runtime backend.
type Factory func(ctx context.Context, cfg config.Runtime) (Runtime, error)

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
func New(ctx context.Context, name string, cfg config.Runtime) (Runtime, error) {
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
