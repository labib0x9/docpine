package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/labib0x9/docpine/internal/runtime"
)

var (
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExpired  = errors.New("session has expired")
)

const (
	// DefaultTTL specifies the ephemeral sandbox lifetime (5 minutes).
	DefaultTTL = 5 * time.Minute
	// ReaperInterval specifies how frequently the reaper cleans up expired sessions.
	ReaperInterval = 10 * time.Second
)

// Session represents an active ephemeral sandbox session.
type Session struct {
	ID        string
	Sandbox   runtime.Sandbox
	CreatedAt time.Time
	ExpiresAt time.Time
}

// SessionInfo provides exported summary metadata about a session.
type SessionInfo struct {
	ID        string    `json:"id"`
	SandboxID string    `json:"sandbox_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Manager manages in-memory session lifecycles, TTLs, and sandbox attachment.
type Manager struct {
	rt         runtime.Runtime
	ttl        time.Duration
	mu         sync.RWMutex
	sessions   map[string]*Session
	onDestroy  []func(sessionID string)
	reaperCtx  context.Context
	reaperStop context.CancelFunc
	reaperDone chan struct{}
}

// NewManager constructs a new session manager backed by the given runtime.
func NewManager(rt runtime.Runtime, ttl ...time.Duration) *Manager {
	sessionTTL := DefaultTTL
	if len(ttl) > 0 && ttl[0] > 0 {
		sessionTTL = ttl[0]
	}

	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{
		rt:         rt,
		ttl:        sessionTTL,
		sessions:   make(map[string]*Session),
		onDestroy:  make([]func(string), 0),
		reaperCtx:  ctx,
		reaperStop: cancel,
		reaperDone: make(chan struct{}),
	}

	go m.runReaper()
	return m
}

// OnDestroy registers a callback triggered when a session is destroyed or reaped.
func (m *Manager) OnDestroy(fn func(sessionID string)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onDestroy = append(m.onDestroy, fn)
}

// Create provisions a new sandbox under the runtime and registers the ephemeral session.
func (m *Manager) Create(ctx context.Context) (string, error) {
	sessionID := uuid.New().String()

	opts := runtime.SandboxOptions{
		SessionID: sessionID,
		Command:   []string{"/bin/sh"},
	}

	sandbox, err := m.rt.CreateSandbox(ctx, opts)
	if err != nil {
		return "", fmt.Errorf("runtime failed to create sandbox: %w", err)
	}

	now := time.Now()
	sess := &Session{
		ID:        sessionID,
		Sandbox:   sandbox,
		CreatedAt: now,
		ExpiresAt: now.Add(m.ttl),
	}

	m.mu.Lock()
	m.sessions[sessionID] = sess
	m.mu.Unlock()

	slog.Info("Session created", "session_id", sessionID, "sandbox_id", sandbox.ID(), "expires_at", sess.ExpiresAt)
	return sessionID, nil
}

// Attach opens an interactive bidirectional PTY stream to the session's sandbox.
func (m *Manager) Attach(ctx context.Context, sessionID string) (io.ReadWriteCloser, error) {
	m.mu.RLock()
	sess, exists := m.sessions[sessionID]
	m.mu.RUnlock()

	if !exists {
		return nil, ErrSessionNotFound
	}

	if time.Now().After(sess.ExpiresAt) {
		_ = m.Destroy(ctx, sessionID)
		return nil, ErrSessionExpired
	}

	return sess.Sandbox.AttachPTY(ctx)
}

// Get retrieves a session by ID if it exists and has not expired.
func (m *Manager) Get(sessionID string) (*Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sess, exists := m.sessions[sessionID]
	if !exists {
		return nil, ErrSessionNotFound
	}

	if time.Now().After(sess.ExpiresAt) {
		return nil, ErrSessionExpired
	}

	return sess, nil
}

// Destroy stops, removes, and unregisters the session and its underlying sandbox.
func (m *Manager) Destroy(ctx context.Context, sessionID string) error {
	m.mu.Lock()
	sess, exists := m.sessions[sessionID]
	if exists {
		delete(m.sessions, sessionID)
	}
	callbacks := make([]func(string), len(m.onDestroy))
	copy(callbacks, m.onDestroy)
	m.mu.Unlock()

	if !exists {
		return nil
	}

	for _, fn := range callbacks {
		fn(sessionID)
	}

	slog.Info("Destroying session", "session_id", sessionID, "sandbox_id", sess.Sandbox.ID())
	return sess.Sandbox.Destroy(ctx)
}

// ActiveCount returns the number of currently active, non-expired sessions.
func (m *Manager) ActiveCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	now := time.Now()
	count := 0
	for _, sess := range m.sessions {
		if sess.ExpiresAt.After(now) {
			count++
		}
	}
	return count
}

// AllSessions returns a snapshot list of active sessions.
func (m *Manager) AllSessions() []SessionInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	list := make([]SessionInfo, 0, len(m.sessions))
	for _, s := range m.sessions {
		list = append(list, SessionInfo{
			ID:        s.ID,
			SandboxID: s.Sandbox.ID(),
			CreatedAt: s.CreatedAt,
			ExpiresAt: s.ExpiresAt,
		})
	}
	return list
}

// Close gracefully stops the reaper and destroys all active sandboxes.
func (m *Manager) Close(ctx context.Context) error {
	m.reaperStop()
	<-m.reaperDone

	m.mu.Lock()
	toDestroy := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		toDestroy = append(toDestroy, s)
	}
	m.sessions = make(map[string]*Session)
	callbacks := make([]func(string), len(m.onDestroy))
	copy(callbacks, m.onDestroy)
	m.mu.Unlock()

	for _, s := range toDestroy {
		for _, fn := range callbacks {
			fn(s.ID)
		}
	}

	var errs []error
	for _, s := range toDestroy {
		if err := s.Sandbox.Destroy(ctx); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors destroying sessions on shutdown: %v", errs)
	}
	return nil
}

// runReaper runs a periodic background task to reap expired sessions.
func (m *Manager) runReaper() {
	defer close(m.reaperDone)
	ticker := time.NewTicker(ReaperInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.reaperCtx.Done():
			return
		case <-ticker.C:
			m.reapExpired()
		}
	}
}

func (m *Manager) reapExpired() {
	now := time.Now()

	m.mu.Lock()
	var expired []*Session
	for id, sess := range m.sessions {
		if now.After(sess.ExpiresAt) {
			expired = append(expired, sess)
			delete(m.sessions, id)
		}
	}
	callbacks := make([]func(string), len(m.onDestroy))
	copy(callbacks, m.onDestroy)
	m.mu.Unlock()

	for _, sess := range expired {
		for _, fn := range callbacks {
			fn(sess.ID)
		}
		slog.Info("Reaping expired session", "session_id", sess.ID, "sandbox_id", sess.Sandbox.ID())
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_ = sess.Sandbox.Destroy(ctx)
		cancel()
	}
}
