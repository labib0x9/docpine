package session

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/uuid"
	"github.com/labib0x9/docpine/internal/docker"
)

type Session struct {
	*docker.Hijack
}

func (s *Session) Close() error {
	return s.Hijack.Close()
}

type Manager struct {
	mu  sync.Mutex
	mp  map[string]string
	con docker.Container
}

func NewManager(con docker.Container) *Manager {
	mn := Manager{
		con: con,
		mp:  make(map[string]string),
	}
	return &mn
}

// get container id by session id
func (m *Manager) GetId(id string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mp[id]
}

func (m *Manager) setId(sessionId string, containerId string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mp[sessionId] = containerId
}

func (m *Manager) Start(ctx context.Context) (string, error) {
	sessionId := uuid.New().String()
	containerId, err := m.con.Create(ctx, sessionId)
	if err != nil {
		return "", err
	}
	if err := m.con.Start(ctx, containerId); err != nil {
		return "", err
	}
	m.setId(sessionId, containerId)
	return sessionId, nil
}

func (m *Manager) Attach(ctx context.Context, id string) (*Session, error) {
	h, err := m.con.Attach(ctx, id)
	if err != nil {
		return nil, err
	}
	return &Session{h}, nil
}

func (m *Manager) Stop(ctx context.Context, id string) error {
	return m.con.Stop(ctx, id)
}

func (m *Manager) AllSessions() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for sID, cID := range m.mp {
		fmt.Println("SessionId=", sID, "ContainerId=", cID)
	}
}
