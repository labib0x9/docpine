package websocket

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/labib0x9/docpine/internal/runtime"
	"github.com/labib0x9/docpine/internal/session"
)

type mockPTYStream struct {
	reader *io.PipeReader
	writer *io.PipeWriter
	inR    *io.PipeReader
	inW    *io.PipeWriter
	mu     sync.Mutex
	closed bool
}

func newMockPTYStream() *mockPTYStream {
	outR, outW := io.Pipe()
	inR, inW := io.Pipe()
	return &mockPTYStream{
		reader: outR,
		writer: outW,
		inR:    inR,
		inW:    inW,
	}
}

func (m *mockPTYStream) Read(p []byte) (int, error) {
	return m.reader.Read(p)
}

func (m *mockPTYStream) Write(p []byte) (int, error) {
	return m.inW.Write(p)
}

func (m *mockPTYStream) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	_ = m.reader.Close()
	_ = m.writer.Close()
	_ = m.inR.Close()
	_ = m.inW.Close()
	return nil
}

type mockWSSandbox struct {
	id     string
	stream *mockPTYStream
}

func (m *mockWSSandbox) ID() string {
	return m.id
}

func (m *mockWSSandbox) AttachPTY(ctx context.Context) (io.ReadWriteCloser, error) {
	return m.stream, nil
}

func (m *mockWSSandbox) Destroy(ctx context.Context) error {
	return m.stream.Close()
}

type mockWSRuntime struct {
	stream *mockPTYStream
}

func (m *mockWSRuntime) Name() string {
	return "mock"
}

func (m *mockWSRuntime) CheckPrerequisites(ctx context.Context) error {
	return nil
}

func (m *mockWSRuntime) CreateSandbox(ctx context.Context, opts runtime.SandboxOptions) (runtime.Sandbox, error) {
	return &mockWSSandbox{id: "sb-" + opts.SessionID, stream: m.stream}, nil
}

func (m *mockWSRuntime) Close() error {
	return nil
}

func TestWebSocketHandler_Attach(t *testing.T) {
	stream := newMockPTYStream()
	defer stream.Close()

	rt := &mockWSRuntime{stream: stream}
	mngr := session.NewManager(rt, 1*time.Minute)
	defer mngr.Close(context.Background())

	sessionID, err := mngr.Create(context.Background())
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	wsHandler := NewHandler(mngr)
	mux := http.NewServeMux()
	wsHandler.RegisterRoutes(mux)

	server := httptest.NewServer(mux)
	defer server.Close()

	// Write initial terminal banner to PTY
	go func() {
		_, _ = stream.writer.Write([]byte("hello from pty\n"))
	}()

	// Connect WebSocket
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/sessions/" + sessionID + "/attach"
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("failed to connect websocket: %v", err)
	}
	defer wsConn.Close()

	// Read Lane 1: PTY Output
	_, msg, err := wsConn.ReadMessage()
	if err != nil {
		t.Fatalf("failed to read from websocket: %v", err)
	}

	if !strings.Contains(string(msg), "hello from pty") {
		t.Fatalf("expected PTY output, got: %s", string(msg))
	}

	// Send Lane 2: Control Ping Message
	pingMsg, _ := json.Marshal(ControlMessage{Type: "ping"})
	if err := wsConn.WriteMessage(websocket.TextMessage, pingMsg); err != nil {
		t.Fatalf("failed to write ping message: %v", err)
	}

	// Read pong
	_, pongMsg, err := wsConn.ReadMessage()
	if err != nil {
		t.Fatalf("failed to read pong message: %v", err)
	}
	if !strings.Contains(string(pongMsg), "pong") {
		t.Fatalf("expected pong message, got: %s", string(pongMsg))
	}
}
