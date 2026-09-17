package websocket

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/labib0x9/docpine/internal/config"
	"github.com/labib0x9/docpine/internal/runtime"
	"github.com/labib0x9/docpine/internal/session"
	"github.com/labib0x9/docpine/internal/utils"
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
	id          string
	stream      *mockPTYStream
	attachError error
}

func (m *mockWSSandbox) ID() string {
	return m.id
}

func (m *mockWSSandbox) CgroupID() (uint64, error) {
	return 4000, nil
}

func (m *mockWSSandbox) AttachPTY(ctx context.Context) (io.ReadWriteCloser, error) {
	if m.attachError != nil {
		return nil, m.attachError
	}
	return m.stream, nil
}

func (m *mockWSSandbox) Destroy(ctx context.Context) error {
	if m.stream != nil {
		return m.stream.Close()
	}
	return nil
}

type mockWSRuntime struct {
	stream      *mockPTYStream
	attachError error
}

func (m *mockWSRuntime) Name() string {
	return "mock"
}

func (m *mockWSRuntime) CheckPrerequisites(ctx context.Context) error {
	return nil
}

func (m *mockWSRuntime) CreateSandbox(ctx context.Context, opts runtime.SandboxOptions) (runtime.Sandbox, error) {
	return &mockWSSandbox{
		id:          "sb-" + opts.SessionID,
		stream:      m.stream,
		attachError: m.attachError,
	}, nil
}

func (m *mockWSRuntime) Close() error {
	return nil
}

func setupTestWebSocketServer(t *testing.T, rt runtime.Runtime, ttl time.Duration) (*session.Manager, *httptest.Server, string) {
	t.Helper()
	tempDir := t.TempDir()
	mngr := session.NewManager(rt, ttl)
	t.Cleanup(func() {
		_ = mngr.Close(context.Background())
	})

	wsHandler := NewHandler(mngr, config.Logger{Directory: tempDir})
	mux := http.NewServeMux()
	wsHandler.RegisterRoutes(mux)

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	return mngr, server, tempDir
}

func TestWebSocketHandler_Attach_FullFlow(t *testing.T) {
	utils.InitAllowedOrigins(&config.Config{AllowedOrigins: []string{"*"}})

	stream := newMockPTYStream()
	defer stream.Close()

	rt := &mockWSRuntime{stream: stream}
	mngr, server, tempDir := setupTestWebSocketServer(t, rt, 1*time.Minute)

	sessionID, err := mngr.Create(context.Background())
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// Write initial terminal output to PTY stream
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

	// 1. Read Terminal Output from PTY (Lane 1)
	_, msg, err := wsConn.ReadMessage()
	if err != nil {
		t.Fatalf("failed to read from websocket: %v", err)
	}
	if !strings.Contains(string(msg), "hello from pty") {
		t.Fatalf("expected PTY output 'hello from pty', got: %s", string(msg))
	}

	// 2. Send Control Ping Message (Lane 2)
	pingMsg, _ := json.Marshal(ControlMessage{Type: "ping"})
	if err := wsConn.WriteMessage(websocket.TextMessage, pingMsg); err != nil {
		t.Fatalf("failed to write ping message: %v", err)
	}

	// Read Pong Message response
	_, pongMsg, err := wsConn.ReadMessage()
	if err != nil {
		t.Fatalf("failed to read pong message: %v", err)
	}
	if !strings.Contains(string(pongMsg), "pong") {
		t.Fatalf("expected pong message, got: %s", string(pongMsg))
	}

	// 3. Send Control Resize Message (Lane 2)
	resizeMsg, _ := json.Marshal(ControlMessage{Type: "resize", Cols: 120, Rows: 40})
	if err := wsConn.WriteMessage(websocket.TextMessage, resizeMsg); err != nil {
		t.Fatalf("failed to write resize message: %v", err)
	}

	// 4. Send Terminal Input into container (Lane 1)
	if err := wsConn.WriteMessage(websocket.TextMessage, []byte("ls -la\n")); err != nil {
		t.Fatalf("failed to write terminal input: %v", err)
	}

	// Close websocket cleanly
	_ = wsConn.Close()
	time.Sleep(50 * time.Millisecond)

	// 5. Verify session input and output log files
	inputLogPath := filepath.Join(tempDir, "sessions", sessionID+".input.log")
	inBytes, err := os.ReadFile(inputLogPath)
	if err != nil {
		t.Fatalf("failed to read input log file: %v", err)
	}
	if !strings.Contains(string(inBytes), "ls -la") {
		t.Errorf("expected input log to contain 'ls -la', got %q", string(inBytes))
	}

	outputLogPath := filepath.Join(tempDir, "sessions", sessionID+".output.log")
	outBytes, err := os.ReadFile(outputLogPath)
	if err != nil {
		t.Fatalf("failed to read output log file: %v", err)
	}
	if !strings.Contains(string(outBytes), "hello from pty") {
		t.Errorf("expected output log to contain 'hello from pty', got %q", string(outBytes))
	}
}

func TestWebSocketHandler_SessionNotFound(t *testing.T) {
	utils.InitAllowedOrigins(&config.Config{AllowedOrigins: []string{"*"}})

	rt := &mockWSRuntime{stream: newMockPTYStream()}
	_, server, _ := setupTestWebSocketServer(t, rt, 1*time.Minute)

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/sessions/non-existent-session-id/attach"
	_, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err == nil {
		t.Fatal("expected error connecting to non-existent session, got nil")
	}
	if resp != nil && resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected HTTP 404 Not Found, got %d", resp.StatusCode)
	}
}

func TestWebSocketHandler_SessionExpired(t *testing.T) {
	utils.InitAllowedOrigins(&config.Config{AllowedOrigins: []string{"*"}})

	rt := &mockWSRuntime{stream: newMockPTYStream()}
	mngr, server, _ := setupTestWebSocketServer(t, rt, 10*time.Millisecond)

	sessionID, err := mngr.Create(context.Background())
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// Wait for TTL expiration
	time.Sleep(25 * time.Millisecond)

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/sessions/" + sessionID + "/attach"
	_, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err == nil {
		t.Fatal("expected error connecting to expired session, got nil")
	}
	if resp != nil && resp.StatusCode != http.StatusGone {
		t.Fatalf("expected HTTP 410 Gone, got %d", resp.StatusCode)
	}
}

func TestWebSocketHandler_OriginValidation(t *testing.T) {
	utils.InitAllowedOrigins(&config.Config{AllowedOrigins: []string{"https://allowed.example.com"}})

	stream := newMockPTYStream()
	defer stream.Close()

	rt := &mockWSRuntime{stream: stream}
	mngr, server, _ := setupTestWebSocketServer(t, rt, 1*time.Minute)

	sessionID, err := mngr.Create(context.Background())
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/sessions/" + sessionID + "/attach"

	// 1. Rejected Origin
	evilHeader := http.Header{"Origin": []string{"https://evil.example.com"}}
	_, resp, err := websocket.DefaultDialer.Dial(wsURL, evilHeader)
	if err == nil {
		t.Fatal("expected connection to fail for unauthorized origin, got nil")
	}
	if resp != nil && resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected HTTP 403 Forbidden for bad origin, got %d", resp.StatusCode)
	}

	// 2. Allowed Origin
	allowedHeader := http.Header{"Origin": []string{"https://allowed.example.com"}}
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, allowedHeader)
	if err != nil {
		t.Fatalf("expected connection to succeed for allowed origin, got error: %v (status: %v)", err, resp)
	}
	defer conn.Close()
}

func TestWebSocketHandler_AttachPTYFailure(t *testing.T) {
	utils.InitAllowedOrigins(&config.Config{AllowedOrigins: []string{"*"}})

	rt := &mockWSRuntime{attachError: errors.New("attach failed")}
	mngr, server, _ := setupTestWebSocketServer(t, rt, 1*time.Minute)

	sessionID, err := mngr.Create(context.Background())
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/sessions/" + sessionID + "/attach"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("failed to connect websocket: %v", err)
	}
	defer conn.Close()

	// Read close frame
	_, _, err = conn.ReadMessage()
	if err == nil {
		t.Fatal("expected read error due to server closing with attach failure, got nil")
	}
}
