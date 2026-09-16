package websocket

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/labib0x9/docpine/internal/session"
	"github.com/labib0x9/docpine/jsonio"
)

// ControlMessage represents out-of-band terminal control messages (Lane 2).
type ControlMessage struct {
	Type string `json:"type"` // e.g. "resize", "ping"
	Cols uint16 `json:"cols,omitempty"`
	Rows uint16 `json:"rows,omitempty"`
}

// Handler manages interactive terminal WebSocket connections.
type Handler struct {
	mngr     *session.Manager
	upgrader websocket.Upgrader
}

// NewHandler constructs a new WebSocket handler.
func NewHandler(mngr *session.Manager) *Handler {
	return &Handler{
		mngr: mngr,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  4096,
			WriteBufferSize: 4096,
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		},
	}
}

// RegisterRoutes registers the WebSocket attach route on the mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.Handle(
		"GET /sessions/{id}/attach",
		http.HandlerFunc(h.Attach),
	)
}

// Attach upgrades the HTTP request to a full-duplex WebSocket and streams PTY terminal I/O.
func (h *Handler) Attach(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("id")
	if sessionID == "" {
		jsonio.SendError(w, "session id is required", http.StatusBadRequest)
		return
	}

	// 1. Verify session exists before upgrading
	_, err := h.mngr.Get(sessionID)
	if err != nil {
		if errors.Is(err, session.ErrSessionNotFound) {
			jsonio.SendError(w, "session not found", http.StatusNotFound)
			return
		}
		if errors.Is(err, session.ErrSessionExpired) {
			jsonio.SendError(w, "session has expired", http.StatusGone)
			return
		}
		jsonio.SendError(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// 2. Upgrade to WebSocket
	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("WebSocket upgrade failed", "error", err, "session_id", sessionID)
		return
	}
	defer conn.Close()

	// 3. Attach to Sandbox PTY stream
	attachCtx, cancel := context.WithCancel(r.Context())
	defer cancel()

	ptyStream, err := h.mngr.Attach(attachCtx, sessionID)
	if err != nil {
		slog.Error("Failed to attach to sandbox PTY", "error", err, "session_id", sessionID)
		_ = conn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseInternalServerErr, "sandbox attach failed"),
			time.Now().Add(time.Second),
		)
		return
	}
	defer ptyStream.Close()

	var writeMu sync.Mutex
	safeWrite := func(messageType int, data []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return conn.WriteMessage(messageType, data)
	}

	errChan := make(chan error, 2)

	// Pump 1: PTY Output -> WebSocket Client (Lane 1: Terminal Bytes)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := ptyStream.Read(buf)
			if n > 0 {
				if wErr := safeWrite(websocket.TextMessage, buf[:n]); wErr != nil {
					errChan <- wErr
					return
				}
			}
			if err != nil {
				if !errors.Is(err, io.EOF) {
					errChan <- err
				} else {
					errChan <- nil
				}
				return
			}
		}
	}()

	// Pump 2: WebSocket Client -> PTY Input / Control Messages
	go func() {
		for {
			messageType, message, err := conn.ReadMessage()
			if err != nil {
				errChan <- err
				return
			}

			// Check for Control Messages (Lane 2: JSON Control Frame)
			if messageType == websocket.TextMessage && len(message) > 0 && message[0] == '{' {
				var ctrl ControlMessage
				if err := json.Unmarshal(message, &ctrl); err == nil && ctrl.Type != "" {
					h.handleControlMessage(ctrl, sessionID, safeWrite)
					continue
				}
			}

			// Lane 1: Raw Terminal Input -> PTY Stream
			if len(message) > 0 {
				if _, wErr := ptyStream.Write(message); wErr != nil {
					errChan <- wErr
					return
				}
			}
		}
	}()

	// Wait for any lane or connection error
	_ = <-errChan

	// Clean up session and sandbox when client disconnects
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cleanupCancel()
	_ = h.mngr.Destroy(cleanupCtx, sessionID)
}

func (h *Handler) handleControlMessage(ctrl ControlMessage, sessionID string, safeWrite func(int, []byte) error) {
	switch ctrl.Type {
	case "ping":
		_ = safeWrite(websocket.TextMessage, []byte(`{"type":"pong"}`))
	case "resize":
		slog.Debug("Terminal resize control message received", "session_id", sessionID, "cols", ctrl.Cols, "rows", ctrl.Rows)
		// PTY resize hook (can be propagated to runtime if supported)
	default:
		slog.Debug("Unknown control message type", "type", ctrl.Type)
	}
}
