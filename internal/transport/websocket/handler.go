package websocket

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/labib0x9/docpine/internal/config"
	"github.com/labib0x9/docpine/internal/session"
	"github.com/labib0x9/docpine/internal/utils"
	"github.com/labib0x9/docpine/jsonio"
)

// ControlMessage represents out-of-band terminal control messages (Lane 2).
type ControlMessage struct {
	Type string `json:"type"` // e.g. "resize", "ping"
	Cols uint16 `json:"cols,omitempty"`
	Rows uint16 `json:"rows,omitempty"`
}

type Handler struct {
	mngr     *session.Manager
	upgrader websocket.Upgrader
	logDir   string
}

func NewHandler(mngr *session.Manager, cfg config.Logger) *Handler {
	logDir := filepath.Join(cfg.Directory, "sessions")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		slog.Warn("Failed to create session log directory", "error", err, "dir", logDir)
	}
	return &Handler{
		mngr: mngr,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  4096,
			WriteBufferSize: 4096,
			CheckOrigin:     utils.CheckOrigin,
		},
		logDir: logDir,
	}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.Handle(
		"GET /sessions/{id}/attach",
		http.HandlerFunc(h.Attach),
	)
}

// Attach upgrades the HTTP request to a full-duplex WebSocket and streams PTY terminal I/O.
func (h *Handler) Attach(w http.ResponseWriter, r *http.Request) {
	rId := r.Header.Get("X-Request-Id")
	sessionID := r.PathValue("id")
	if sessionID == "" {
		jsonio.SendError(w, "session id is required", http.StatusBadRequest)
		slog.Error("Session ID is required", "request_id", rId, "error", "session id is required")
		return
	}

	_, err := h.mngr.Get(sessionID)
	if err != nil {
		if errors.Is(err, session.ErrSessionNotFound) {
			jsonio.SendError(w, "session not found", http.StatusNotFound)
			slog.Error("Session not found", "request_id", rId, "session_id", sessionID, "error", err)
			return
		}
		if errors.Is(err, session.ErrSessionExpired) {
			jsonio.SendError(w, "session has expired", http.StatusGone)
			slog.Error("Session expired", "request_id", rId, "session_id", sessionID, "error", err)
			return
		}
		jsonio.SendError(w, "internal server error", http.StatusInternalServerError)
		slog.Error("Internal server error", "request_id", rId, "session_id", sessionID, "error", err)
		return
	}

	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("WebSocket upgrade failed", "request_id", rId, "error", err, "session_id", sessionID)
		return
	}
	defer conn.Close()

	attachCtx, cancel := context.WithCancel(r.Context())
	defer cancel()

	ptyStream, err := h.mngr.Attach(attachCtx, sessionID)
	if err != nil {
		slog.Error("Failed to attach to sandbox PTY", "request_id", rId, "error", err, "session_id", sessionID)
		_ = conn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseInternalServerErr, "sandbox attach failed"),
			time.Now().Add(time.Second),
		)
		return
	}
	defer ptyStream.Close()

	inLog, err := os.OpenFile(filepath.Join(h.logDir, fmt.Sprintf("%s.input.log", sessionID)), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		slog.Warn("Failed to open session input log file", "request_id", rId, "error", err, "session_id", sessionID)
	} else {
		defer inLog.Close()
	}

	outLog, err := os.OpenFile(filepath.Join(h.logDir, fmt.Sprintf("%s.output.log", sessionID)), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		slog.Warn("Failed to open session output log file", "request_id", rId, "error", err, "session_id", sessionID)
	} else {
		defer outLog.Close()
	}

	var writeMu sync.Mutex
	safeWrite := func(messageType int, data []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return conn.WriteMessage(messageType, data)
	}

	ttl := time.NewTimer(5 * time.Minute)
	defer ttl.Stop()
	errChan := make(chan error, 2)

	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := ptyStream.Read(buf)
			if n > 0 {
				if outLog != nil {
					_, _ = outLog.Write(buf[:n])
				}
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

	go func() {
		for {
			messageType, message, err := conn.ReadMessage()
			if err != nil {
				errChan <- err
				return
			}

			if messageType == websocket.TextMessage && len(message) > 0 && message[0] == '{' {
				var ctrl ControlMessage
				if err := json.Unmarshal(message, &ctrl); err == nil && ctrl.Type != "" {
					h.handleControlMessage(ctrl, sessionID, rId, safeWrite)
					continue
				}
			}

			if len(message) > 0 {
				if inLog != nil {
					_, _ = inLog.Write(message)
				}
				if _, wErr := ptyStream.Write(message); wErr != nil {
					errChan <- wErr
					return
				}
			}
		}
	}()

	select {
	case err := <-errChan:
		{
			if err != nil {
				slog.Error("Error occured in session", "request_id", rId, "session_id", sessionID, "error", err)
			}
			_ = safeWrite(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, "session closed"),
			)
		}
	case <-ttl.C:
		{
			slog.Warn("Session timeout", "request_id", rId, "session_id", sessionID)
			_ = safeWrite(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, "session duration limit reached"),
			)
		}
	}

	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cleanupCancel()
	_ = h.mngr.Destroy(cleanupCtx, sessionID)
}

func (h *Handler) handleControlMessage(ctrl ControlMessage, sessionID string, requestId string, safeWrite func(int, []byte) error) {
	switch ctrl.Type {
	case "ping":
		_ = safeWrite(websocket.TextMessage, []byte(`{"type":"pong"}`))
	case "resize":
		slog.Debug("Terminal resize control message received", "request_id", requestId, "session_id", sessionID, "cols", ctrl.Cols, "rows", ctrl.Rows)
	default:
		slog.Debug("Unknown control message type", "request_id", requestId, "session_id", sessionID, "type", ctrl.Type)
	}
}
