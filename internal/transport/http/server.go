package http

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/labib0x9/docpine/internal/config"
	"github.com/labib0x9/docpine/internal/transport/websocket"
)

// Server wraps the standard HTTP server multiplexing REST and WebSocket handlers.
type Server struct {
	addr      string
	server    *http.Server
	handler   *SessionHandler
	wsHandler *websocket.Handler
}

// NewServer constructs a new HTTP server.
func NewServer(cnf *config.Config, handler *SessionHandler, wsHandler *websocket.Handler) *Server {
	addr := fmt.Sprintf("%s:%d", cnf.Addr, cnf.Port)
	initAllowedOrigins(cnf)
	return &Server{
		addr:      addr,
		handler:   handler,
		wsHandler: wsHandler,
	}
}

// Start registers routes and starts listening for incoming HTTP and WebSocket connections.
func (s *Server) Start() error {
	mux := http.NewServeMux()

	s.handler.RegisterRoutes(mux)
	s.wsHandler.RegisterRoutes(mux)

	s.server = &http.Server{
		Addr:    s.addr,
		Handler: RequestId(Logger(Cors(mux))),
	}

	fmt.Printf("Docpine listening on http://%s\n", s.addr)
	err := s.server.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("Server ListenAndServe failed", "error", err)
		return err
	}
	return nil
}

// Shutdown initiates a graceful shutdown of the HTTP server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.server != nil {
		return s.server.Shutdown(ctx)
	}
	return nil
}
