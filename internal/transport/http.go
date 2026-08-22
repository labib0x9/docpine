package transport

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/labib0x9/docpine/internal/websocket"
)

type Server struct {
	server    http.Server
	handler   *Handler
	wsHandler *websocket.Handler
}

func NewServer(handler *Handler, wsHandler *websocket.Handler) *Server {
	return &Server{handler: handler, wsHandler: wsHandler}
}

func (s *Server) Start() {
	mux := http.NewServeMux()

	s.handler.RegisterRoutes(mux)
	s.wsHandler.RegisterRoutes(mux)

	addr := "http://127.0.0.1:8080"
	s.server = http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	fmt.Printf("Starting Server at %s\n", addr)
	err := s.server.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("Server ListenAndServe():", "error", err)
	}
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}
