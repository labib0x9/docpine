package main

import (
	"context"
	"os/signal"
	"syscall"
	"time"

	"github.com/labib0x9/docpine/internal/docker"
	"github.com/labib0x9/docpine/internal/session"
	"github.com/labib0x9/docpine/internal/transport"
	"github.com/labib0x9/docpine/internal/websocket"
)

func main() {

	dockerRepo := docker.NewClient()
	defer dockerRepo.Close()

	mngr := session.NewManager(dockerRepo)

	handler := transport.NewHandler(mngr)
	wsHandler := websocket.NewHandler(mngr)
	server := transport.NewServer(handler, wsHandler)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		server.Start()
	}()

	<-ctx.Done()

	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	server.Shutdown(shutdown)

}
