package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/labib0x9/docpine/internal/abuse"
	"github.com/labib0x9/docpine/internal/config"
	"github.com/labib0x9/docpine/internal/runtime"
	_ "github.com/labib0x9/docpine/internal/runtime/docker"
	_ "github.com/labib0x9/docpine/internal/runtime/firecracker"
	_ "github.com/labib0x9/docpine/internal/runtime/gvisor"
	"github.com/labib0x9/docpine/internal/session"
	transporthttp "github.com/labib0x9/docpine/internal/transport/http"
	"github.com/labib0x9/docpine/internal/websocket"
)

func main() {
	// Configure structured JSON/text logging
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	cfg := config.LoadFromEnv()

	slog.Info("Starting Docpine Sandbox Engine",
		"runtime", cfg.RuntimeName,
		"addr", cfg.Addr,
		"session_ttl", cfg.SessionTTL,
		"max_concurrent_sessions", cfg.MaxConcurrent,
		"pow_difficulty", cfg.PoWDifficulty,
		"turnstile_enabled", cfg.TurnstileKey != "",
	)

	// 1. Initialize Pluggable Runtime Backend with Prerequisite Validation
	initCtx, initCancel := context.WithTimeout(context.Background(), 10*time.Second)
	rt, err := runtime.New(initCtx, cfg.RuntimeName, cfg.Runtime)
	initCancel()
	if err != nil {
		slog.Error("FATAL: Runtime backend initialization failed", "runtime", cfg.RuntimeName, "error", err)
		fmt.Fprintf(os.Stderr, "\n[FATAL] Failed to initialize runtime backend %q: %v\n\n", cfg.RuntimeName, err)
		os.Exit(1)
	}
	defer rt.Close()

	// 2. Initialize Abuse Protection Guard
	guard := abuse.NewGuard(cfg.ToGuardConfig())

	// 3. Initialize Ephemeral Session Manager
	mngr := session.NewManager(rt, cfg.SessionTTL)
	mngr.OnDestroy(func(sessionID string) {
		guard.ConcurrencyLimiter().Release()
	})
	defer func() {
		shutdownCtx, sCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer sCancel()
		_ = mngr.Close(shutdownCtx)
	}()

	// 4. Initialize Transport and WebSocket Handlers
	handler := transporthttp.NewSessionHandler(mngr, guard)
	wsHandler := websocket.NewHandler(mngr)
	server := transporthttp.NewServer(cfg.Addr, handler, wsHandler)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		if err := server.Start(); err != nil {
			slog.Error("Server stopped with error", "error", err)
		}
	}()

	<-ctx.Done()
	slog.Info("Shutdown signal received, draining active sandboxes and connections...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Error("Error during HTTP server shutdown", "error", err)
	}
	slog.Info("Docpine shutdown complete.")
}
