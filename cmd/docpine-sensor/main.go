package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/labib0x9/docpine/internal/app/security"
	"github.com/labib0x9/docpine/internal/config"
	"github.com/labib0x9/docpine/internal/infra/ebpf"
	"github.com/labib0x9/docpine/internal/infra/postgres"
	transporthttp "github.com/labib0x9/docpine/internal/transport/http"
	"github.com/labib0x9/docpine/pkg/logger"
	_ "github.com/lib/pq"
)

func main() {
	cfg := config.GetConfig()

	logCloser, err := logger.Setup(cfg.Logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize logger: %v\n", err)
	}
	if logCloser != nil {
		defer logCloser.Close()
	}

	slog.Info("Starting Docpine eBPF Runtime Security Sensor & Monitor")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	db := postgres.NewPostgresConn(cfg.PostgreSQL)

	slog.Info("Connected to PostgreSQL database for runtime security events")
	repo := postgres.NewPostgresRepo(db)

	// 2. Initialize Security Engine & eBPF Manager
	engine := security.NewEngine(repo)
	bpfManager := ebpf.NewBPFManager(engine)

	if err := bpfManager.Start(ctx); err != nil {
		slog.Error("Failed to start eBPF manager", "error", err)
	}
	defer bpfManager.Close()

	// 3. Start Security REST API Server
	sensorAddr := cfg.Sensor.Addr

	mux := http.NewServeMux()
	secHandler := transporthttp.NewSecurityHandler(engine)
	secHandler.RegisterRoutes(mux)

	server := &http.Server{
		Addr:    sensorAddr,
		Handler: transporthttp.RequestId(transporthttp.Logger(transporthttp.Cors(mux))),
	}

	go func() {
		fmt.Printf("Docpine Security API listening on %s\n", sensorAddr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("Security HTTP Server error", "error", err)
		}
	}()

	<-ctx.Done()
	slog.Info("Shutdown signal received, shutting down sensor...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_ = server.Shutdown(shutdownCtx)
	slog.Info("Docpine Security Sensor shutdown complete.")
}
