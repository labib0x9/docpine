package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/labib0x9/docpine/internal/app/security"
	"github.com/labib0x9/docpine/internal/infra/ebpf"
	"github.com/labib0x9/docpine/internal/infra/postgres"
	transporthttp "github.com/labib0x9/docpine/internal/transport/http"
	_ "github.com/lib/pq"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	slog.Info("Starting Docpine eBPF Runtime Security Sensor & Monitor")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// 1. Initialize Storage Backend (Postgres or In-Memory)
	var repo postgres.Repository
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL != "" {
		db, err := sql.Open("postgres", dbURL)
		if err != nil {
			slog.Error("Failed to open Postgres connection", "error", err)
			os.Exit(1)
		}
		defer db.Close()

		if err := db.Ping(); err != nil {
			slog.Warn("Postgres not reachable, falling back to MemoryRepo", "error", err)
			repo = postgres.NewMemoryRepo()
		} else {
			slog.Info("Connected to PostgreSQL database for runtime security events")
			repo = postgres.NewPostgresRepo(db)
		}
	} else {
		slog.Info("DATABASE_URL not set: using in-memory security repository")
		repo = postgres.NewMemoryRepo()
	}

	// 2. Initialize Security Engine & eBPF Manager
	engine := security.NewEngine(repo)
	bpfManager := ebpf.NewBPFManager(engine)

	if err := bpfManager.Start(ctx); err != nil {
		slog.Error("Failed to start eBPF manager", "error", err)
	}
	defer bpfManager.Close()

	// 3. Start Security REST API Server
	sensorAddr := os.Getenv("DOCPINE_SENSOR_ADDR")
	if sensorAddr == "" {
		sensorAddr = ":8081"
	}

	mux := http.NewServeMux()
	secHandler := transporthttp.NewSecurityHandler(engine)
	secHandler.RegisterRoutes(mux)

	server := &http.Server{
		Addr:    sensorAddr,
		Handler: mux,
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
