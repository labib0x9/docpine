package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/jmoiron/sqlx"
	"github.com/labib0x9/docpine/internal/config"
	"github.com/labib0x9/docpine/internal/queue"
	"github.com/labib0x9/docpine/internal/repository"
	"github.com/labib0x9/docpine/internal/runner"
	"github.com/labib0x9/docpine/internal/worker"
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

	db, err := sqlx.Connect("postgres", cfg.Database.DSN)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to connect to postgres: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	queueClient, err := queue.New(cfg.RabbitMQ.URL, cfg.RabbitMQ.Queue, cfg.RabbitMQ.EventsExchange)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to connect to rabbitmq: %v\n", err)
		os.Exit(1)
	}
	defer queueClient.Close()

	testRunner, err := runner.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize docker runner: %v\n", err)
		os.Exit(1)
	}
	defer testRunner.Close()

	labRepo := repository.NewLabRepository(*db)
	labWorker := worker.New(labRepo, queueClient, testRunner, cfg.Lab)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errorsCh := make(chan error, 1)
	go func() {
		errorsCh <- queueClient.Consume(ctx, labWorker.Process)
	}()

	slog.Info("Docpine worker ready", "queue", cfg.RabbitMQ.Queue, "events", cfg.RabbitMQ.EventsExchange)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
	select {
	case <-quit:
	case err := <-errorsCh:
		if !errors.Is(err, context.Canceled) {
			slog.Error("worker stopped", "error", err)
		}
	}

	cancel()
	slog.Info("Docpine worker shutdown complete")
}
