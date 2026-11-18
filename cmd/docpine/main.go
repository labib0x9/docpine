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

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/labib0x9/docpine/internal/abuse"
	"github.com/labib0x9/docpine/internal/config"
	"github.com/labib0x9/docpine/internal/handler"
	"github.com/labib0x9/docpine/internal/middleware"
	"github.com/labib0x9/docpine/internal/queue"
	"github.com/labib0x9/docpine/internal/repository"
	"github.com/labib0x9/docpine/internal/service"
	"github.com/labib0x9/docpine/internal/sse"
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

	authRepo := repository.NewAuthRepository(*db)
	labRepo := repository.NewLabRepository(*db)
	hub := sse.NewHub()
	authService := service.NewAuthService(cfg.OAuthGithub, authRepo)
	labService := service.NewLabService(labRepo, queueClient)
	turnstileValidator := abuse.NewTurnstileValidator(cfg.Abuse.TurnstileSecret)

	authHandler := handler.NewAuthHandler(authService, cfg.OAuthGithub.ForceSecure)
	labHandler := handler.NewLabHandler(labService, hub)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errorsCh := make(chan error, 2)
	go func() {
		errorsCh <- queueClient.ConsumeEvents(ctx, func(_ context.Context, event queue.LabEvent) error {
			sseEvent := sse.Event{Type: event.Type, Data: event.Data}
			if event.Type == "result" || event.Type == "error" {
				hub.Finish(event.RunID, sseEvent)
				return nil
			}
			hub.Publish(event.RunID, sseEvent)
			return nil
		})
	}()

	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	engine.Use(
		gin.Recovery(),
		middleware.RequestID(),
		middleware.Logger(),
		middleware.Cors(cfg.AllowedOrigins),
	)

	engine.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	v1 := engine.Group("/v1")
	{
		auth := v1.Group("/auth")
		{
			auth.POST("/login", middleware.Turnstile(turnstileValidator), authHandler.Login)
			auth.GET("/login", authHandler.Login)
			auth.GET("/callback", authHandler.Callback)
			auth.POST("/callback", authHandler.Callback)
			auth.POST("/logout", authHandler.Logout)
		}

		protected := v1.Group("")
		protected.Use(handler.RequireAuth(cfg.OAuthGithub.SessionSecret, authRepo))
		{
			protected.GET("/me", authHandler.Me)
			protected.GET("/labs", labHandler.ListLabs)
			protected.PUT("/me/repo", labHandler.SetRepo)
			protected.GET("/me/repo", labHandler.GetRepo)
			protected.POST("/labs/:id/runs", middleware.Turnstile(turnstileValidator), labHandler.CreateRun)
			protected.GET("/labs/:id/runs", labHandler.ListRuns)
			protected.GET("/labs/:id/runs/:runID", labHandler.GetRun)
			protected.GET("/labs/:id/runs/:runID/result", labHandler.GetResult)
			protected.GET("/labs/:id/runs/:runID/events", labHandler.Events)
		}
	}

	srv := http.Server{
		Addr:              fmt.Sprintf("%s:%d", cfg.Addr, cfg.Port),
		Handler:           engine,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errorsCh <- err
		}
	}()

	slog.Info("Docpine API ready", "addr", srv.Addr, "queue", cfg.RabbitMQ.Queue)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
	select {
	case <-quit:
	case err := <-errorsCh:
		if !errors.Is(err, context.Canceled) {
			slog.Error("service stopped", "error", err)
		}
	}

	cancel()
	hub.Shutdown()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("server shutdown", "error", err)
	}
	slog.Info("Docpine shutdown complete")
}
