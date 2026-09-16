package logger

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/labib0x9/docpine/internal/config"
	"gopkg.in/natefinch/lumberjack.v2"
)

// MultiHandler dispatches log records to multiple underlying slog handlers.
type MultiHandler struct {
	handlers []slog.Handler
}

func (m *MultiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, h := range m.handlers {
		if h.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (m *MultiHandler) Handle(ctx context.Context, r slog.Record) error {
	var errs []error
	for _, h := range m.handlers {
		if h.Enabled(ctx, r.Level) {
			if err := h.Handle(ctx, r); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func (m *MultiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	cloned := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		cloned[i] = h.WithAttrs(attrs)
	}
	return &MultiHandler{handlers: cloned}
}

func (m *MultiHandler) WithGroup(name string) slog.Handler {
	cloned := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		cloned[i] = h.WithGroup(name)
	}
	return &MultiHandler{handlers: cloned}
}

// LevelFilterHandler filters records strictly according to a level predicate.
type LevelFilterHandler struct {
	handler   slog.Handler
	predicate func(level slog.Level) bool
}

func (f *LevelFilterHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return f.predicate(level) && f.handler.Enabled(ctx, level)
}

func (f *LevelFilterHandler) Handle(ctx context.Context, r slog.Record) error {
	if !f.predicate(r.Level) {
		return nil
	}
	return f.handler.Handle(ctx, r)
}

func (f *LevelFilterHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &LevelFilterHandler{
		handler:   f.handler.WithAttrs(attrs),
		predicate: f.predicate,
	}
}

func (f *LevelFilterHandler) WithGroup(name string) slog.Handler {
	return &LevelFilterHandler{
		handler:   f.handler.WithGroup(name),
		predicate: f.predicate,
	}
}

type multiCloser []io.Closer

func (mc multiCloser) Close() error {
	var errs []error
	for _, c := range mc {
		if c != nil {
			if err := c.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// Setup initializes the global slog logger.
// If Directory is specified in cfg (e.g. "logs"), it creates 4 split rotating log files:
//   - <Directory>/debug.log (DEBUG level only)
//   - <Directory>/info.log  (INFO level only)
//   - <Directory>/warn.log  (WARN level only)
//   - <Directory>/error.log (ERROR level and higher)
// If Filename is specified, it writes combined logs to that single file.
// In all cases, it streams to os.Stdout based on the configured Level.
func Setup(cfg *config.Logger) (io.Closer, error) {
	var closers multiCloser
	var handlers []slog.Handler

	consoleLevel := slog.LevelInfo
	format := "text"

	if cfg != nil {
		switch strings.ToLower(cfg.Level) {
		case "debug":
			consoleLevel = slog.LevelDebug
		case "warn":
			consoleLevel = slog.LevelWarn
		case "error":
			consoleLevel = slog.LevelError
		default:
			consoleLevel = slog.LevelInfo
		}

		if cfg.Format != "" {
			format = strings.ToLower(cfg.Format)
		}
	}

	createBaseHandler := func(w io.Writer, minLevel slog.Level) slog.Handler {
		opts := &slog.HandlerOptions{Level: minLevel}
		if format == "json" {
			return slog.NewJSONHandler(w, opts)
		}
		return slog.NewTextHandler(w, opts)
	}

	// 1. Console (Stdout) Handler
	stdoutHandler := createBaseHandler(os.Stdout, consoleLevel)
	handlers = append(handlers, stdoutHandler)

	// 2. 4-File Directory Mode (debug.log, info.log, warn.log, error.log)
	if cfg != nil && cfg.Directory != "" {
		if err := os.MkdirAll(cfg.Directory, 0755); err != nil {
			return nil, err
		}

		levels := []struct {
			name      string
			predicate func(l slog.Level) bool
		}{
			{
				name: "debug.log",
				predicate: func(l slog.Level) bool {
					return l == slog.LevelDebug
				},
			},
			{
				name: "info.log",
				predicate: func(l slog.Level) bool {
					return l == slog.LevelInfo
				},
			},
			{
				name: "warn.log",
				predicate: func(l slog.Level) bool {
					return l == slog.LevelWarn
				},
			},
			{
				name: "error.log",
				predicate: func(l slog.Level) bool {
					return l >= slog.LevelError
				},
			},
		}

		for _, lvl := range levels {
			filePath := filepath.Join(cfg.Directory, lvl.name)
			rotator := &lumberjack.Logger{
				Filename:   filePath,
				MaxSize:    cfg.MaxSize,
				MaxBackups: cfg.MaxBackups,
				MaxAge:     cfg.MaxAge,
				Compress:   cfg.Compress,
			}
			closers = append(closers, rotator)

			baseHandler := createBaseHandler(rotator, slog.LevelDebug)
			filterHandler := &LevelFilterHandler{
				handler:   baseHandler,
				predicate: lvl.predicate,
			}
			handlers = append(handlers, filterHandler)
		}
	} else if cfg != nil && cfg.Filename != "" {
		// 3. Single File Mode
		rotator := &lumberjack.Logger{
			Filename:   cfg.Filename,
			MaxSize:    cfg.MaxSize,
			MaxBackups: cfg.MaxBackups,
			MaxAge:     cfg.MaxAge,
			Compress:   cfg.Compress,
		}
		closers = append(closers, rotator)

		baseHandler := createBaseHandler(rotator, consoleLevel)
		handlers = append(handlers, baseHandler)
	}

	multiHandler := &MultiHandler{handlers: handlers}
	slog.SetDefault(slog.New(multiHandler))

	if len(closers) == 0 {
		return nil, nil
	}
	return closers, nil
}
