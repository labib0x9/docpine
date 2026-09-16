package logger_test

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/labib0x9/docpine/internal/config"
	"github.com/labib0x9/docpine/pkg/logger"
)

func TestSetupLogger_StdoutOnly(t *testing.T) {
	closer, err := logger.Setup(&config.Logger{
		Format: "json",
		Level:  "info",
	})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if closer != nil {
		t.Errorf("expected closer to be nil when no filename/directory is configured")
	}

	slog.Info("stdout log test message")
}

func TestSetupLogger_SingleRotatingFile(t *testing.T) {
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "test_app.log")

	closer, err := logger.Setup(&config.Logger{
		Filename:   logFile,
		MaxSize:    10,
		MaxBackups: 2,
		MaxAge:     1,
		Compress:   false,
		Format:     "json",
		Level:      "debug",
	})
	if err != nil {
		t.Fatalf("failed to setup logger: %v", err)
	}
	defer func() {
		if closer != nil {
			_ = closer.Close()
		}
	}()

	slog.Info("single file test entry", "key", "value")

	if closer != nil {
		_ = closer.Close()
	}

	content, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("expected log file to exist: %v", err)
	}

	if len(content) == 0 {
		t.Fatalf("expected log file content to not be empty")
	}
}

func TestSetupLogger_FourFileLevelSplit(t *testing.T) {
	tempDir := t.TempDir()

	closer, err := logger.Setup(&config.Logger{
		Directory:  tempDir,
		MaxSize:    10,
		MaxBackups: 2,
		MaxAge:     1,
		Compress:   false,
		Format:     "text",
		Level:      "debug",
	})
	if err != nil {
		t.Fatalf("failed to setup 4-file logger: %v", err)
	}

	slog.Debug("this is debug message", "module", "debug-test")
	slog.Info("this is info message", "module", "info-test")
	slog.Warn("this is warn message", "module", "warn-test")
	slog.Error("this is error message", "module", "error-test")

	if closer != nil {
		_ = closer.Close()
	}

	// Verify debug.log contains debug but not info/warn/error
	debugBytes, err := os.ReadFile(filepath.Join(tempDir, "debug.log"))
	if err != nil {
		t.Fatalf("failed to read debug.log: %v", err)
	}
	debugContent := string(debugBytes)
	if !strings.Contains(debugContent, "this is debug message") {
		t.Errorf("expected debug.log to contain debug message, got: %s", debugContent)
	}
	if strings.Contains(debugContent, "this is error message") {
		t.Errorf("expected debug.log NOT to contain error message")
	}

	// Verify info.log contains info but not debug
	infoBytes, err := os.ReadFile(filepath.Join(tempDir, "info.log"))
	if err != nil {
		t.Fatalf("failed to read info.log: %v", err)
	}
	infoContent := string(infoBytes)
	if !strings.Contains(infoContent, "this is info message") {
		t.Errorf("expected info.log to contain info message, got: %s", infoContent)
	}
	if strings.Contains(infoContent, "this is debug message") {
		t.Errorf("expected info.log NOT to contain debug message")
	}

	// Verify warn.log contains warn
	warnBytes, err := os.ReadFile(filepath.Join(tempDir, "warn.log"))
	if err != nil {
		t.Fatalf("failed to read warn.log: %v", err)
	}
	warnContent := string(warnBytes)
	if !strings.Contains(warnContent, "this is warn message") {
		t.Errorf("expected warn.log to contain warn message, got: %s", warnContent)
	}

	// Verify error.log contains error
	errorBytes, err := os.ReadFile(filepath.Join(tempDir, "error.log"))
	if err != nil {
		t.Fatalf("failed to read error.log: %v", err)
	}
	errorContent := string(errorBytes)
	if !strings.Contains(errorContent, "this is error message") {
		t.Errorf("expected error.log to contain error message, got: %s", errorContent)
	}
}
