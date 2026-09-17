package websocket

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/labib0x9/docpine/internal/config"
	"github.com/labib0x9/docpine/internal/runtime/docker"
	"github.com/labib0x9/docpine/internal/session"
	"github.com/labib0x9/docpine/internal/utils"
)

// TestDocker_ConcurrentAttachLoad stress tests N simultaneous real Docker container sessions
// attached over WebSocket PTY streams.
//
// Usage:
//
//	# Run with default N=5
//	go test -v -run TestDocker_ConcurrentAttachLoad ./internal/transport/websocket/...
//
//	# Run with custom N (e.g. 20, 50, 100 concurrent containers) and higher timeout
//	CONCURRENT_SESSIONS=20 go test -v -timeout 15m -run TestDocker_ConcurrentAttachLoad ./internal/transport/websocket/...
func TestDocker_ConcurrentAttachLoad(t *testing.T) {
	utils.InitAllowedOrigins(&config.Config{AllowedOrigins: []string{"*"}})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dockerCfg := config.Runtime{
		Name:        "docker",
		Image:       "alpine:3.20",
		NetworkMode: "none",
		MemoryLimit: 64 * 1024 * 1024, // 64MB per sandbox for dense packing
	}

	rt, err := docker.New(ctx, dockerCfg)
	if err != nil {
		t.Fatalf("failed to initialize Docker runtime: %v", err)
	}
	defer rt.Close()

	if err := rt.CheckPrerequisites(ctx); err != nil {
		t.Skipf("Skipping real Docker concurrent load test: Docker daemon is unreachable (%v). Start Docker daemon to run this benchmark.", err)
		return
	}

	n := 5
	if envN := os.Getenv("CONCURRENT_SESSIONS"); envN != "" {
		if parsed, err := strconv.Atoi(envN); err == nil && parsed > 0 {
			n = parsed
		}
	}

	t.Logf("=================================================================")
	t.Logf("🚀 Starting Docker Concurrent Attach Load Benchmark: N = %d", n)
	t.Logf("=================================================================")

	tempDir := t.TempDir()
	mngr := session.NewManager(rt, 10*time.Minute)
	defer mngr.Close(context.Background())

	wsHandler := NewHandler(mngr, config.Logger{Directory: tempDir})
	mux := http.NewServeMux()
	wsHandler.RegisterRoutes(mux)

	server := httptest.NewServer(mux)
	defer server.Close()

	wsBaseURL := "ws" + strings.TrimPrefix(server.URL, "http")

	var (
		wg              sync.WaitGroup
		successCount    int64
		failureCount    int64
		totalSpawnNanos int64
		startBenchmark  = time.Now()
		holdBarrier     = make(chan struct{})
	)

	type workerResult struct {
		id       int
		sessID   string
		duration time.Duration
		err      error
	}

	results := make([]workerResult, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			start := time.Now()
			res := &results[workerID]
			res.id = workerID

			createCtx, createCancel := context.WithTimeout(ctx, 30*time.Second)
			sessID, err := mngr.Create(createCtx)
			createCancel()
			if err != nil {
				res.err = fmt.Errorf("session create failed: %w", err)
				atomic.AddInt64(&failureCount, 1)
				return
			}
			res.sessID = sessID

			wsURL := fmt.Sprintf("%s/sessions/%s/attach", wsBaseURL, sessID)
			dialer := websocket.Dialer{
				HandshakeTimeout: 15 * time.Second,
			}
			conn, _, err := dialer.Dial(wsURL, nil)
			if err != nil {
				res.err = fmt.Errorf("ws dial failed: %w", err)
				atomic.AddInt64(&failureCount, 1)
				_ = mngr.Destroy(context.Background(), sessID)
				return
			}
			defer conn.Close()

			pingTag := fmt.Sprintf("PING_WORKER_%d_%d", workerID, time.Now().UnixNano())
			cmd := fmt.Sprintf("echo %s\n", pingTag)
			if err := conn.WriteMessage(websocket.TextMessage, []byte(cmd)); err != nil {
				res.err = fmt.Errorf("ws write failed: %w", err)
				atomic.AddInt64(&failureCount, 1)
				_ = mngr.Destroy(context.Background(), sessID)
				return
			}

			_ = conn.SetReadDeadline(time.Now().Add(20 * time.Second))
			var output strings.Builder
			for {
				_, msg, err := conn.ReadMessage()
				if err != nil {
					res.err = fmt.Errorf("ws read failed waiting for response: %w (accumulated: %q)", err, output.String())
					atomic.AddInt64(&failureCount, 1)
					_ = mngr.Destroy(context.Background(), sessID)
					return
				}
				output.Write(msg)
				if strings.Contains(output.String(), pingTag) {
					break
				}
			}

			spawnDuration := time.Since(start)
			res.duration = spawnDuration
			atomic.AddInt64(&totalSpawnNanos, int64(spawnDuration))
			atomic.AddInt64(&successCount, 1)

			select {
			case <-holdBarrier:
			case <-ctx.Done():
			}

			_ = conn.Close()
			_ = mngr.Destroy(context.Background(), sessID)
		}(i)
	}

	time.Sleep(2 * time.Second)
	close(holdBarrier) // Release all workers to finish and tear down
	wg.Wait()

	totalDuration := time.Since(startBenchmark)

	sCount := atomic.LoadInt64(&successCount)
	fCount := atomic.LoadInt64(&failureCount)

	t.Logf("=================================================================")
	t.Logf("📊 BENCHMARK RESULTS (Concurrent Docker PTY Attach)")
	t.Logf("=================================================================")
	t.Logf("Target Concurrent Sessions:   %d", n)
	t.Logf("Successful Active Sandboxes:  %d (%.1f%%)", sCount, float64(sCount)/float64(n)*100)
	t.Logf("Failed Sessions:              %d", fCount)
	t.Logf("Total Benchmark Duration:     %v", totalDuration)

	if sCount > 0 {
		avgNanos := totalSpawnNanos / sCount
		t.Logf("Avg Provision + Attach Time:  %v", time.Duration(avgNanos))
	}

	for _, res := range results {
		if res.err != nil {
			t.Logf("  ❌ Worker %02d failed: %v", res.id, res.err)
		} else {
			t.Logf("  ✅ Worker %02d connected: session=%s in %v", res.id, res.sessID, res.duration)
		}
	}
	t.Logf("=================================================================")

	if fCount > 0 {
		t.Errorf("Concurrent load test experienced %d failures out of %d workers", fCount, n)
	}
}
