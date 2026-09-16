# Implementation Plan: Pluggable Sandbox Runtime Layer & Anonymous Abuse Protection

Docpine is an ephemeral PTY shell service in Go delivering interactive sandboxes over WebSockets with a 5-minute TTL. This plan details the architectural refactor to introduce a pluggable `Runtime` interface supporting **Docker**, **gVisor (`runsc`)**, and **Firecracker** microVMs, alongside a multi-layered **Abuse Protection System** for anonymous session creation behind Cloudflare Tunnel.

## User Review Required

> [!IMPORTANT]
> - **Zero DDD restructuring / Package-by-Feature preserved**: All packages follow `internal/<feature>` (`internal/runtime`, `internal/abuse`, `internal/session`, `internal/transport`, `internal/websocket`).
> - **Prerequisite Checks & Visibly Skipping Tests**: Host-dependent backends (Firecracker requiring `/dev/kvm`, gVisor requiring `runsc`, Docker requiring Docker daemon) will fail fast at startup if selected, and their integration tests will skip cleanly and visibly with informative messages (e.g. `t.Skip("skipping firecracker test: /dev/kvm not found")`) rather than failing or silently passing.
> - **Cloudflare Tunnel Trust Assumption**: Because Docpine is exposed via Cloudflare Tunnel (`cloudflared`), client IP is extracted from `CF-Connecting-IP` (fallback `X-Forwarded-For`).
> - **Backend Architectural Tradeoffs**:
>   - **gVisor**: Implements container execution with `runsc`. Supports both Docker runtime configuration (`--runtime=runsc`) and direct OCI/`runsc` execution.
>   - **Firecracker**: MicroVM execution using guest serial console / FIFO PTY (documenting the tradeoff vs in-guest vsock agent).

---

## Proposed Architecture & Changes

```
                     ┌────────────────────────────────────────┐
                     │ Cloudflare Edge (Rate Limiting Rule)   │
                     └───────────────────┬────────────────────┘
                                         │ Cloudflare Tunnel
                                         ▼
                     ┌────────────────────────────────────────┐
                     │    Docpine HTTP / WS Transport         │
                     │  - Real-IP Extraction (CF-Connecting)  │
                     │  - Signed Device Cookie (__dp_dev)     │
                     │  - Token Bucket (IP + Cookie pair)     │
                     │  - Turnstile Gate & PoW Challenge      │
                     │  - Global Concurrency Cap              │
                     └───────────────────┬────────────────────┘
                                         │
                                         ▼
                     ┌────────────────────────────────────────┐
                     │           Session Manager              │
                     │  - 5-minute TTL Auto-Reaper            │
                     │  - Session ID <-> Sandbox mapping      │
                     └───────────────────┬────────────────────┘
                                         │
                                         ▼
                     ┌────────────────────────────────────────┐
                     │          internal/runtime              │
                     │  Runtime & Sandbox Interface Contract  │
                     └───────┬───────────┼───────────┬────────┘
                             │           │           │
            ┌────────────────┘           │           └────────────────┐
            ▼                            ▼                            ▼
  ┌───────────────────┐        ┌───────────────────┐        ┌───────────────────┐
  │   Docker Backend  │        │   gVisor Backend  │        │Firecracker Backend│
  │ (Sibling Container│        │ (runsc Sandboxed  │        │ (MicroVM + Serial │
  │  Alpine:3.20 PTY) │        │  OCI Container)   │        │     Console PTY)  │
  └───────────────────┘        └───────────────────┘        └───────────────────┘
```

---

## Proposed Changes

### Component 1: Pluggable Runtime Layer (`internal/runtime`)

#### [NEW] [runtime.go](file:///Users/labib0x9/Desktop/dockpine/internal/runtime/runtime.go)
- Defines core contracts:
  ```go
  type SandboxOptions struct {
      SessionID   string
      Image       string
      Command     []string
      Env         []string
      MemoryLimit int64
      CPUShares   int64
  }

  type Sandbox interface {
      ID() string
      AttachPTY(ctx context.Context) (io.ReadWriteCloser, error)
      Destroy(ctx context.Context) error
  }

  type Runtime interface {
      Name() string
      CheckPrerequisites(ctx context.Context) error
      CreateSandbox(ctx context.Context, opts SandboxOptions) (Sandbox, error)
      Close() error
  }
  ```
- Defines standard errors (`ErrPrerequisiteFailed`, `ErrSandboxNotFound`, `ErrRuntimeUnavailable`).

#### [NEW] [registry.go](file:///Users/labib0x9/Desktop/dockpine/internal/runtime/registry.go)
- Registry & factory for `"docker"`, `"gvisor"`, `"firecracker"`.
- `Init(ctx, name, config)` function that instantiates the requested runtime, performs `CheckPrerequisites()`, and fails fast if missing.

#### [NEW] [docker/docker.go](file:///Users/labib0x9/Desktop/dockpine/internal/runtime/docker/docker.go)
- Refactors existing Docker logic into `internal/runtime/docker`.
- Implements `Runtime` and `Sandbox` interfaces.
- `CheckPrerequisites()` verifies Docker daemon connectivity via `Ping()`.
- Wraps hijacked Docker stream into `io.ReadWriteCloser`.
- Integration test `docker_test.go` testing create -> attach PTY -> execute -> destroy, skipping cleanly if Docker daemon is not running.

#### [NEW] [gvisor/gvisor.go](file:///Users/labib0x9/Desktop/dockpine/internal/runtime/gvisor/gvisor.go)
- Implements `Runtime` and `Sandbox` for gVisor (`runsc`).
- `CheckPrerequisites()` checks for `runsc` availability in PATH or Docker daemon's configured `runsc` runtime.
- Creates sandboxed container with `runsc` isolation.
- Integration test `gvisor_test.go` with visible `t.Skip` on missing prerequisites.

#### [NEW] [firecracker/firecracker.go](file:///Users/labib0x9/Desktop/dockpine/internal/runtime/firecracker/firecracker.go)
- Implements `Runtime` and `Sandbox` for Firecracker microVMs.
- `CheckPrerequisites()` verifies `/dev/kvm` read/write access, `firecracker` binary, kernel image, and rootfs.
- Spawns Firecracker process configured with guest kernel & rootfs, wires serial console FIFO / PTY for bidirectional I/O.
- Integration test `firecracker_test.go` with visible `t.Skip` on missing `/dev/kvm` / binary.

#### [DELETE] [internal/docker](file:///Users/labib0x9/Desktop/dockpine/internal/docker)
- Replaced by `internal/runtime/docker`.

---

### Component 2: Session Management & Auto-Reaper (`internal/session`)

#### [MODIFY] [manager.go](file:///Users/labib0x9/Desktop/dockpine/internal/session/manager.go)
- Decouples completely from concrete Docker types, depending strictly on `runtime.Runtime` and `runtime.Sandbox`.
- Session tracking with TTL (default 5 minutes).
- Automated background reaper worker that scans and destroys expired sessions.
- Thread-safe session lookup, attach, and termination.

---

### Component 3: Abuse Protection Layer (`internal/abuse`)

#### [NEW] [ip.go](file:///Users/labib0x9/Desktop/dockpine/internal/abuse/ip.go)
- Extract client IP from `CF-Connecting-IP` (fallback `X-Forwarded-For`, fallback `RemoteAddr`).

#### [NEW] [cookie.go](file:///Users/labib0x9/Desktop/dockpine/internal/abuse/cookie.go)
- Server-issued, HMAC-SHA256 signed anonymous device cookie `__dp_dev`.
- Prevents client-side forging.

#### [NEW] [limiter.go](file:///Users/labib0x9/Desktop/dockpine/internal/abuse/limiter.go)
- Token bucket rate limiter keyed on combined `(IP, DeviceCookie)`.
- Secondary per-IP bucket.
- Automatic background eviction of stale buckets.

#### [NEW] [pow.go](file:///Users/labib0x9/Desktop/dockpine/internal/abuse/pow.go)
- Hash-based Proof-of-Work engine:
  - Generates HMAC-signed challenges with salt, timestamp, and target difficulty.
  - Verifies solution nonces in $O(1)$ time where `SHA256(challenge + salt + nonce)` satisfies difficulty.
  - Nonce expiry & replay protection.

#### [NEW] [turnstile.go](file:///Users/labib0x9/Desktop/dockpine/internal/abuse/turnstile.go)
- Cloudflare Turnstile token verification against `https://challenges.cloudflare.com/turnstile/v0/siteverify`.
- Dev/mock bypass support when secret is not configured or in test environments.

#### [NEW] [concurrency.go](file:///Users/labib0x9/Desktop/dockpine/internal/abuse/concurrency.go)
- Global concurrency limiter / semaphore for active anonymous sandboxes.
- Separate logging and metrics for aggregate capacity exhaustion vs per-client rate limiting.

#### [NEW] [middleware.go](file:///Users/labib0x9/Desktop/dockpine/internal/abuse/middleware.go)
- Unifies real-IP extraction, device cookie management, token bucket checks, Turnstile/PoW validation, and global concurrency cap.
- Responds with `429 Too Many Requests` + `Retry-After`, `428 Precondition Required` (with PoW challenge payload and Turnstile requirement), or `503 Service Unavailable`.

---

### Component 4: Transport & WebSocket Updates (`internal/transport`, `internal/websocket`)

#### [MODIFY] [handler.go](file:///Users/labib0x9/Desktop/dockpine/internal/transport/handler.go)
- Integrates abuse protection middleware on `POST /sessions` and adds `GET /challenges/pow` endpoint if client requests a fresh PoW puzzle.
- Returns proper JSON error responses and challenge payloads.

#### [MODIFY] [handler.go](file:///Users/labib0x9/Desktop/dockpine/internal/websocket/handler.go)
- Robust two-lane WebSocket implementation:
  - Lane 1: PTY I/O bi-directional pipe.
  - Lane 2: Control messages (resize terminal, heartbeat ping/pong).
  - Handles client disconnects, context cancellation, and ensures sandbox teardown upon disconnect or TTL expiry.

#### [MODIFY] [main.go](file:///Users/labib0x9/Desktop/dockpine/cmd/docpine/main.go)
- Environment variable configuration (`DOCPINE_RUNTIME`, `DOCPINE_MAX_SESSIONS`, `DOCPINE_POW_DIFFICULTY`, `DOCPINE_TURNSTILE_SECRET`, etc.).
- Runtime selection via factory with fail-fast prerequisite checks.
- Graceful shutdown of HTTP server, WebSocket connections, session reaper, and sandbox runtime.

---

### Component 5: Documentation & Tests

#### [MODIFY] [README.md](file:///Users/labib0x9/Desktop/dockpine/README.md)
- Complete guide to:
  - Switching runtimes (`DOCPINE_RUNTIME=docker|gvisor|firecracker`).
  - Host prerequisites for Docker, gVisor, and Firecracker.
  - Architectural tradeoffs (gVisor OCI vs Docker runtime; Firecracker serial console vs vsock).
  - Multi-layer abuse protection (Cloudflare Zone Rule, Real-IP, Signed Device Cookie, Combined Keying, Turnstile, PoW, Global Concurrency Cap).
  - Client abuse vs aggregate capacity exhaustion comparison.
  - Running test suite locally and in CI.

---

## Verification Plan

### Automated Tests
1. **Abuse Protection Suite**:
   ```bash
   go test -v ./internal/abuse/...
   ```
   - Real-IP header parsing tests (CF-Connecting-IP, X-Forwarded-For, fallback).
   - Signed device cookie creation, verification, tampering rejection tests.
   - Token bucket rate limiter concurrency and refill tests.
   - PoW challenge generation, solving, verification, replay, and expiry tests.
   - Concurrency limiter acquiring and releasing tests.
2. **Session Manager Suite**:
   ```bash
   go test -v ./internal/session/...
   ```
   - Session lifecycle, TTL reaper expiration, concurrent access.
3. **Transport & WebSocket Suite**:
   ```bash
   go test -v ./internal/transport/... ./internal/websocket/...
   ```
   - Rate limiting HTTP status codes (429 with `Retry-After`).
   - Challenge requirements (428 with challenge payload).
   - WebSocket upgrade and two-lane message routing.
4. **Runtime Matrix Integration Tests**:
   ```bash
   go test -v ./internal/runtime/...
   ```
   - Tests `docker`, `gvisor`, and `firecracker` packages.
   - Verifies clean and visible `t.Skip` when host prerequisites are missing.

### Manual Verification
- Start Docpine with different `DOCPINE_RUNTIME` settings.
- Verify fail-fast startup behavior when invalid backend or missing prereqs are specified.
- Verify HTTP `POST /sessions` challenge/rate limit behavior using `curl`.
- Verify full test suite passes with `go test ./...`.
