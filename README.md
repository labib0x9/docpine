# dockpine 🐳 

A Go ephemeral container platform combining **pluggable sandbox runtimes** (Docker, gVisor, Firecracker), **layered abuse protection** for anonymous public sessions behind Cloudflare Tunnel, and interactive bidirectional terminal streaming over WebSockets.

---

## Table of Contents

- [Overview](#-overview)
- [Architecture](#-architecture)
- [Subsystem 1: Pluggable Sandbox Runtime Layer](#-subsystem-1-pluggable-sandbox-runtime-layer)
- [Subsystem 2: Abuse Protection (Behind Cloudflare Tunnel)](#-subsystem-2-abuse-protection-behind-cloudflare-tunnel)
- [API Reference](#-api-reference)
- [Environment Configuration](#️-environment-configuration)
- [Testing Matrix & CI](#-testing-matrix--ci)
- [Getting Started](#-getting-started)

---

## Overview

Dockpine provisions isolated, ephemeral **Alpine Linux (`alpine:3.20`)** sandboxes on-demand and streams bidirectional interactive PTY terminal sessions over **WebSockets** with a 5-minute TTL.

### Core Pillars
1. **Pluggable Sandbox Runtimes**: Switch seamlessly between **Docker containers**, **gVisor (`runsc`) sandboxes**, and **Firecracker microVMs** with zero changes to session/transport code.
2. **Layered Abuse Protection**: Multi-tiered defense-in-depth against compute exhaustion on public anonymous endpoints behind **Cloudflare Tunnel (`cloudflared`)**.
3. **Interactive PTY Streaming**: Low-latency binary and control frame multiplexing for browser terminal emulation (xterm.js).

---

## Architecture

```
                                    Incoming Traffic
                                           │
                        ┌──────────────────┴──────────────────┐
                        │   Cloudflare Edge (Rate Limiting)   │
                        └──────────────────┬──────────────────┘
                                           │ Cloudflare Tunnel (cloudflared)
                                           ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                                 CONTROL PLANE (cmd/docpine)                                 │
│                                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────────────────────┐   │
│   │                              Abuse Protection Guard                                 │   │
│   │  • Real IP Extraction (CF-Connecting-IP)       • Cloudflare Turnstile Gate          │   │
│   │  • Signed Device Cookie (__dp_dev HMAC)        • Combined (IP, Cookie) Token Bucket │   │
│   │  • Global Concurrency Cap (Backstop)                                                │   │
│   └──────────────────────────────────┬──────────────────────────────────────────────────┘   │
│                                      │ (Allowed)                                            │
│                                      ▼                                                      │
│   ┌─────────────────────────────────────────────────────────────────────────────────────┐   │
│   │                 Session Manager (In-Memory Registry + 5-minute TTL Reaper)          │   │
│   └──────────────────────────────────┬──────────────────────────────────────────────────┘   │
│                                      │                                                      │
│                                      ▼                                                      │
│   ┌─────────────────────────────────────────────────────────────────────────────────────┐   │
│   │                            internal/runtime (Interface)                             │   │
│   │              DOCPINE_RUNTIME = docker | gvisor (runsc) | firecracker                │   │
│   └───────────────┬──────────────────────────┬──────────────────────────┬───────────────┘   │
└───────────────────┼──────────────────────────┼──────────────────────────┼───────────────────┘
                    │                          │                          │
                    ▼                          ▼                          ▼
          ┌───────────────────┐      ┌───────────────────┐      ┌───────────────────┐
          │  Docker Sandbox   │      │  gVisor (runsc)   │      │Firecracker MicroVM│
          │ (Alpine 3.20 PTY) │      │  (Sentry Sandbox) │      │(Guest Serial PTY) │
          └───────────────────┘      └───────────────────┘      └───────────────────┘
```

---

## Subsystem 1: Pluggable Sandbox Runtime Layer

Dockpine completely decouples session tracking and WebSocket multiplexing from the underlying container technology via the `runtime.Runtime` interface in `internal/runtime`:

```go
type Runtime interface {
    Name() string
    CheckPrerequisites(ctx context.Context) error
    CreateSandbox(ctx context.Context, opts SandboxOptions) (Sandbox, error)
    Close() error
}

type Sandbox interface {
    ID() string
    AttachPTY(ctx context.Context) (io.ReadWriteCloser, error)
    Destroy(ctx context.Context) error
}
```

### Backend Selection
Select the active backend at startup using `RUNTIME_NAME` (or environment variable `DOCPINE_RUNTIME`):
```bash
# Options: docker (default) | gvisor | firecracker
export DOCPINE_RUNTIME=docker
```
Dockpine verifies host requirements upon startup and **fails fast and loudly** if prerequisites are missing.

### Backend Comparison & Architectural Tradeoffs

| Backend | Driver | Host Prerequisites | Tradeoff & Architectural Decision |
| :--- | :--- | :--- | :--- |
| **Docker** | `docker` | Docker daemon reachable | Standard sibling-container execution using Docker API hijack streaming. Fast, ubiquitous, minimal configuration. |
| **gVisor** | `gvisor` | `runsc` on `$PATH` + Docker daemon `runsc` runtime | **Tradeoff:** Docker `--runtime=runsc` vs direct OCI bundles.<br>**Decision:** Docpine drives `runsc` via Docker daemon configuration, gaining OCI image distribution and network isolation while gVisor's Sentry kernel intercepts syscalls in user space. |
| **Firecracker** | `firecracker` | Linux `/dev/kvm`, `firecracker` binary, `vmlinux`, `rootfs.ext4` | **Tradeoff:** Guest serial console (`ttyS0`) over FIFOs vs in-guest vsock daemon (`AF_VSOCK`).<br>**Decision:** Docpine wires guest serial console `ttyS0` to named host FIFOs. Zero guest agent dependencies, instantaneous boot terminal access, and pure 1:1 hardware virtualization isolation per session. *(Requires Linux with KVM).* |

---

## Subsystem 2: Abuse Protection (Behind Cloudflare Tunnel)

To defend anonymous public creation endpoints (`POST /sessions`) against denial-of-service and transient compute pressure, Dockpine implements layered security:

```
[ Incoming Request ]
        │
        ▼
[ Layer 0: Cloudflare Zone Rate Limiting Rule ] ── (Edge Coarse Filter)
        │
        ▼ (Cloudflare Tunnel: cloudflared)
[ Layer 1: Real IP Extraction ] ── (Strictly CF-Connecting-IP, never RemoteAddr)
        │
        ▼
[ Layer 2: Signed Device Cookie ] ── (Server-issued HMAC-SHA256 __dp_dev)
        │
        ▼
[ Layer 3: Global Concurrency Cap ] ── (Hard Host Ceiling: Max N Sandboxes)
        │
        ├── Full? ──► HTTP 429 / 503 (Capacity Reached)
        │
        ▼
[ Layer 4: Cloudflare Turnstile Gate ] ── (Challenge Verification)
        │
        ▼
[ Layer 5: Token Bucket Rate Limiter ] ── (Keyed on (IP, DeviceCookie) Pair)
        │
        ├── Throttled? ──► HTTP 429 Too Many Requests
        │
        ▼
[ Sandbox Provisioned & 5-minute TTL Started ]
```

### Protection Layers
1. **Real IP Extraction**: Since traffic arrives via `cloudflared` on localhost, real client IP is strictly parsed from `CF-Connecting-IP` (fallback `X-Forwarded-For`).
2. **Signed Device Cookie (`__dp_dev`)**: Server-issued, HMAC-SHA256 signed browser cookie (`<uuid>.<timestamp>.<signature>`) preventing client tampering.
3. **Combined Keying Token Bucket**: Rate limits on composite `(IP, DeviceCookie)` pairs with secondary per-IP limits.
4. **Cloudflare Turnstile Gate**: Server-side token validation via Cloudflare `siteverify` API.
5. **Hard Global Concurrency Cap**: Atomic semaphore enforcing a hard ceiling on concurrent active anonymous sandboxes (e.g. 20).

---

## API Reference

### 1. Create Anonymous Sandbox Session
- **Endpoint:** `POST /sessions`
- **Headers (Optional):** `CF-Turnstile-Response: <token>`
- **Request Body (Optional):**
```json
{
  "turnstile_token": "0.example-turnstile-token"
}
```
- **Responses:**
  - `201 Created`: `{"session_id": "8a3e9c20-...", "expires_in_sec": 300}`
  - `428 Precondition Required`: `{"error": "challenge_required", "pow_challenge": {...}}`
  - `429 Too Many Requests`: `{"error": "rate_limited", "retry_after": 30}`
  - `503 Service Unavailable`: `{"error": "global_capacity_reached"}`

### 2. Attach Interactive WebSocket Terminal
- **Endpoint:** `GET /sessions/{session_id}/attach`
- **Protocol:** `ws://` / `wss://`
- **Lane 1 (Terminal I/O):** Raw bidirectional bytes.
- **Lane 2 (Control Frames):** JSON frames (e.g. `{"type": "resize", "cols": 120, "rows": 40}`, `{"type": "ping"}`).

---

## Environment Configuration

| Variable | Default | Description |
| :--- | :--- | :--- |
| `RUNTIME_NAME` | `docker` | Runtime backend: `docker`, `gvisor`, `firecracker` |
| `ADDR` / `PORT` | `0.0.0.0:8080` | HTTP/WS server listen address |
| `SESSION_TTL` | `5m` | Ephemeral sandbox TTL |
| `MAX_SESSIONS` | `20` | Global concurrency limit on active sandboxes |
| `RATE_LIMIT_BURST` | `5` | Token bucket burst capacity |
| `RATE_LIMIT_REFILL` | `30s` | Token refill duration |
| `TURNSTILE_SECRET` | `""` | Cloudflare Turnstile secret key |
| `COOKIE_SECRET` | `""` | Secret key for signing `__dp_dev` cookies |
| `ALLOWED_ORIGINS` | `""` | Comma-separated list of allowed CORS / WS origins |
| `RUNSC_PATH` | `runsc` | Path to `runsc` binary (gVisor) |
| `FIRECRACKER_BIN` | `firecracker` | Path to `firecracker` binary |
| `KERNEL_PATH` | `/var/lib/docpine/vmlinux` | Path to guest kernel (Firecracker) |
| `ROOTFS_PATH` | `/var/lib/docpine/rootfs.ext4` | Path to guest rootfs (Firecracker) |

---

## Getting Started

### 1. Clone and Install
```bash
git clone https://github.com/labib0x9/docpine.git
cd docpine
go mod tidy
```

### 2. Configure Environment
```bash
cp .env.example .env
```

### 3. Start Control Plane (Port 8080)
```bash
# Docker backend
go run ./cmd/docpine

# Or gVisor backend
DOCPINE_RUNTIME=gvisor go run ./cmd/docpine
```