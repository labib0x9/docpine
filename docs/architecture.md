# Docpine Architecture: Pluggable Sandbox Platform

## 1. System Overview

Docpine is an ephemeral container and sandbox provisioning engine designed for running isolated, disposable Linux execution environments on-demand.

Key system capabilities:
- **Pluggable Sandbox Runtimes**: Standardized backend engine interface supporting **Docker containers**, **gVisor (`runsc`) userspace kernel sandboxes**, and **Firecracker microVMs** with automatic prerequisite detection and fail-fast validation.
- **Layered Abuse Protection**: Defense-in-depth protection for anonymous public endpoints behind Cloudflare Tunnel (`cloudflared`), featuring real client IP extraction, signed device cookies (HMAC-SHA256), token-bucket rate limiting, Cloudflare Turnstile, and a global concurrency cap.
- **Ephemeral Session Lifecycle**: In-memory registry with a strict 5-minute TTL reaper, graceful draining, and asynchronous sandbox destruction.
- **Bidirectional WebSocket PTY**: Low-latency interactive pseudo-terminal streaming using xterm.js-compatible binary streams.

---

## 2. Core Architecture Diagram

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

## 3. Pluggable Runtime Layer

Docpine completely decouples session tracking and WebSocket multiplexing from the underlying container technology via the `runtime.Runtime` interface in `internal/runtime`:

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

### Backend Comparison & Architectural Tradeoffs

| Backend | Driver | Host Prerequisites | Architectural Tradeoffs |
| :--- | :--- | :--- | :--- |
| **Docker** | `docker` | Docker daemon reachable | Standard sibling-container execution using Docker API hijack streaming. Fast, ubiquitous, minimal configuration. |
| **gVisor** | `gvisor` | `runsc` on `$PATH` + Docker daemon `runsc` runtime | Drives `runsc` via Docker daemon configuration, gaining OCI image distribution and network isolation while gVisor's Sentry kernel intercepts syscalls in user space. |
| **Firecracker** | `firecracker` | Linux `/dev/kvm`, `firecracker` binary, `vmlinux`, `rootfs.ext4` | Wires guest serial console `ttyS0` to named host FIFOs. Zero guest agent dependencies, instantaneous boot terminal access, and pure 1:1 hardware virtualization isolation per session. |

---

## 4. Layered Abuse Protection

1. **Real IP Extraction**: Strictly reads `CF-Connecting-IP` (falling back to first `X-Forwarded-For` entry or `RemoteAddr`), preventing IP spoofing behind reverse proxies.
2. **Signed Device Cookie (`__dp_dev`)**: HMAC-SHA256 signed cookie identifying client devices across IP rotations.
3. **Dual Token-Bucket Rate Limiter**: Per-IP and per-Device bucket limiting burst and refill rates.
4. **Cloudflare Turnstile Verification**: Challenge token verification for human verification.
5. **Global Concurrency Cap**: Strict aggregate limit of simultaneous active sandboxes with immediate 429 backoff when full.
