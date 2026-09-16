# dockpine (🐳)

A Go ephemeral container platform combining **pluggable sandbox runtimes** (Docker, gVisor, Firecracker), **layered abuse protection** for anonymous public sessions behind Cloudflare Tunnel, and **eBPF-powered runtime security monitoring** with kernel-level policy enforcement.

---

## 📑 Table of Contents

- [Overview](#-overview)
- [Architecture](#-architecture)
- [Subsystem 1: Pluggable Sandbox Runtime Layer](#-subsystem-1-pluggable-sandbox-runtime-layer)
- [Subsystem 2: Abuse Protection (Behind Cloudflare Tunnel)](#-subsystem-2-abuse-protection-behind-cloudflare-tunnel)
- [Subsystem 3: eBPF Runtime Security & Behavioral Detection](#-subsystem-3-ebpf-runtime-security--behavioral-detection)
- [📡 API Reference](#-api-reference)
- [⚙️ Environment Configuration](#️-environment-configuration)
- [🔬 Lab Attack Scenarios](#-lab-attack-scenarios)
- [🧪 Testing Matrix & CI](#-testing-matrix--ci)
- [💻 Getting Started](#-getting-started)

---

## 🚀 Overview

Dockpine provisions isolated, ephemeral **Alpine Linux (`alpine:3.20`)** sandboxes on-demand and streams bidirectional interactive PTY terminal sessions over **WebSockets** with a 5-minute TTL.

### Core Pillars
1. **Pluggable Sandbox Runtimes**: Switch seamlessly between **Docker containers**, **gVisor (`runsc`) sandboxes**, and **Firecracker microVMs** with zero changes to session/transport code.
2. **Layered Abuse Protection**: Multi-tiered defense-in-depth against compute exhaustion on public anonymous endpoints behind **Cloudflare Tunnel (`cloudflared`)**.
3. **eBPF Runtime Security Engine**: Kernel-space syscall observation tagged with `cgroup_id`, temporal sliding-window behavioral correlation, and synchronous in-kernel policy enforcement (BPF LSM, cgroup BPF).

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
│   │  • Real IP Extraction (CF-Connecting-IP)       • Proof-of-Work (PoW) Engine         │   │
│   │  • Signed Device Cookie (__dp_dev HMAC)        • Cloudflare Turnstile Gate          │   │
│   │  • Combined (IP, Cookie) Token Bucket          • Global Concurrency Cap (Backstop)  │   │
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
          └─────────┬─────────┘      └─────────┬─────────┘      └─────────┬─────────┘
                    │                          │                          │
════════════════════╪══════════════════════════╪══════════════════════════╪══════════════════════
                    │ (Kernel Syscalls Tagged with cgroup_id)             │
                    ▼                                                     ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                       RUNTIME SECURITY & MONITORING (cmd/docpine-sensor)                    │
│                                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────────────────────┐   │
│   │                        In-Kernel eBPF Programs (bpf/)                               │   │
│   │  • trace_sys_enter (raw_syscalls)              • block_file_open (BPF LSM)          │   │
│   │  • sched_process_fork / exec / exit            • net_connect4 / 6 (cgroup BPF)      │   │
│   └──────────────────────────────────┬───────────────────────────────────▲──────────────┘   │
│                                      │ (RINGBUF Map Stream)              │                  │
│                                      ▼                                   │ BPF Policy Maps  │
│   ┌──────────────────────────────────────────────────────────────────────┴──────────────┐   │
│   │                       Behavioral Correlation Engine (Go)                            │   │
│   │  • Process Ancestry Lineage                     • Capability Drift Tracking         │   │
│   │  • Flagship Detection: Shell-to-Exfil           • Namespace Drift Detection         │   │
│   │  • Host Exposure Risk Scoring                   • In-Kernel Policy Compiler         │   │
│   └──────────────────────────────────┬──────────────────────────────────────────────────┘   │
│                                      │                                                      │
│                                      ▼                                                      │
│                         PostgreSQL / In-Memory Store                                        │
│                 (GET /containers/{id}/findings & /timeline)                                 │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
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
Select the active backend at startup using `DOCPINE_RUNTIME`:
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

## 🛡️ Subsystem 2: Abuse Protection (Behind Cloudflare Tunnel)

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
[ Layer 6: Global Concurrency Cap ] ── (Hard Host Ceiling: Max N Sandboxes)
        │
        ├── Full? ──► HTTP 503 Service Unavailable (Retry-After: 30)
        │
        ▼
[ Layer 4 & 5: Challenges (PoW & Turnstile) ]
        │
        ├── Missing/Invalid? ──► HTTP 428 Precondition Required (Carries PoW Puzzle)
        │
        ▼
[ Layer 3: Token Bucket Rate Limiter ] ── (Keyed on (IP, DeviceCookie) Pair)
        │
        ├── Throttled? ──► HTTP 429 Too Many Requests (Retry-After: N)
        │
        ▼
[ Sandbox Provisioned & 5-minute TTL Started ]
```

### Protection Layers
1. **Real IP Extraction**: Since traffic arrives via `cloudflared` on localhost, real client IP is strictly parsed from `CF-Connecting-IP` (fallback `X-Forwarded-For`).
2. **Signed Device Cookie (`__dp_dev`)**: Server-issued, HMAC-SHA256 signed browser cookie (`<uuid>.<timestamp>.<signature>`) preventing client tampering.
3. **Combined Keying Token Bucket**: Rate limits on composite `(IP, DeviceCookie)` pairs with secondary per-IP limits.
4. **Cloudflare Turnstile Gate**: Server-side token validation via Cloudflare `siteverify` API.
5. **Proof-of-Work (PoW) Engine**: Cryptographic puzzle (`SHA256(challenge + salt + nonce)` with $N$ leading zero bits). Solved client-side in 10–50ms and verified server-side in $O(1)$ time with replay protection.
6. **Hard Global Concurrency Cap**: Atomic semaphore enforcing a hard ceiling on concurrent active anonymous sandboxes (e.g. 20).

### Defense Observability

| Failure Mode | Defending Layer | HTTP Status | Log Event |
| :--- | :--- | :--- | :--- |
| **Single Abusive Client** | Token Bucket / PoW Challenge | `429 Too Many Requests` or `428 Precondition Required` | `slog.Warn("Session create throttled: per-client rate limit exceeded")` |
| **Distributed / Aggregate Load** | Global Concurrency Cap | `503 Service Unavailable` | `slog.Warn("Global anonymous concurrency cap reached (aggregate capacity exhausted)")` |

---

## Subsystem 3: eBPF Runtime Security & Behavioral Detection

The runtime security engine answers one question: *Is this container process still behaving like the container it started as?*

### 1. In-Kernel Syscall & Lifecycle Observation
- `raw_syscalls/sys_enter`: Generic syscall tagging with `cgroup_id` via `bpf_get_current_cgroup_id()`.
- Specialized hooks: `execve`, `openat` (path capture via `bpf_probe_read_user_str`), `connect`, `setns`, `unshare`, `mount`, `ptrace`.
- Process ancestry tracking: `sched_process_fork`, `exec`, and `exit` building full lineage (`init -> sh -> curl`).

### 2. Behavioral Detection Rules (Temporal Sequences)
- **Flagship Detection: Shell-to-Exfil Chain (`SHELL_TO_EXFIL`)**:
  $$\text{Interactive Shell Exec} \longrightarrow \text{Sensitive File Open (/etc/shadow)} \longrightarrow \text{Outbound Connect}$$
  Evaluated within a 30-second sliding window on the process tree.
- **Privilege Escalation (`PRIVILEGE_CHANGE`)**: Gaining effective capabilities (`CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_SYS_PTRACE`) beyond container start baseline.
- **Namespace Drift (`NETWORK_NAMESPACE_CHANGED`)**: Container process calling `setns`/`unshare` or deviating from initial `/proc/<pid>/ns/*` inodes.
- **Host Exposure Risk Amplifier**: Elevates finding severities to `CRITICAL` if the container has `--privileged` or docker socket mounts.
- **False-Positive Resistance**: Benign build tasks (e.g. `go build`, compilation, package downloads) do not touch sensitive credential paths and avoid alerts.

### 3. Kernel Enforcement Boundary
- Go is **strictly asynchronous** and out of the kernel hot path.
- Go compiles security policies (`ContainerPolicy`) into BPF maps (`net_policy_map`, `fs_deny_policy_map`).
- `cgroup/connect4` and `lsm/file_open` evaluate decisions **synchronously inside the kernel**.

---

## API Reference

### 1. Request Proof-of-Work Challenge
- **Endpoint:** `GET /challenges/pow`
- **Response (`200 OK`):**
```json
{
  "challenge": "a8f3b209e14c45b7",
  "salt": "7f09a12c",
  "difficulty": 16,
  "expires_at": 1726250400,
  "signature": "d3b07384d113edec49eaa6238ad5ff00..."
}
```

### 2. Create Anonymous Sandbox Session
- **Endpoint:** `POST /sessions`
- **Headers (Optional):** `CF-Turnstile-Response: <token>`
- **Request Body (Optional):**
```json
{
  "pow_solution": {
    "challenge": "a8f3b209e14c45b7",
    "salt": "7f09a12c",
    "difficulty": 16,
    "expires_at": 1726250400,
    "signature": "d3b07384d113edec49eaa6238ad5ff00...",
    "nonce": "48201"
  },
  "turnstile_token": "0.example-turnstile-token"
}
```
- **Responses:**
  - `201 Created`: `{"session_id": "8a3e9c20-...", "expires_in_sec": 300}`
  - `428 Precondition Required`: `{"error": "challenge_required", "pow_challenge": {...}}`
  - `429 Too Many Requests`: `{"error": "rate_limited", "retry_after": 30}`
  - `503 Service Unavailable`: `{"error": "global_capacity_reached"}`

### 3. Attach Interactive WebSocket Terminal
- **Endpoint:** `GET /sessions/{session_id}/attach`
- **Protocol:** `ws://` / `wss://`
- **Lane 1 (Terminal I/O):** Raw bidirectional bytes.
- **Lane 2 (Control Frames):** JSON frames (e.g. `{"type": "resize", "cols": 120, "rows": 40}`, `{"type": "ping"}`).

### 4. Security Findings & Timeline API (Sensor)
- **Get Findings:** `GET /containers/{id}/findings`
- **Get Event Timeline:** `GET /containers/{id}/timeline?limit=100`
- **Apply In-Kernel Policy:** `POST /containers/{id}/policy`
```json
{
  "allowed_capabilities": ["CAP_CHOWN"],
  "network_rules": [
    {"dst_ip": "0.0.0.0", "dst_port": 443, "action": "deny"}
  ],
  "fs_rules": [
    {"path": "/etc/shadow", "action": "deny"}
  ]
}
```
- **Security Metrics:** `GET /security/stats`

---

## Environment Configuration

| Variable | Default | Subsystem | Description |
| :--- | :--- | :--- | :--- |
| `DOCPINE_RUNTIME` | `docker` | Control Plane | Runtime backend: `docker`, `gvisor`, `firecracker` |
| `DOCPINE_ADDR` / `DOCPINE_PORT` | `:8080` | Control Plane | HTTP/WS server listen address |
| `DOCPINE_SESSION_TTL` | `5m` | Control Plane | Ephemeral sandbox TTL |
| `DOCPINE_MAX_SESSIONS` | `20` | Abuse Guard | Global concurrency limit on active sandboxes |
| `DOCPINE_RATE_LIMIT_BURST` | `5` | Abuse Guard | Token bucket burst capacity |
| `DOCPINE_RATE_LIMIT_REFILL` | `30s` | Abuse Guard | Token refill duration |
| `DOCPINE_POW_DIFFICULTY` | `16` | Abuse Guard | Leading zero bits for PoW puzzle |
| `DOCPINE_REQUIRE_POW` | `false` | Abuse Guard | Require PoW unconditionally on all creates |
| `DOCPINE_TURNSTILE_SECRET` | `""` | Abuse Guard | Cloudflare Turnstile secret key |
| `DOCPINE_SENSOR_ADDR` | `:8081` | Security Sensor | Security REST API listen address |
| `DATABASE_URL` | `""` | Storage | PostgreSQL connection string (in-memory if empty) |
| `DOCPINE_RUNSC_PATH` | `runsc` | gVisor | Path to `runsc` binary |
| `DOCPINE_FIRECRACKER_BIN` | `firecracker` | Firecracker | Path to `firecracker` binary |
| `DOCPINE_KERNEL_PATH` | `/var/lib/docpine/vmlinux` | Firecracker | Path to guest kernel |
| `DOCPINE_ROOTFS_PATH` | `/var/lib/docpine/rootfs.ext4` | Firecracker | Path to guest rootfs |

---

## Lab Attack Scenarios

The repository includes reproducible attack simulation scripts under `test/lab/`:

| Script | Attack Target | Expected Security Verdict |
| :--- | :--- | :--- |
| [`shell_to_exfil.sh`](file:///Users/labib0x9/Desktop/dockpine/test/lab/shell_to_exfil.sh) | `sh` $\to$ `/etc/shadow` $\to$ outbound connect | `FindingShellToExfil` (`HIGH` / `CRITICAL`) |
| [`privilege_escalation.sh`](file:///Users/labib0x9/Desktop/dockpine/test/lab/privilege_escalation.sh) | Capability elevation $\to$ unauthorized `mount` | `FindingPrivilegeEscalation` (`HIGH`) |
| [`namespace_pivot.sh`](file:///Users/labib0x9/Desktop/dockpine/test/lab/namespace_pivot.sh) | Invoking `unshare` / `setns` | `FindingNamespaceDrift` (`MEDIUM` / `HIGH`) |
| [`container_escape_attempt.sh`](file:///Users/labib0x9/Desktop/dockpine/test/lab/container_escape_attempt.sh) | Inspecting `/proc/kcore` / `ptrace` | `FindingSensitiveFileAccess` (`CRITICAL` with host exposure) |
| [`benign_noisy_workload.sh`](file:///Users/labib0x9/Desktop/dockpine/test/lab/benign_noisy_workload.sh) | High-volume code build & compilation | **0 Findings** (False-Positive Validation) |

---

## Testing Matrix & CI

### Host Prerequisite Clean Skipping

Integration tests under `internal/runtime/<backend>/*_test.go` automatically inspect the host environment and **visibly skip** (via `t.Skipf`) when host prerequisites (`/dev/kvm`, `runsc`) are absent, rather than failing or silently passing:

```bash
go test -count=1 -v ./...
```

Sample output:
```
=== RUN   TestDockerRuntime_Integration
--- PASS: TestDockerRuntime_Integration (2.45s)
=== RUN   TestFirecrackerRuntime_Integration
    firecracker_test.go:23: skipping firecracker integration test: /dev/kvm is not accessible. Firecracker requires Linux with KVM
--- SKIP: TestFirecrackerRuntime_Integration (0.00s)
=== RUN   TestGvisorRuntime_Integration
    gvisor_test.go:25: skipping gvisor integration test: gvisor binary "runsc" not found on PATH
--- SKIP: TestGvisorRuntime_Integration (0.00s)
PASS
```

### GitHub Actions CI

In CI, `/dev/kvm` is enabled on Ubuntu Linux runners, allowing the full matrix to execute:

```yaml
name: Test Suite
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.26'
      - name: Run Full Test Matrix
        run: go test -v -count=1 ./...
```

---

## Getting Started

### 1. Clone and Install
```bash
git clone https://github.com/labib0x9/dockpine.git
cd dockpine
go mod tidy
```

### 2. Start Control Plane (Port 8080)
```bash
# Docker backend
go run ./cmd/docpine

# Or gVisor backend
DOCPINE_RUNTIME=gvisor go run ./cmd/docpine
```

### 3. Start eBPF Security Sensor Daemon (Port 8081)
```bash
go run ./cmd/docpine-sensor
```

---

```bash

# macOS
brew install cloudflared
# Linux (Ubuntu/Debian)
curl -L --output cloudflared.deb https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
sudo dpkg -i cloudflared.deb

mkdir -p ~/.cloudflared

cloudflared tunnel login
cloudflared tunnel create docpine-tunnel

~/.cloudflared/config.yml
tunnel: <YOUR-TUNNEL-UUID>
credentials-file: /root/.cloudflared/<YOUR-TUNNEL-UUID>.json

ingress:
  # Route public domain to dockpine HTTP & WebSocket server
  - hostname: sandboxes.yourdomain.com
    service: http://127.0.0.1:8080
    originRequest:
      # Ensures WebSocket upgrades and HTTP/2 connections pass cleanly
      noTLSVerify: true
      keepAliveTimeout: 300s
      connectTimeout: 30s
  - service: http_status:404

cloudflared tunnel route dns docpine-tunnel sandboxes.yourdomain.com
cloudflared tunnel run docpine-tunnel

Ensure WebSockets are enabled in the Cloudflare Dashboard under Network -> WebSockets: ON.


```

```
 Cloudflare Turnstile Gate
Cloudflare Turnstile is a privacy-first CAPTCHA alternative. The browser generates a token, which your backend verifies with Cloudflare's siteverify API.

A. Cloudflare Dashboard Setup
Go to Cloudflare Dashboard $\to$ Turnstile $\to$ Add Site.
Set Domain (e.g. sandboxes.yourdomain.com or localhost for development).
Mode: Managed or Non-Interactive (invisible).
You will get two keys:
Site Key (Public, for Frontend)
Secret Key (Private, for Backend)
B. Backend Configuration
Set the secret key in your .env file:

env
TURNSTILE_SECRET=0x4AAAAAA...YOUR_SECRET_KEY
How Dockpine validates it (

internal/abuse/turnstile.go
):

go
// Sends POST to https://challenges.cloudflare.com/turnstile/v0/siteverify
form := url.Values{
    "secret":   {v.secretKey},
    "response": {token},
    "remoteip": {clientIP}, // Uses CF-Connecting-IP
}
TIP

Cloudflare Dummy Keys for Testing:

Secret: 1x0000000000000000000000000000000AA (Always passes)
Secret: 2x0000000000000000000000000000000AA (Always fails)
C. Frontend Implementation (React / Next.js)
Install the React Turnstile wrapper:

bash
npm install @marsidev/react-turnstile
In your React component:

tsx
import { Turnstile } from '@marsidev/react-turnstile';
import { useState } from 'react';
export function SessionLauncher() {
  const [turnstileToken, setTurnstileToken] = useState<string>('');
  const handleLaunch = async () => {
    const res = await fetch('https://sandboxes.yourdomain.com/sessions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        turnstile_token: turnstileToken,
      }),
    });
    const data = await res.json();
    console.log('Session created:', data.session_id);
  };
  return (
    <div>
      <Turnstile
        siteKey="0x4AAAAAA...YOUR_SITE_KEY"
        onSuccess={(token) => setTurnstileToken(token)}
      />
      <button onClick={handleLaunch} disabled={!turnstileToken}>
        Launch Sandbox
      </button>
    </div>
  );
}
3. Proof-of-Work (PoW) Engine
Proof-of-Work forces the client's CPU to compute a cryptographic puzzle (10–50ms) before creating a container. This makes automated DDoS / bot script attacks computationally expensive while remaining imperceptible to real users.

How the Cryptographic Puzzle Works
Server issues signed challenge:
challenge: 16 random hex bytes
salt: 8 random hex bytes
difficulty: 16 (means the resulting SHA-256 hash must start with 16 zero bits = 2 leading 0x00 bytes)
expires_at: Unix timestamp (+60s)
signature: HMAC-SHA256(challenge + "|" + salt + "|" + difficulty + "|" + expires_at, secret)
Client brute-forces a nonce:
Finds an integer nonce where SHA256(challenge + salt + nonce.toString()) has $N$ leading zero bits.
Server verifies in $O(1)$ time:
Verifies HMAC signature (proves server generated it).
Verifies timestamp (not expired).
Checks replay cache (nonce hasn't been used before).
Calculates one single SHA256(challenge + salt + nonce) and checks leading zero bits.
A. Backend Configuration
In .env:

env
REQUIRE_POW=true
POW_DIFFICULTY=16
COOKIE_SECRET=c2e8a109f5bc3a728d32b509ef1d48c0816e8b617a29e8471e4cb8f9d023a105
B. Client-Side JavaScript / TypeScript Solver
You can run this in a Web Worker or directly in TypeScript:

ts
// pow-solver.ts
export interface PoWChallenge {
  challenge: string;
  salt: string;
  difficulty: number;
  expires_at: number;
  signature: string;
}
export interface PoWSolution extends PoWChallenge {
  nonce: string;
}
// Check leading zero bits
function hasLeadingZeroBits(hashBytes: Uint8Array, bitsRequired: number): boolean {
  const fullBytes = Math.floor(bitsRequired / 8);
  const remainingBits = bitsRequired % 8;
  for (let i = 0; i < fullBytes; i++) {
    if (hashBytes[i] !== 0) return false;
  }
  if (remainingBits > 0) {
    const mask = 0xff << (8 - remainingBits);
    if ((hashBytes[fullBytes] & mask) !== 0) {
      return false;
    }
  }
  return true;
}
// Fast Web Crypto API solver
export async function solvePoW(challenge: PoWChallenge): Promise<PoWSolution> {
  const enc = new TextEncoder();
  let nonce = 0;
  while (true) {
    const nonceStr = nonce.toString();
    const data = enc.encode(challenge.challenge + challenge.salt + nonceStr);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashBytes = new Uint8Array(hashBuffer);
    if (hasLeadingZeroBits(hashBytes, challenge.difficulty)) {
      return {
        ...challenge,
        nonce: nonceStr,
      };
    }
    nonce++;
  }
}
C. End-to-End Frontend Flow
ts
export async function createSandboxSession(turnstileToken?: string) {
  // 1. Get PoW challenge from server
  const chalRes = await fetch('http://localhost:8080/challenges/pow');
  const challenge: PoWChallenge = await chalRes.json();
  // 2. Solve PoW in JS (takes ~15-30ms for difficulty 16)
  const startTime = performance.now();
  const solution = await solvePoW(challenge);
  console.log(`Solved PoW in ${(performance.now() - startTime).toFixed(1)}ms with nonce:`, solution.nonce);
  // 3. Submit Session Create Request with both PoW & Turnstile
  const response = await fetch('http://localhost:8080/sessions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(turnstileToken ? { 'CF-Turnstile-Response': turnstileToken } : {}),
    },
    body: JSON.stringify({
      pow_solution: solution,
      turnstile_token: turnstileToken,
    }),
  });
  if (response.status === 201) {
    const data = await response.json();
    return data.session_id; // Ready to attach WebSocket!
  } else if (response.status === 428) {
    // 428 Precondition Required (PoW required or missing)
    const err = await response.json();
    console.error('Challenge required:', err);
  } else if (response.status === 429) {
    // 429 Too Many Requests (Rate limited)
    const retryAfter = response.headers.get('Retry-After');
    console.warn(`Rate limited. Retry after ${retryAfter}s`);
  } else if (response.status === 503) {
    // 503 Service Unavailable (Global concurrency limit reached)
    console.warn('All sandbox slots full, please try again in a few moments');
  }
}
4. Summary Checklist for Full Setup
Component	Where Configured	Key Settings
Cloudflare Tunnel	~/.cloudflared/config.yml	service: http://127.0.0.1:8080, WebSockets enabled
Real IP Extraction	Dockpine Engine	Automatically parses CF-Connecting-IP header
Turnstile	.env (TURNSTILE_SECRET)	Set Cloudflare Turnstile Secret Key (or dummy key for dev)
Proof-of-Work	.env (REQUIRE_POW=true, POW_DIFFICULTY=16)	Solved in client JS/Worker via SHA256(challenge+salt+nonce)
Device Cookie	.env (COOKIE_SECRET)	Server issues signed __dp_dev HMAC cookie to prevent multi-session abuse
```

## Relationship with Sockforces

`dockpine` serves as the underlying sandbox and runtime security engine extracted and refined from [**sockforces**](https://github.com/labib0x9/sockforces), focusing on container orchestration, TTY multiplexing, and kernel-level sandbox security.






-------
-------
-------
-------
-------


# PROMPT: Build the Full Frontend for dockpine (ephemeral container sandbox & eBPF security platform)

You are an expert full-stack engineer and UI/UX designer specializing in high-performance DevSecOps dashboards, WebSockets, xterm.js terminal emulation, and cyber-security telemetry interfaces.

Build a modern, state-of-the-art, dark-themed Web Frontend for **dockpine** — an ephemeral container platform combining pluggable sandboxes (Docker, gVisor, Firecracker), layered abuse protection (Proof-of-Work, Cloudflare Turnstile, Token Bucket rate limiting)

---

## 🏗️ 1. Technical Stack & Architecture

- **Framework**: Next.js 14+ (App Router) or Vite + React 18+ (TypeScript).
- **Styling**: Tailwind CSS + Framer Motion for smooth transitions, Glassmorphism, and cybernetic micro-animations.
- **Terminal**: `@xterm/xterm` + `@xterm/addon-fit` + `@xterm/addon-web-links` + `@xterm/addon-canvas`.
- **Icons**: `lucide-react`.
- **State & Real-time**: Zustand or TanStack Query + native WebSockets + Web Workers (for background PoW computation).
- **Visualization**: VisX, Recharts, or Canvas for timeline graphs and process ancestry trees.

---

## 📡 2. Backend API & Protocol Specification

The frontend connects to two dockpine backend services (or a unified reverse proxy):
- **Control Plane** (Default `http://localhost:8080`): Session provisioning, abuse challenges, and interactive WebSocket PTY streaming., 

### Endpoint Catalog:

1. **PoW Challenge**: `GET /challenges/pow`
   - Response (`200 OK`):
     ```json
     {
       "challenge": "a8f3b209e14c45b7",
       "salt": "7f09a12c",
       "difficulty": 16,
       "expires_at": 1726250400,
       "signature": "d3b07384d113edec49eaa6238ad5ff00..."
     }
     ```
2. **Create Session**: `POST /sessions`
   - Request Body:
     ```json
     {
       "pow_solution": {
         "challenge": "a8f3b209e14c45b7",
         "salt": "7f09a12c",
         "difficulty": 16,
         "expires_at": 1726250400,
         "signature": "d3b07384d113edec49eaa6238ad5ff00...",
         "nonce": "48201"
       },
       "turnstile_token": "optional-turnstile-token"
     }
     ```
   - Responses:
     - `201 Created`: `{"session_id": "uuid-here", "expires_in_sec": 300}`
     - `428 Precondition Required`: `{"error": "challenge_required", "pow_challenge": {...}}`
     - `429 Too Many Requests`: `{"error": "rate_limited", "retry_after": 30}`
     - `503 Service Unavailable`: `{"error": "global_capacity_reached"}`

3. **WebSocket Interactive Terminal**: `GET /sessions/{session_id}/attach`
   - **Lane 1 (Terminal I/O)**: Raw bidirectional UTF-8 bytes to/from container PTY.
   - **Lane 2 (Control Frames)**: Out-of-band JSON text messages:
     - Terminal resize: `{"type": "resize", "cols": 120, "rows": 40}`
     - Heartbeat ping: `{"type": "ping"}` -> Server replies `{"type": "pong"}`

## 🧩 4. Core Features & Module Breakdown

### Module 1: Proof-of-Work (PoW) Client Web Worker
- Implement an off-main-thread Web Worker (`pow.worker.ts`) that solves SHA-256 puzzles without freezing the UI.
- Algorithm: Iterate `nonce` (uint64) such that `SHA256(challenge + salt + nonce.toString())` has $N$ leading zero bits (`difficulty`).
- Automatically fetch `/challenges/pow` in the background or solve on demand when intercepting `428 Precondition Required`.