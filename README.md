# dockpine (🐳)

A lightweight, high-performance Go service that provisions ephemeral **Alpine Linux (`alpine:3.20`)** sandbox containers on-demand and bridges interactive TTY terminal sessions directly to web clients over **WebSockets**.

> [!NOTE]
> **dockpine** is a focused container runtime & sandbox subsystem derived as a standalone subset of [**sockforces**](https://github.com/labib0x9/sockforces).

---

## 🚀 Overview

`dockpine` manages isolated container lifecycles and multiplexes raw Docker TTY input/output streams over WebSockets for browser-based terminals (such as [xterm.js](https://xtermjs.org/)).

### Core Features
- **Ephemeral Alpine Sandboxes:** Fast instantiation of minimal `alpine:3.20` containers running `/bin/sh`.
- **Bi-directional WebSocket Streaming:** Full TTY hijacking allowing real-time interactive terminal emulation.
- **Clean Go Architecture:** Interface-driven design, standard library HTTP routing (Go 1.22+), and graceful shutdown handling.
- **Session-to-Container Isolation:** UUID-based session tracking mapping incoming connections to isolated containers.

---

## 🏗️ Architecture

```
[ Frontend / Webhook / Web Terminal ]
                  │
                  ├── (1) POST /sessions ──────────► [ REST Handler ]
                  │                                          │
                  │                                 (Allocates UUID Session)
                  │                                          ▼
                  │                                 [ Session Manager ]
                  │                                          │
                  │                                 (Docker API Request)
                  │                                          ▼
                  │                                 [ Docker Client (SDK) ]
                  │                                 - Creates & starts alpine container
                  │
                  └── (2) GET /sessions/{id}/attach (WS) ► [ WebSocket Handler ]
                                                              │
                                                     (Hijacks TTY Stream)
                                                              ▼
                                                     [ Container: /bin/sh ]
                                                     (Bidirectional I/O)
```

---

## 📡 API Reference

### 1. Create a Session
Spawns a new Alpine container and initializes a session.

- **Endpoint:** `POST /sessions`
- **Response:** `201 Created`
```json
{
  "session_id": "8a3e9c20-7b61-4fa3-9f82-3d5f9e2b4123"
}
```

### 2. Attach Interactive Terminal (WebSocket)
Upgrades the connection to a WebSocket and streams container stdin/stdout.

- **Endpoint:** `GET /sessions/{session_id}/attach`
- **Protocol:** `ws://` / `wss://`
- **Payload:** Raw text / terminal bytes bi-directionally.

---

## 🛠️ Roadmap & Planned Enhancements

### 🔒 Sandbox Hardening & Security
- [ ] **Zero-Network Isolation:** Enforce `NetworkMode: "none"` to prevent external network access from within containers.
- [ ] **Strict Cgroup Quotas:** Limit containers to **128 MB RAM** (no swap) and **0.05 CPU (5% of 1 core)**.
- [ ] **Fork-Bomb Protection:** Set `PidsLimit: 50` to prevent thread/process exhaustion.
- [ ] **Privilege Restriction:** Drop all Linux capabilities (`CapDrop: ALL`) and enforce `no-new-privileges: true`.
- [ ] **Ephemeral Filesystems:** Read-only root filesystem with a small memory-backed `tmpfs` mount on `/tmp`.

### 🔍 Observability & Tracing
- [ ] **eBPF Syscall Monitoring:** Trace container syscalls (`execve`, `openat`, `socket`, etc.) using Aqua Tracee / Tetragon to audit container activity and detect RCE attempts.
- [ ] **Docker Event Tracking:** Real-time monitoring for container exits, OOM (Out Of Memory) events, and crashes via Docker Events API.
- [ ] **Session Audit Correlation:** Correlate user remote IP addresses with container IDs and execution logs.

### ⚡ Concurrency & Backpressure
- [ ] **Concurrency Semaphore:** Global cap on active concurrent containers to ensure host stability.
- [ ] **Automated Session Reaper:** Idle timeout background worker to stop and remove inactive containers automatically.
- [ ] **Bounded WebSocket Buffers:** Backpressure handling to drop slow consumers and prevent host memory inflation.

---

## 💻 Getting Started

### Prerequisites
- [Go](https://golang.org/) 1.22 or higher
- [Docker Engine](https://docs.docker.com/engine/) installed and running locally

### Running Locally

1. **Clone the repository:**
   ```bash
   git clone https://github.com/labib0x9/dockpine.git
   cd dockpine
   ```

2. **Download dependencies:**
   ```bash
   go mod tidy
   ```

3. **Start the server:**
   ```bash
   go run ./cmd/docpine
   ```
   The server starts on `http://127.0.0.1:8080`.

---

## 📜 Relationship with Sockforces

`dockpine` serves as the underlying sandbox engine extracted and refined from [**sockforces**](https://github.com/labib0x9/sockforces), focusing strictly on high-performance container orchestration, TTY multiplexing, and kernel-level sandbox security.
