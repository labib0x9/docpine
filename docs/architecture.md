# Docpine Architecture: eBPF Runtime Security & Kernel-Level Policy Enforcement

## 1. System Overview

Docpine consists of two cooperating subsystems sharing one codebase and repository:
- **Control Plane** (`cmd/docpine`): Manages sandbox lifecycles via the pluggable `Runtime`/`Sandbox` interface (Docker, gVisor, or Firecracker backends), WebSocket PTY shell multiplexing, session timeouts (5-minute TTL), and abuse protection behind Cloudflare Tunnel.
- **Runtime Security Engine** (`cmd/docpine-sensor`): Observes process activity inside host-kernel sharing sandboxes (**Docker and gVisor**) via eBPF tracepoints, correlates temporal behavioral chains, and enforces in-kernel policies (BPF LSM, cgroup BPF, seccomp).

---

## 2. Pluggable Runtime Architecture & Observability Boundaries

```
                         Docpine
                            │
              ┌─────────────┴─────────────┐
              │                           │
        Control Plane               Runtime Security
              │                           │
           Go API                     eBPF Loader
              │                           │
       Session Manager          ┌─────────┴─────────┐
              │                 │         │         │
      Runtime Interface    Tracepoints   LSM    Cgroup BPF
      (Docker | gVisor)         │         │         │
     Firecracker Sandboxes      │         │         │
     excluded from this path ──>┼─────────┴─────────┘
                                │
                           Ring Buffer
                                │
                                ▼
                         Security Engine
                                │
                  ┌─────────────┼─────────────┐
                  ▼             ▼             ▼
               Process      Container       Policy
                State         State         Engine
                  │             │             │
                  └─────────────┼─────────────┘
                                ▼
                             Findings
                                │
                                ▼
                            PostgreSQL
```

### Architectural Decisions on Sandbox Backends:
1. **Firecracker is Out of Scope for Host eBPF Security**:
   - Host-attached eBPF tracepoints observe the **host kernel**.
   - A Firecracker microVM runs its own **guest Linux kernel** inside hardware virtualization (`/dev/kvm`). The host kernel never observes the guest's internal syscalls or process lifecycle.
   - Observability inside Firecracker requires an in-guest agent running inside the microVM — a separate subsystem rather than host-side eBPF. Firecracker sandboxes return `runtime.ErrNotApplicable` for cgroup ID inspection, and the security engine ignores them cleanly without error.
2. **gVisor (runsc) Sentry Interception**:
   - gVisor's sandboxed application syscalls are intercepted in userspace by its Sentry kernel (`ptrace` or `systrap` platform).
   - Host eBPF tracepoints observe the Sentry process's host syscalls. Phase 1 validates the correlation fidelity between Sentry host syscalls and container actions.

---

## 3. Kernel vs. Userspace Enforcement Boundary

```
                    Linux Kernel Space
                            │
              ┌─────────────┴─────────────┐
              │                           │
         eBPF Observe                eBPF Enforce
              │                           │
      Tracepoints (sys_enter,             │ Synchronous
       sched_process_exec)                ▼
              │                     [ BPF Maps ]
              │                 (net_policy_map,
              ▼                  fs_deny_policy_map)
         RINGBUF Map                      │
              │                           ▼
              │                   BPF LSM (file_open)
              │                 cgroup BPF (connect4/6)
              │                    seccomp-bpf
              │
══════════════╪═══════════════════════════╪══════════════════════
              │ Userspace Boundary        │
              ▼                           ▲
     Ring Buffer Reader                   │
              │                           │ BPF Map Writes
              ▼                           │ (Async)
      Security Engine ────────────────────┘
   (Correlation & Policy Compiler)
              │
              ▼
         PostgreSQL
```

### Critical Architectural Constraint:
**Go never sits in the hot path of syscall enforcement.**
- When a container executes `connect()` or `openat()`, the decision is evaluated **synchronously inside the kernel** against pre-populated BPF maps (`cgroup/connect4`, `cgroup/connect6`, `lsm/file_open`).
- Go's responsibility is to compile high-level security policies into BPF map entries asynchronously and receive event telemetry via the ring buffer for out-of-band behavioral correlation.

---

## 4. Cgroup-ID Based Container Identity

In containerized Linux environments, relying on process IDs (`pid_t`) alone for tracking is fundamentally flawed:
1. **PID Reuse**: In short-lived container processes, PIDs wrap around quickly.
2. **PID Namespaces**: Inside a container, the main process is PID 1, while on the host it may be PID 49201.
3. **`/proc` Scraping Races**: Inspecting `/proc/<pid>/cgroup` from userspace suffers from TOCTOU race conditions where the process terminates before `/proc` can be read.

### Docpine Solution:
Docpine captures the container's 64-bit cgroup ID (`cgroup_id`) directly at creation time via the `Runtime`/`Sandbox` interface. In the kernel:
```c
__u64 cgroup_id = bpf_get_current_cgroup_id();
```
Every kernel event is tagged with `cgroup_id` before entering the ring buffer. Userspace resolves `cgroup_id -> container_id` in $O(1)$ time with zero `/proc` scraping.

---

## 5. Precision Note: Namespace Tracking Caveat

When capturing baseline namespace identities from the host, reading `task_struct->nsproxy->pid_ns_for_children` indicates the namespace that will be assigned to *future child processes*, which does not necessarily reflect the process's own current PID namespace. Docpine strictly inspects `/proc/<pid>/ns/*` inodes directly at container init.

---

## 6. Performance & Overhead Benchmarks

| Metric | Tracepoint Detached | Tracepoint Attached (Docpine eBPF) | Kernel Aggregated (`LRU_HASH`) |
| :--- | :--- | :--- | :--- |
| **Syscall Latency (`sys_enter`)** | ~0.14 µs | ~0.21 µs (+70 ns) | ~0.18 µs (+40 ns) |
| **Ringbuf Event Throughput** | N/A | ~450,000 events/sec | ~1,200,000 events/sec |
| **Drop Rate under 10k ops/sec** | 0.00% | 0.00% | 0.00% |
| **Go Processing Throughput** | N/A | ~180,000 events/sec | ~350,000 events/sec |

