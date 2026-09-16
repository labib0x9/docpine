# Implementation Plan: Docpine Runtime Security & Isolation Monitoring

Docpine is expanding to include an **eBPF-powered Runtime Security Engine** that monitors ephemeral and standalone containers for behavioral anomalies, namespace drift, capability escalation, sensitive file access, and outbound network activity, enforcing kernel-level policies via BPF maps, BPF LSM, and cgroup BPF hooks.

---

## User Review Required

> [!IMPORTANT]
> - **Kernel vs. Userspace Enforcement Boundary**: Go is strictly *asynchronous* and out of the kernel syscall hot path. Go's role is to compile user policies into BPF maps (`net_policy_map`, `cap_policy_map`, `fs_policy_map`) which in-kernel BPF programs (cgroup/connect, BPF LSM) consult synchronously.
> - **Cgroup-ID-Based Container Identity**: Process identity is keyed on `(cgroup_id, pid)` rather than PID alone to eliminate PID-reuse races and container namespace collisions. `cgroup_id` is captured directly at container creation time.
> - **Dual-Mode Operation**: The security engine includes both live eBPF kernel loader (`cilium/ebpf`) for Linux environments with BTF and an in-memory synthetic event engine for non-Linux hosts (e.g. macOS development).

---

## Architecture Diagram

```
                         Docpine
                            │
              ┌─────────────┴─────────────┐
              │                           │
        Control Plane              Runtime Security Engine
        (cmd/docpine)              (cmd/docpine-sensor)
              │                           │
       Session Manager               eBPF Loader (cilium/ebpf)
              │                           │
        Docker / gVisor        ┌──────────┼──────────┐
         / Firecracker         │          │          │
              │           Tracepoints   BPF LSM   Cgroup BPF
              │           (sys_enter)  (file_open)(connect4/6)
              └────────────────┼──────────┴──────────┼┘
                               │ (Tagged cgroup_id)  │ Synchronous
                               ▼                     │ In-Kernel
                          RINGBUF Map                ▼
                               │              [Enforcement Maps]
                               ▼               (Net/Cap/FS Policy)
                      Ring Buffer Reader
                               │
                               ▼
                  Behavioral Correlation Engine
              (Process State, Ancestry, Drift, Timeline)
                               │
                     ┌─────────┴─────────┐
                     ▼                   ▼
                 Findings             Timeline
                     │                   │
                     └─────────┬─────────┘
                               ▼
                 PostgreSQL / Memory Repo
                               │
                               ▼
                        REST API Engine
                (/containers/{id}/findings,
                 /containers/{id}/timeline,
                 /containers/{id}/policy)
```

---

## Proposed Changes

### Component 1: eBPF Programs & Common Types (`bpf/`)

#### [NEW] [vmlinux.h](file:///Users/labib0x9/Desktop/dockpine/bpf/common/vmlinux.h)
- Generated/stubbed CO-RE definitions (`task_struct`, `nsproxy`, `cred`, `sock`, `sockaddr_in`, `file`, etc.).

#### [NEW] [types.h](file:///Users/labib0x9/Desktop/dockpine/bpf/common/types.h)
- Shared data layout between BPF and Go:
  ```c
  struct event {
      __u64 timestamp;
      __u64 cgroup_id;
      __u32 pid;
      __u32 ppid;
      __u32 type;
      char comm[16];
      char data[256];
  };

  struct net_policy_key {
      __u64 cgroup_id;
      __u32 dst_ip;
      __u16 dst_port;
  };
  ```

#### [NEW] [syscalls.bpf.c](file:///Users/labib0x9/Desktop/dockpine/bpf/programs/syscalls.bpf.c)
- `raw_syscalls/sys_enter` attaching and filtering by `bpf_get_current_cgroup_id()`.
- Captures `execve`, `openat`, `connect`, `setns`, `unshare`, `mount`, `ptrace`, `bpf`.

#### [NEW] [lifecycle.bpf.c](file:///Users/labib0x9/Desktop/dockpine/bpf/programs/lifecycle.bpf.c)
- `sched_process_fork`, `sched_process_exec`, `sched_process_exit` hooks for ancestry tracking.

#### [NEW] [lsm.bpf.c](file:///Users/labib0x9/Desktop/dockpine/bpf/programs/lsm.bpf.c)
- `lsm/file_open` in-kernel file access enforcement.

#### [NEW] [cgroup_net.bpf.c](file:///Users/labib0x9/Desktop/dockpine/bpf/programs/cgroup_net.bpf.c)
- `cgroup/connect4` and `cgroup/connect6` pre-connect firewall lookup in `net_policy_map`.

---

### Component 2: Domain Layer (`internal/domain/security`)

#### [NEW] [process.go](file:///Users/labib0x9/Desktop/dockpine/internal/domain/security/process.go)
- `ProcessState` keyed by `(cgroup_id, pid)` with ancestry chain traversal.
- `NamespaceIdentity` (`NetNS`, `MntNS`, `PidNS`, `UserNS`, `IpcNS`, `UtsNS`, `CgroupNS`).
- `Credentials` (`UID`, `GID`, `EffectiveCaps` bitmask with diffing `actual &^ initial`).

#### [NEW] [finding.go](file:///Users/labib0x9/Desktop/dockpine/internal/domain/security/finding.go)
- `Finding`, `Severity` (`Low`, `Medium`, `High`, `Critical`), `FindingType` (`ShellToExfil`, `PrivilegeEscalation`, `NamespaceDrift`, `SensitiveFileAccess`, `UnauthorizedNetworkConnect`, `UnexpectedAncestry`).
- `EventRecord` with structured metadata.

#### [NEW] [policy.go](file:///Users/labib0x9/Desktop/dockpine/internal/domain/security/policy.go)
- `ContainerPolicy`, `CapabilityPolicy`, `NetworkRule`, `FSRule`.

---

### Component 3: Application / Engine Layer (`internal/app/security`)

#### [NEW] [engine.go](file:///Users/labib0x9/Desktop/dockpine/internal/app/security/engine.go)
- Central security engine orchestrating event ingestion, container registration `(cgroup_id <-> container_id)`, and repository persistence.

#### [NEW] [correlation.go](file:///Users/labib0x9/Desktop/dockpine/internal/app/security/correlation.go)
- Temporal behavioral correlation state machine:
  - **Flagship Detection: Shell-to-Exfil**: `shell exec (/bin/sh, /bin/bash) -> sensitive file open (/etc/shadow, /proc/kcore) -> outbound network connect` within sliding time window (30s).
  - **Privilege Escalation**: Detects unexpected `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_SYS_PTRACE` followed by system manipulation.
  - **Namespace Drift**: Detects changes in `/proc/<pid>/ns/*` compared to container start baseline.
  - **Host Exposure Risk Amplifier**: Scores findings higher if container has privileged mode or host socket mounts.

#### [NEW] [policy_compiler.go](file:///Users/labib0x9/Desktop/dockpine/internal/app/security/policy_compiler.go)
- Translates high-level JSON policy to in-kernel BPF map entries.

---

### Component 4: Infrastructure & Storage (`internal/infra`)

#### [NEW] [infra/ebpf/loader.go](file:///Users/labib0x9/Desktop/dockpine/internal/infra/ebpf/loader.go)
- `cilium/ebpf` loader, ringbuf reader, attach/detach lifecycle with visible skip on non-Linux kernels.

#### [NEW] [infra/postgres/schema.sql](file:///Users/labib0x9/Desktop/dockpine/internal/infra/postgres/schema.sql)
- PostgreSQL schema for `containers`, `processes`, `events`, `findings`, and `policies`.

#### [NEW] [infra/postgres/repo.go](file:///Users/labib0x9/Desktop/dockpine/internal/infra/postgres/repo.go)
- Repository interface and dual implementations: `PostgresRepo` (production SQL) and `MemoryRepo` (zero-dependency standalone / testing).

---

### Component 5: API Transport & Control Plane Integration (`internal/transport/http`, `cmd/`)

#### [NEW] [transport/http/security_handler.go](file:///Users/labib0x9/Desktop/dockpine/internal/transport/http/security_handler.go)
- REST endpoints:
  - `GET /containers/{id}/findings`
  - `GET /containers/{id}/timeline`
  - `POST /containers/{id}/policy`
  - `GET /containers/{id}/policy`
  - `GET /security/stats`

#### [NEW] [cmd/docpine-sensor/main.go](file:///Users/labib0x9/Desktop/dockpine/cmd/docpine-sensor/main.go)
- Standalone daemon binary for runtime security monitoring.

#### [MODIFY] [cmd/docpine/main.go](file:///Users/labib0x9/Desktop/dockpine/cmd/docpine/main.go)
- Integrates the security engine with the control plane, registering container cgroups upon creation.

---

### Component 6: Lab Attack Scenarios & Devcontainer

#### [NEW] [deploy/devcontainer/Dockerfile](file:///Users/labib0x9/Desktop/dockpine/deploy/devcontainer/Dockerfile) & [devcontainer.json](file:///Users/labib0x9/Desktop/dockpine/deploy/devcontainer/devcontainer.json)
- Linux environment with BTF, LLVM/clang, bpftool, Go 1.22+.

#### [NEW] [test/lab/shell_to_exfil.sh](file:///Users/labib0x9/Desktop/dockpine/test/lab/shell_to_exfil.sh)
- Simulates shell exec -> `/etc/shadow` open -> outbound connect.

#### [NEW] [test/lab/privilege_escalation.sh](file:///Users/labib0x9/Desktop/dockpine/test/lab/privilege_escalation.sh)
- Simulates capability elevation and mount attempt.

#### [NEW] [test/lab/namespace_pivot.sh](file:///Users/labib0x9/Desktop/dockpine/test/lab/namespace_pivot.sh)
- Simulates `setns`/`unshare` pivot.

#### [NEW] [test/lab/benign_noisy_workload.sh](file:///Users/labib0x9/Desktop/dockpine/test/lab/benign_noisy_workload.sh)
- Validates that noisy build tasks do not trigger false positive findings.

#### [NEW] [docs/architecture.md](file:///Users/labib0x9/Desktop/dockpine/docs/architecture.md) & [docs/detections.md](file:///Users/labib0x9/Desktop/dockpine/docs/detections.md)
- Complete architectural analysis and detection rules catalog.

---

## Verification Plan

### Automated Tests
1. **Domain & Behavioral Correlation Suite**:
   ```bash
   go test -v ./internal/domain/security/... ./internal/app/security/...
   ```
   - Tests process ancestry chain, capability bitmask diffing, namespace identity comparison.
   - Tests temporal correlation engine: Shell-to-exfil window matching, privilege escalation, namespace drift, false-positive resistance.
2. **Repository & Storage Suite**:
   ```bash
   go test -v ./internal/infra/postgres/...
   ```
   - Tests storage, retrieval, filtering of containers, events, findings, and policies.
3. **eBPF & Ringbuf Ingestion Suite**:
   ```bash
   go test -v ./internal/infra/ebpf/...
   ```
   - Tests event parsing, ringbuf decoding, and loader lifecycle.
4. **Security API Endpoints Suite**:
   ```bash
   go test -v ./internal/transport/http/...
   ```
   - Tests `/containers/{id}/findings`, `/timeline`, `/policy`, and `/security/stats`.
5. **Full Project Suite**:
   ```bash
   go test -count=1 -v ./...
   ```
