# Docpine Detections Catalog: Behavioral Rules & Anomaly Analysis

Docpine avoids noisy, single-syscall alerts (`if syscall == X: alert`). Findings are generated through **temporal behavioral sequence correlation** within sliding time windows.

---

## 1. Flagship Detection: Shell-to-Exfiltration Chain (`SHELL_TO_EXFIL`)

### Sequence:
$$\text{Interactive Shell Exec} \longrightarrow \text{Sensitive File Open} \longrightarrow \text{Outbound Network Connect}$$

- **Time Window:** 30 seconds (configurable).
- **Triggers:**
  1. `execve` of a shell binary (`/bin/sh`, `/bin/bash`, `ash`, `zsh`).
  2. `openat` targeting sensitive files (`/etc/shadow`, `/etc/passwd`, `/etc/sudoers`, `/root/.ssh/*`, `/proc/kcore`, `/var/run/docker.sock`).
  3. `connect` to external non-loopback IP addresses.
- **Default Severity:** `HIGH` (elevated to `CRITICAL` if container has host exposures like `--privileged` or host mounts).
- **False-Positive Tuning:** Legitimate compilation commands (e.g. `go build`, `gcc`) do not access credential files and therefore do not trigger this rule.

---

## 2. Privilege Escalation & Capability Drift (`PRIVILEGE_CHANGE`)

### Sequence:
$$\text{Process Gains Capability} \notin \text{Baseline Effective Caps} \longrightarrow \text{Privileged Action (e.g. mount / ptrace)}$$

- **Effective Capability Diff:**
  $$\text{Gained} = \text{CurrentCaps} \ \& \sim \text{BaselineCaps}$$
- **High-Risk Capabilities:** `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`.
- **Default Severity:** `HIGH`.

---

## 3. Namespace Drift & Container Pivot (`NETWORK_NAMESPACE_CHANGED`)

### Sequence:
$$\text{Process Invokes } \texttt{setns}() \text{ or } \texttt{unshare}() \ \lor \ \text{Namespace Inode Differs from Baseline}$$

- **Signal vs. Verdict:** Namespace drift is treated as a high-fidelity *signal* combined with ancestry and capability state rather than an immediate standalone compromise verdict.
- **Default Severity:** `MEDIUM` / `HIGH`.

---

## 4. Sensitive File Access Without Exfiltration (`SENSITIVE_FILE_ACCESS`)

- **Trigger:** Process opens a credential or kernel memory path directly without preceding shell or following network connection.
- **Default Severity:** `MEDIUM`.

---

## 5. Host Resource Exposure Risk Amplifier (`HOST_RESOURCE_EXPOSURE`)

- **Trigger:** Evaluated at container creation time.
- **Indicators:**
  - `privileged: true`
  - Host network namespace (`--net=host`)
  - Host PID namespace (`--pid=host`)
  - Docker daemon socket mount (`/var/run/docker.sock`)
- **Impact:** Automatically elevates all subsequent runtime findings from `HIGH` to `CRITICAL`.
