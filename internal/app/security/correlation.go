package security

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/labib0x9/docpine/internal/domain/security"
	"github.com/labib0x9/docpine/internal/infra/postgres"
)

var sensitivePathKeywords = []string{
	"/etc/shadow",
	"/etc/passwd",
	"/etc/sudoers",
	"/root/.ssh",
	"/root/.bash_history",
	"/proc/kcore",
	"/dev/mem",
	"/dev/kmem",
	"/var/run/docker.sock",
	"/etc/ssl/private",
}

// isSensitiveFile checks if the accessed path contains a high-value sensitive target.
func isSensitiveFile(path string) bool {
	normalized := strings.ToLower(strings.TrimSpace(path))
	for _, kw := range sensitivePathKeywords {
		if strings.Contains(normalized, kw) {
			return true
		}
	}
	return false
}

// isShellCommand checks if the command or binary is an interactive shell.
func isShellCommand(comm, data string) bool {
	normComm := strings.ToLower(comm)
	normData := strings.ToLower(data)
	shells := []string{"sh", "bash", "zsh", "dash", "ash", "csh", "tcsh"}
	for _, s := range shells {
		if normComm == s || strings.HasSuffix(normData, "/"+s) || normData == s {
			return true
		}
	}
	return false
}

type processTemporalState struct {
	ShellExecEventID       int64
	ShellExecTime          time.Time
	SensitiveFileEventID   int64
	SensitiveFileTime      time.Time
	SensitiveFilePath      string
	OutboundConnectEventID int64
	OutboundConnectTime    time.Time
	OutboundTarget         string
	ExfilFindingProduced   bool
}

// CorrelationEngine evaluates sequential streams of kernel events against temporal behavioral patterns.
type CorrelationEngine struct {
	mu             sync.Mutex
	window         time.Duration
	processStates  map[string]*processTemporalState // keyed by "cgroup:pid"
	repo           postgres.Repository
}

// NewCorrelationEngine creates a correlation engine with a configurable sliding window (default 30s).
func NewCorrelationEngine(repo postgres.Repository, window ...time.Duration) *CorrelationEngine {
	win := 30 * time.Second
	if len(window) > 0 && window[0] > 0 {
		win = window[0]
	}
	return &CorrelationEngine{
		window:        win,
		processStates: make(map[string]*processTemporalState),
		repo:          repo,
	}
}

// IngestEvent processes an incoming event record and returns any newly produced findings.
func (ce *CorrelationEngine) IngestEvent(e *security.EventRecord, container *postgres.ContainerRecord, proc *security.ProcessState) (*security.Finding, error) {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	procKey := fmt.Sprintf("%d:%d", e.CgroupID, e.PID)
	st, exists := ce.processStates[procKey]
	if !exists {
		st = &processTemporalState{}
		ce.processStates[procKey] = st
	}

	containerID := ""
	var hostExposure map[string]any
	if container != nil {
		containerID = container.ID
		hostExposure = container.HostExposure
	}

	now := e.Time
	if now.IsZero() {
		now = time.Now()
	}

	ancestry := ""
	if proc != nil {
		ancestry = proc.AncestryString()
	}

	isPrivilegedHost := false
	if hostExposure != nil {
		if priv, ok := hostExposure["privileged"].(bool); ok && priv {
			isPrivilegedHost = true
		}
	}

	// 1. Evaluate Rule 1: Shell Execution
	if e.Type == security.EventExec && isShellCommand(e.Comm, e.Data) {
		st.ShellExecEventID = e.ID
		st.ShellExecTime = now
	}

	// 2. Evaluate Rule 2: Sensitive File Open
	if e.Type == security.EventOpenat && isSensitiveFile(e.Data) {
		st.SensitiveFileEventID = e.ID
		st.SensitiveFileTime = now
		st.SensitiveFilePath = e.Data

		// If no shell preceded it, record standalone sensitive file access finding
		if st.ShellExecEventID == 0 || now.Sub(st.ShellExecTime) > ce.window {
			sev := security.SeverityMedium
			if isPrivilegedHost {
				sev = security.SeverityHigh
			}
			finding := &security.Finding{
				ContainerID:  containerID,
				CgroupID:     e.CgroupID,
				PID:          e.PID,
				Severity:     sev,
				FindingType:  security.FindingSensitiveFileAccess,
				Summary:      fmt.Sprintf("Process %q accessed sensitive file path: %s", e.Comm, e.Data),
				EventIDs:     []int64{e.ID},
				Ancestry:     ancestry,
				CreatedAt:    now,
				HostExposure: hostExposure,
			}
			return finding, nil
		}
	}

	// 3. Evaluate Rule 3: Outbound Network Connect
	if e.Type == security.EventConnect {
		st.OutboundConnectEventID = e.ID
		st.OutboundConnectTime = now
		st.OutboundTarget = e.Data

		// FLAGSHIP DETECTION: Shell-to-Exfil Chain (shell -> sensitive file -> outbound connect within window)
		if st.ShellExecEventID != 0 && st.SensitiveFileEventID != 0 && !st.ExfilFindingProduced {
			timeSinceShell := now.Sub(st.ShellExecTime)
			timeSinceFile := now.Sub(st.SensitiveFileTime)

			if timeSinceShell <= ce.window && timeSinceFile <= ce.window && !st.SensitiveFileTime.Before(st.ShellExecTime) {
				st.ExfilFindingProduced = true

				sev := security.SeverityHigh
				if isPrivilegedHost {
					sev = security.SeverityCritical
				}

				finding := &security.Finding{
					ContainerID: containerID,
					CgroupID:    e.CgroupID,
					PID:         e.PID,
					Severity:    sev,
					FindingType: security.FindingShellToExfil,
					Summary: fmt.Sprintf("CRITICAL BEHAVIORAL CHAIN: Shell execution (%s) followed by sensitive file read (%s) and outbound network connection within %v window",
						e.Comm, st.SensitiveFilePath, ce.window),
					EventIDs:     []int64{st.ShellExecEventID, st.SensitiveFileEventID, e.ID},
					Ancestry:     ancestry,
					CreatedAt:    now,
					HostExposure: hostExposure,
				}
				return finding, nil
			}
		}
	}

	// 4. Evaluate Rule 4: Namespace Pivot (setns / unshare)
	if e.Type == security.EventSetns || e.Type == security.EventUnshare {
		sev := security.SeverityHigh
		if isPrivilegedHost {
			sev = security.SeverityCritical
		}
		finding := &security.Finding{
			ContainerID:  containerID,
			CgroupID:     e.CgroupID,
			PID:          e.PID,
			Severity:     sev,
			FindingType:  security.FindingNamespaceDrift,
			Summary:      fmt.Sprintf("Process %q performed namespace manipulation (%s)", e.Comm, e.Type.String()),
			EventIDs:     []int64{e.ID},
			Ancestry:     ancestry,
			CreatedAt:    now,
			HostExposure: hostExposure,
		}
		return finding, nil
	}

	// 5. Evaluate Rule 5: Capability Privilege Escalation
	if e.Type == security.EventCapabilityChange {
		sev := security.SeverityHigh
		if isPrivilegedHost {
			sev = security.SeverityCritical
		}
		finding := &security.Finding{
			ContainerID:  containerID,
			CgroupID:     e.CgroupID,
			PID:          e.PID,
			Severity:     sev,
			FindingType:  security.FindingPrivilegeEscalation,
			Summary:      fmt.Sprintf("Process %q gained elevated capabilities beyond initial baseline: %s", e.Comm, e.Data),
			EventIDs:     []int64{e.ID},
			Ancestry:     ancestry,
			CreatedAt:    now,
			HostExposure: hostExposure,
		}
		return finding, nil
	}

	return nil, nil
}
