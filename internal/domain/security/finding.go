package security

import (
	"time"
)

// Severity indicates the risk rating of a security finding.
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// EventType represents the category of kernel event observed.
type EventType uint32

const (
	EventExec EventType = iota
	EventOpenat
	EventConnect
	EventSetns
	EventUnshare
	EventCapabilityChange
	EventNamespaceChange
	EventFork
	EventExit
	EventPtrace
	EventMount
	EventBpf
)

func (e EventType) String() string {
	switch e {
	case EventExec:
		return "exec"
	case EventOpenat:
		return "openat"
	case EventConnect:
		return "connect"
	case EventSetns:
		return "setns"
	case EventUnshare:
		return "unshare"
	case EventCapabilityChange:
		return "capability_change"
	case EventNamespaceChange:
		return "namespace_change"
	case EventFork:
		return "fork"
	case EventExit:
		return "exit"
	case EventPtrace:
		return "ptrace"
	case EventMount:
		return "mount"
	case EventBpf:
		return "bpf"
	default:
		return "unknown"
	}
}

// EventRecord captures an observed kernel activity.
type EventRecord struct {
	ID       int64     `json:"id"`
	Time     time.Time `json:"time"`
	CgroupID uint64    `json:"cgroup_id"`
	PID      uint32    `json:"pid"`
	Type     EventType `json:"type"`
	TypeStr  string    `json:"type_str"`
	Comm     string    `json:"comm"`
	Data     string    `json:"data"`
}

// Standard Finding Types
const (
	FindingShellToExfil              = "SHELL_TO_EXFIL"
	FindingPrivilegeEscalation       = "PRIVILEGE_CHANGE"
	FindingNamespaceDrift            = "NETWORK_NAMESPACE_CHANGED"
	FindingSensitiveFileAccess       = "SENSITIVE_FILE_ACCESS"
	FindingUnauthorizedNetworkConnect = "UNAUTHORIZED_NETWORK_CONNECT"
	FindingUnexpectedAncestry        = "UNEXPECTED_ANCESTRY"
	FindingHostExposure              = "HOST_RESOURCE_EXPOSURE"
)

// Finding represents a behavioral correlation verdict produced by the security engine.
type Finding struct {
	ID           int64          `json:"id"`
	ContainerID  string         `json:"container_id"`
	CgroupID     uint64         `json:"cgroup_id"`
	PID          uint32         `json:"pid"`
	Severity     Severity       `json:"severity"`
	FindingType  string         `json:"finding_type"`
	Summary      string         `json:"summary"`
	EventIDs     []int64        `json:"event_ids"`
	Ancestry     string         `json:"ancestry,omitempty"`
	CreatedAt    time.Time      `json:"created_at"`
	HostExposure map[string]any `json:"host_exposure,omitempty"`
}
