package security

import (
	"fmt"
	"strings"
	"time"
)

// Linux Capability Constants
const (
	CAP_CHOWN            = 1 << 0
	CAP_DAC_OVERRIDE     = 1 << 1
	CAP_DAC_READ_SEARCH  = 1 << 2
	CAP_FOWNER           = 1 << 3
	CAP_FSETID           = 1 << 4
	CAP_KILL             = 1 << 5
	CAP_SETGID           = 1 << 6
	CAP_SETUID           = 1 << 7
	CAP_SETPCAP          = 1 << 8
	CAP_LINUX_IMMUTABLE  = 1 << 9
	CAP_NET_BIND_SERVICE = 1 << 10
	CAP_NET_BROADCAST    = 1 << 11
	CAP_NET_ADMIN        = 1 << 12
	CAP_NET_RAW          = 1 << 13
	CAP_IPC_LOCK         = 1 << 14
	CAP_IPC_OWNER        = 1 << 15
	CAP_SYS_MODULE       = 1 << 16
	CAP_SYS_RAWIO        = 1 << 17
	CAP_SYS_CHROOT       = 1 << 18
	CAP_SYS_PTRACE       = 1 << 19
	CAP_SYS_PACCT        = 1 << 20
	CAP_SYS_ADMIN        = 1 << 21
	CAP_SYS_BOOT         = 1 << 22
	CAP_SYS_NICE         = 1 << 23
	CAP_SYS_RESOURCE     = 1 << 24
	CAP_SYS_TIME         = 1 << 25
	CAP_SYS_TTY_CONFIG   = 1 << 26
	CAP_MKNOD            = 1 << 27
	CAP_LEASE            = 1 << 28
	CAP_AUDIT_WRITE      = 1 << 29
	CAP_AUDIT_CONTROL    = 1 << 30
	CAP_SETFCAP          = 1 << 31
)

var capNames = map[uint64]string{
	CAP_CHOWN:            "CAP_CHOWN",
	CAP_DAC_OVERRIDE:     "CAP_DAC_OVERRIDE",
	CAP_DAC_READ_SEARCH:  "CAP_DAC_READ_SEARCH",
	CAP_SETGID:           "CAP_SETGID",
	CAP_SETUID:           "CAP_SETUID",
	CAP_NET_ADMIN:        "CAP_NET_ADMIN",
	CAP_NET_RAW:          "CAP_NET_RAW",
	CAP_SYS_PTRACE:       "CAP_SYS_PTRACE",
	CAP_SYS_ADMIN:        "CAP_SYS_ADMIN",
	CAP_SYS_CHROOT:       "CAP_SYS_CHROOT",
	CAP_SYS_BOOT:         "CAP_SYS_BOOT",
	CAP_SYS_MODULE:       "CAP_SYS_MODULE",
}

// CapNames returns a list of human-readable capability names present in the bitmask.
func CapNames(mask uint64) []string {
	var names []string
	for bit, name := range capNames {
		if (mask & bit) != 0 {
			names = append(names, name)
		}
	}
	return names
}

// Credentials models a process's security credential baseline.
type Credentials struct {
	UID           uint32 `json:"uid"`
	GID           uint32 `json:"gid"`
	EffectiveCaps uint64 `json:"effective_caps"`
}

// DiffCaps computes gained and dropped capabilities compared to an initial baseline.
func (c Credentials) DiffCaps(initialCaps uint64) (gained uint64, dropped uint64) {
	gained = c.EffectiveCaps &^ initialCaps
	dropped = initialCaps &^ c.EffectiveCaps
	return gained, dropped
}

// NamespaceIdentity represents the 7 Linux namespace inodes for a container process.
type NamespaceIdentity struct {
	NetNS    uint64 `json:"net_ns"`
	MntNS    uint64 `json:"mnt_ns"`
	PidNS    uint64 `json:"pid_ns"`
	UserNS   uint64 `json:"user_ns"`
	IpcNS    uint64 `json:"ipc_ns"`
	UtsNS    uint64 `json:"uts_ns"`
	CgroupNS uint64 `json:"cgroup_ns"`
}

// Diff compares the namespace identity against an initial baseline and returns a list of drifted namespaces.
func (n NamespaceIdentity) Diff(baseline NamespaceIdentity) []string {
	var drifted []string
	if baseline.NetNS != 0 && n.NetNS != 0 && n.NetNS != baseline.NetNS {
		drifted = append(drifted, fmt.Sprintf("net:[%d->%d]", baseline.NetNS, n.NetNS))
	}
	if baseline.MntNS != 0 && n.MntNS != 0 && n.MntNS != baseline.MntNS {
		drifted = append(drifted, fmt.Sprintf("mnt:[%d->%d]", baseline.MntNS, n.MntNS))
	}
	if baseline.PidNS != 0 && n.PidNS != 0 && n.PidNS != baseline.PidNS {
		drifted = append(drifted, fmt.Sprintf("pid:[%d->%d]", baseline.PidNS, n.PidNS))
	}
	if baseline.UserNS != 0 && n.UserNS != 0 && n.UserNS != baseline.UserNS {
		drifted = append(drifted, fmt.Sprintf("user:[%d->%d]", baseline.UserNS, n.UserNS))
	}
	if baseline.IpcNS != 0 && n.IpcNS != 0 && n.IpcNS != baseline.IpcNS {
		drifted = append(drifted, fmt.Sprintf("ipc:[%d->%d]", baseline.IpcNS, n.IpcNS))
	}
	if baseline.UtsNS != 0 && n.UtsNS != 0 && n.UtsNS != baseline.UtsNS {
		drifted = append(drifted, fmt.Sprintf("uts:[%d->%d]", baseline.UtsNS, n.UtsNS))
	}
	return drifted
}

// ProcessState represents a process running in a specific cgroup.
// Keyed by (cgroup_id, pid) to prevent PID reuse collisions.
type ProcessState struct {
	CgroupID  uint64        `json:"cgroup_id"`
	PID       uint32        `json:"pid"`
	PPID      uint32        `json:"ppid"`
	Comm      string        `json:"comm"`
	StartedAt time.Time     `json:"started_at"`
	ExitedAt  *time.Time    `json:"exited_at,omitempty"`
	Parent    *ProcessState `json:"-"`
}

// AncestryChain traverses parent links to build the full execution lineage.
// e.g. ["container-init", "sh", "curl"]
func (p *ProcessState) AncestryChain() []string {
	var chain []string
	curr := p
	for curr != nil {
		comm := curr.Comm
		if comm == "" {
			comm = fmt.Sprintf("pid-%d", curr.PID)
		}
		chain = append([]string{comm}, chain...)
		curr = curr.Parent
	}
	return chain
}

// AncestryString formats the ancestry chain into an arrow-delimited string.
func (p *ProcessState) AncestryString() string {
	return strings.Join(p.AncestryChain(), " -> ")
}
