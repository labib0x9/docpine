package security

import (
	"strings"
	"time"
)

// NetworkRule specifies in-kernel connection rules (cgroup/connect4).
type NetworkRule struct {
	DstIP   string `json:"dst_ip"`   // IPv4 string e.g. "203.0.113.10" or "0.0.0.0" (any)
	DstPort uint16 `json:"dst_port"` // Port number (0 for any port)
	Action  string `json:"action"`   // "allow" or "deny"
}

// FSRule specifies in-kernel sensitive file access rules (lsm/file_open).
type FSRule struct {
	Path   string `json:"path"`   // Sensitive path pattern e.g. "/etc/shadow"
	Inode  uint64 `json:"inode"`  // Resolved inode on host (0 if unresolved)
	Dev    uint32 `json:"dev"`    // Device number
	Action string `json:"action"` // "allow" or "deny"
}

// ContainerPolicy represents security restrictions compiled to in-kernel BPF maps.
type ContainerPolicy struct {
	ContainerID         string        `json:"container_id"`
	AllowedCapabilities []string      `json:"allowed_capabilities"`
	NetworkRules        []NetworkRule `json:"network_rules"`
	FSRules             []FSRule      `json:"fs_rules"`
	UpdatedAt           time.Time     `json:"updated_at"`
}

// CapsBitmask converts a slice of capability names into an unsigned 64-bit mask.
func (p ContainerPolicy) CapsBitmask() uint64 {
	var mask uint64
	for _, capName := range p.AllowedCapabilities {
		normalized := strings.ToUpper(strings.TrimSpace(capName))
		if !strings.HasPrefix(normalized, "CAP_") {
			normalized = "CAP_" + normalized
		}
		for bit, name := range capNames {
			if name == normalized {
				mask |= bit
				break
			}
		}
	}
	return mask
}
