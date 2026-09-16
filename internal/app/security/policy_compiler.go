package security

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/labib0x9/docpine/internal/domain/security"
)

// CompiledNetRule represents binary struct net_policy_key / net_policy_val for BPF maps.
type CompiledNetRule struct {
	CgroupID uint64
	DstIP    uint32 // network byte order
	DstPort  uint16 // network byte order
	Action   uint32 // 1 = allow, 0 = deny
}

// CompiledFSRule represents binary struct fs_policy_key for BPF LSM maps.
type CompiledFSRule struct {
	CgroupID uint64
	Inode    uint64
	Dev      uint32
	Action   uint32
}

// CompiledPolicy contains in-kernel struct representations ready for BPF map injection.
type CompiledPolicy struct {
	ContainerID string
	CgroupID    uint64
	AllowedCaps uint64
	NetRules    []CompiledNetRule
	FSRules     []CompiledFSRule
}

// PolicyCompiler translates domain ContainerPolicy into kernel BPF map structures.
type PolicyCompiler struct{}

// NewPolicyCompiler creates a new policy compiler.
func NewPolicyCompiler() *PolicyCompiler {
	return &PolicyCompiler{}
}

// Compile translates domain security policy into kernel-ready binary map entries.
func (c *PolicyCompiler) Compile(cgroupID uint64, p security.ContainerPolicy) (*CompiledPolicy, error) {
	compiled := &CompiledPolicy{
		ContainerID: p.ContainerID,
		CgroupID:    cgroupID,
		AllowedCaps: p.CapsBitmask(),
	}

	for _, rule := range p.NetworkRules {
		ipUint, err := parseIPv4(rule.DstIP)
		if err != nil {
			return nil, fmt.Errorf("invalid network rule IP %q: %w", rule.DstIP, err)
		}

		action := uint32(1) // default allow
		if strings.ToLower(rule.Action) == "deny" || rule.Action == "block" || rule.Action == "0" {
			action = 0
		}

		compiled.NetRules = append(compiled.NetRules, CompiledNetRule{
			CgroupID: cgroupID,
			DstIP:    ipUint,
			DstPort:  rule.DstPort,
			Action:   action,
		})
	}

	for _, fsRule := range p.FSRules {
		action := uint32(1)
		if strings.ToLower(fsRule.Action) == "deny" || fsRule.Action == "block" || fsRule.Action == "0" {
			action = 0
		}

		compiled.FSRules = append(compiled.FSRules, CompiledFSRule{
			CgroupID: cgroupID,
			Inode:    fsRule.Inode,
			Dev:      fsRule.Dev,
			Action:   action,
		})
	}

	return compiled, nil
}

func parseIPv4(ipStr string) (uint32, error) {
	if ipStr == "" || ipStr == "0.0.0.0" || ipStr == "*" {
		return 0, nil
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0, fmt.Errorf("invalid IP format")
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, fmt.Errorf("only IPv4 rules currently supported")
	}
	return binary.BigEndian.Uint32(ip4), nil
}
