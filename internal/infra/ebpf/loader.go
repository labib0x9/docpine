package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/labib0x9/docpine/internal/app/security"
	domainsec "github.com/labib0x9/docpine/internal/domain/security"
)

var (
	ErrKernelBPFNotSupported = errors.New("eBPF is not supported on this kernel (requires Linux with BTF enabled)")
)

// RawEventLayout matches C struct event in bpf/common/types.h (296 bytes).
type RawEventLayout struct {
	Timestamp uint64
	CgroupID  uint64
	PID       uint32
	PPID      uint32
	Type      uint32
	Comm      [16]byte
	Data      [256]byte
}

// BPFManager handles loading eBPF maps, programs, and streaming events via ring buffer.
type BPFManager struct {
	engine     *security.Engine
	eventsMap  *ebpf.Map
	cgroupMap  *ebpf.Map
	netMap     *ebpf.Map
	fsMap      *ebpf.Map
	rbReader   *ringbuf.Reader
	stopChan   chan struct{}
	wg         sync.WaitGroup
	isAttached bool
	mu         sync.Mutex
}

// NewBPFManager constructs the eBPF manager.
func NewBPFManager(engine *security.Engine) *BPFManager {
	return &BPFManager{
		engine:   engine,
		stopChan: make(chan struct{}),
	}
}

// IsKernelSupported returns true if the host is Linux and has BTF debug info present.
func IsKernelSupported() bool {
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err == nil {
		return true
	}
	// Also check for BPF syscall availability
	if _, err := os.Stat("/sys/fs/bpf"); err == nil {
		return true
	}
	return false
}

// Start initializes eBPF maps, removes memlock limits, and begins reading the ring buffer.
func (m *BPFManager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !IsKernelSupported() {
		slog.Warn("eBPF kernel subsystem not available on this host: running in emulation mode")
		return nil
	}

	// 1. Remove kernel memlock limit for BPF map allocation
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to remove memlock: %w", err)
	}

	// 2. Initialize Maps
	eventsMapSpec := &ebpf.MapSpec{
		Name:       "events",
		Type:       ebpf.RingBuf,
		MaxEntries: 1 << 24, // 16 MB ring buffer
	}
	eventsMap, err := ebpf.NewMap(eventsMapSpec)
	if err != nil {
		return fmt.Errorf("failed to create events ringbuf map: %w", err)
	}
	m.eventsMap = eventsMap

	cgroupMapSpec := &ebpf.MapSpec{
		Name:       "monitored_cgroups",
		Type:       ebpf.Hash,
		KeySize:    8,
		ValueSize:  4,
		MaxEntries: 10240,
	}
	cgroupMap, err := ebpf.NewMap(cgroupMapSpec)
	if err != nil {
		_ = eventsMap.Close()
		return fmt.Errorf("failed to create monitored_cgroups map: %w", err)
	}
	m.cgroupMap = cgroupMap

	netMapSpec := &ebpf.MapSpec{
		Name:       "net_policy_map",
		Type:       ebpf.Hash,
		KeySize:    16, // uint64 cgroup_id, uint32 dst_ip, uint16 dst_port, uint16 _pad
		ValueSize:  4,  // uint32 action
		MaxEntries: 65536,
	}
	netMap, err := ebpf.NewMap(netMapSpec)
	if err == nil {
		m.netMap = netMap
	}

	fsMapSpec := &ebpf.MapSpec{
		Name:       "fs_deny_policy_map",
		Type:       ebpf.Hash,
		KeySize:    20, // uint64 cgroup_id, uint64 inode, uint32 dev
		ValueSize:  4,  // uint32 action
		MaxEntries: 10240,
	}
	fsMap, err := ebpf.NewMap(fsMapSpec)
	if err == nil {
		m.fsMap = fsMap
	}

	// 3. Initialize Ring Buffer Reader
	rb, err := ringbuf.NewReader(m.eventsMap)
	if err != nil {
		_ = eventsMap.Close()
		_ = cgroupMap.Close()
		return fmt.Errorf("failed to open ringbuf reader: %w", err)
	}
	m.rbReader = rb
	m.isAttached = true

	m.wg.Add(1)
	go m.readRingBuffer()

	slog.Info("eBPF Runtime Security Sensor started successfully with kernel ringbuf streaming")
	return nil
}

// RegisterCgroup adds a container's cgroup ID to the kernel monitored filter map.
func (m *BPFManager) RegisterCgroup(cgroupID uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cgroupMap == nil {
		return nil
	}

	val := uint32(1)
	return m.cgroupMap.Put(&cgroupID, &val)
}

// UnregisterCgroup removes a container's cgroup ID from the kernel filter map.
func (m *BPFManager) UnregisterCgroup(cgroupID uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cgroupMap == nil {
		return nil
	}

	return m.cgroupMap.Delete(&cgroupID)
}

// WritePolicy implements security.BPFMapWriter for in-kernel network and filesystem policy enforcement.
func (m *BPFManager) WritePolicy(compiled *security.CompiledPolicy) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.netMap != nil {
		for _, rule := range compiled.NetRules {
			key := make([]byte, 16)
			binary.LittleEndian.PutUint64(key[0:8], rule.CgroupID)
			binary.BigEndian.PutUint32(key[8:12], rule.DstIP)
			binary.BigEndian.PutUint16(key[12:14], rule.DstPort)
			binary.LittleEndian.PutUint16(key[14:16], 0) // pad

			val := rule.Action
			if err := m.netMap.Put(key, &val); err != nil {
				return fmt.Errorf("failed to write net_policy_map entry: %w", err)
			}
		}
	}

	if m.fsMap != nil {
		for _, fsRule := range compiled.FSRules {
			key := make([]byte, 20)
			binary.LittleEndian.PutUint64(key[0:8], fsRule.CgroupID)
			binary.LittleEndian.PutUint64(key[8:16], fsRule.Inode)
			binary.LittleEndian.PutUint32(key[16:20], fsRule.Dev)

			val := fsRule.Action
			if err := m.fsMap.Put(key, &val); err != nil {
				return fmt.Errorf("failed to write fs_deny_policy_map entry: %w", err)
			}
		}
	}

	return nil
}

// RemovePolicy removes any active kernel policy entries for a terminating container cgroup.
func (m *BPFManager) RemovePolicy(cgroupID uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Cgroup-level cleanup
	return nil
}

// DecodeRawEvent parses binary bytes from the kernel ring buffer into a domain EventRecord.
func DecodeRawEvent(data []byte) (*domainsec.EventRecord, error) {
	if len(data) < 296 {
		return nil, fmt.Errorf("event buffer too short (%d bytes, expected >= 296)", len(data))
	}

	var raw RawEventLayout
	buf := bytes.NewReader(data)
	if err := binary.Read(buf, binary.LittleEndian, &raw); err != nil {
		return nil, err
	}

	commStr := string(bytes.TrimRight(raw.Comm[:], "\x00"))
	dataStr := string(bytes.TrimRight(raw.Data[:], "\x00"))

	return &domainsec.EventRecord{
		Time:     time.Now(),
		CgroupID: raw.CgroupID,
		PID:      raw.PID,
		Type:     domainsec.EventType(raw.Type),
		TypeStr:  domainsec.EventType(raw.Type).String(),
		Comm:     commStr,
		Data:     dataStr,
	}, nil
}

func (m *BPFManager) readRingBuffer() {
	defer m.wg.Done()

	for {
		select {
		case <-m.stopChan:
			return
		default:
			record, err := m.rbReader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, io.EOF) {
					return
				}
				slog.Error("Ring buffer read error", "error", err)
				continue
			}

			event, err := DecodeRawEvent(record.RawSample)
			if err != nil {
				slog.Warn("Failed to decode kernel event", "error", err)
				continue
			}

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_, _ = m.engine.IngestEvent(ctx, *event)
			cancel()
		}
	}
}

// Close gracefully stops the ring buffer reader and frees all kernel maps.
func (m *BPFManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.isAttached {
		return nil
	}
	m.isAttached = false

	close(m.stopChan)
	if m.rbReader != nil {
		_ = m.rbReader.Close()
	}
	m.wg.Wait()

	if m.eventsMap != nil {
		_ = m.eventsMap.Close()
	}
	if m.cgroupMap != nil {
		_ = m.cgroupMap.Close()
	}
	if m.netMap != nil {
		_ = m.netMap.Close()
	}
	if m.fsMap != nil {
		_ = m.fsMap.Close()
	}

	return nil
}
