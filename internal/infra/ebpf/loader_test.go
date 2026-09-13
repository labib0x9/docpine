package ebpf

import (
	"bytes"
	"encoding/binary"
	"testing"

	domainsec "github.com/labib0x9/docpine/internal/domain/security"
)

func TestDecodeRawEvent(t *testing.T) {
	raw := RawEventLayout{
		Timestamp: 1000000000,
		CgroupID:  777,
		PID:       1234,
		PPID:      1,
		Type:      uint32(domainsec.EventOpenat),
	}
	copy(raw.Comm[:], "cat")
	copy(raw.Data[:], "/etc/shadow")

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, &raw); err != nil {
		t.Fatalf("failed to encode raw event: %v", err)
	}

	decoded, err := DecodeRawEvent(buf.Bytes())
	if err != nil {
		t.Fatalf("failed to decode raw event: %v", err)
	}

	if decoded.CgroupID != 777 {
		t.Fatalf("expected cgroup_id 777, got %d", decoded.CgroupID)
	}
	if decoded.PID != 1234 {
		t.Fatalf("expected pid 1234, got %d", decoded.PID)
	}
	if decoded.Type != domainsec.EventOpenat {
		t.Fatalf("expected EventOpenat, got %v", decoded.Type)
	}
	if decoded.Comm != "cat" {
		t.Fatalf("expected comm 'cat', got %q", decoded.Comm)
	}
	if decoded.Data != "/etc/shadow" {
		t.Fatalf("expected data '/etc/shadow', got %q", decoded.Data)
	}
}
