package security

import (
	"testing"
)

func TestProcessAncestry(t *testing.T) {
	initProc := &ProcessState{
		CgroupID: 100,
		PID:      1,
		PPID:     0,
		Comm:     "container-init",
	}

	shProc := &ProcessState{
		CgroupID: 100,
		PID:      12,
		PPID:     1,
		Comm:     "sh",
		Parent:   initProc,
	}

	curlProc := &ProcessState{
		CgroupID: 100,
		PID:      45,
		PPID:     12,
		Comm:     "curl",
		Parent:   shProc,
	}

	chain := curlProc.AncestryChain()
	if len(chain) != 3 {
		t.Fatalf("expected ancestry chain of length 3, got %d", len(chain))
	}

	expectedStr := "container-init -> sh -> curl"
	if curlProc.AncestryString() != expectedStr {
		t.Fatalf("expected ancestry %q, got %q", expectedStr, curlProc.AncestryString())
	}
}

func TestCredentialsDiff(t *testing.T) {
	initial := uint64(CAP_CHOWN | CAP_SETUID)
	creds := Credentials{
		UID:           0,
		GID:           0,
		EffectiveCaps: uint64(CAP_CHOWN | CAP_SETUID | CAP_SYS_ADMIN),
	}

	gained, dropped := creds.DiffCaps(initial)
	if gained != CAP_SYS_ADMIN {
		t.Fatalf("expected gained CAP_SYS_ADMIN, got %d", gained)
	}
	if dropped != 0 {
		t.Fatalf("expected 0 dropped caps, got %d", dropped)
	}

	gainedNames := CapNames(gained)
	if len(gainedNames) != 1 || gainedNames[0] != "CAP_SYS_ADMIN" {
		t.Fatalf("expected [CAP_SYS_ADMIN], got %v", gainedNames)
	}
}

func TestNamespaceDiff(t *testing.T) {
	baseline := NamespaceIdentity{
		NetNS: 4026531992,
		MntNS: 4026531993,
		PidNS: 4026531994,
	}

	drifted := NamespaceIdentity{
		NetNS: 4026532888, // Changed net namespace
		MntNS: 4026531993,
		PidNS: 4026531994,
	}

	diffs := drifted.Diff(baseline)
	if len(diffs) != 1 {
		t.Fatalf("expected 1 drifted namespace, got %d: %v", len(diffs), diffs)
	}

	if diffs[0] != "net:[4026531992->4026532888]" {
		t.Fatalf("unexpected diff output: %s", diffs[0])
	}
}

func TestPolicyCapsBitmask(t *testing.T) {
	policy := ContainerPolicy{
		AllowedCapabilities: []string{"CHOWN", "CAP_SYS_ADMIN", "net_admin"},
	}

	mask := policy.CapsBitmask()
	expected := uint64(CAP_CHOWN | CAP_SYS_ADMIN | CAP_NET_ADMIN)
	if mask != expected {
		t.Fatalf("expected mask %d, got %d", expected, mask)
	}
}
