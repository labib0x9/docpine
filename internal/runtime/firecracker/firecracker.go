package firecracker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/labib0x9/docpine/internal/runtime"
)

/*
Architecture Tradeoff Analysis: Firecracker PTY Attach Architecture
===================================================================

In Firecracker microVMs, there is no Docker-style container runtime daemon or `exec attach` API.
We evaluated two mechanisms for attaching interactive PTY sessions to guest microVMs:

Choice A: Guest Serial Console over Named FIFOs (Selected Implementation)
-------------------------------------------------------------------------
- How it works: Firecracker boots the guest kernel with `console=ttyS0 init=/bin/sh` (or agetty).
  The microVM's serial port is bound to host-side named FIFO pipes (`stdin.fifo`, `stdout.fifo`).
  Docpine attaches interactive terminal streams by reading from `stdout.fifo` and writing to `stdin.fifo`.
- Pros:
  1. Standard Linux kernel serial driver with zero custom guest daemon dependencies.
  2. Extremely minimal rootfs image footprint (runs standard Alpine/Busybox rootfs directly).
  3. Immediate early-boot terminal availability and resilience to userland crashes.
- Cons:
  1. Single console stream per microVM (ideal for Docpine's 1-session-per-microVM architecture).

Choice B: In-Guest Agent over Host-Guest Vsock (AF_VSOCK)
--------------------------------------------------------
- How it works: A custom Go agent is baked into the rootfs image, starts on boot, and listens
  on a designated vsock port (e.g. port 52). When host connects, the agent calls `openpty` to spawn
  an interactive shell and relays raw PTY bytes across the vsock channel.
- Pros:
  1. Supports multi-exec attachments per VM and explicit out-of-band PTY window resize signals.
- Cons:
  1. Requires building, maintaining, and baking custom guest binaries into every rootfs image.
  2. Guest agent startup delays and potential failure modes if guest agent crashes.

Decision:
Docpine implements Choice A (Guest Serial Console over FIFOs) to provide rock-solid, zero-dependency,
fast microVM provisioning with true 1:1 hardware virtualization isolation.
*/

func init() {
	runtime.Register("firecracker", func(ctx context.Context, cfg runtime.Config) (runtime.Runtime, error) {
		return New(ctx, cfg)
	})
}

// FirecrackerRuntime manages Firecracker microVM lifecycles.
type FirecrackerRuntime struct {
	cfg        runtime.Config
	binPath    string
	kernelPath string
	rootfsPath string
}

// New creates a new Firecracker runtime instance.
func New(ctx context.Context, cfg runtime.Config) (*FirecrackerRuntime, error) {
	bin := cfg.FirecrackerBin
	if bin == "" {
		bin = "firecracker"
	}

	kernel := cfg.KernelPath
	if kernel == "" {
		kernel = os.Getenv("DOCPINE_KERNEL_PATH")
		if kernel == "" {
			kernel = "/var/lib/docpine/vmlinux"
		}
	}

	rootfs := cfg.RootFSPath
	if rootfs == "" {
		rootfs = os.Getenv("DOCPINE_ROOTFS_PATH")
		if rootfs == "" {
			rootfs = "/var/lib/docpine/rootfs.ext4"
		}
	}

	return &FirecrackerRuntime{
		cfg:        cfg,
		binPath:    bin,
		kernelPath: kernel,
		rootfsPath: rootfs,
	}, nil
}

// Name returns the backend identifier.
func (r *FirecrackerRuntime) Name() string {
	return "firecracker"
}

// CheckPrerequisites verifies /dev/kvm availability, the firecracker binary, kernel, and rootfs.
func (r *FirecrackerRuntime) CheckPrerequisites(ctx context.Context) error {
	// 1. Verify /dev/kvm read/write access (requires Linux with hardware virt or nested virt)
	kvmFile, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("%w: /dev/kvm is not accessible (%v). Firecracker requires Linux with KVM virtualization support", runtime.ErrPrerequisiteFailed, err)
	}
	_ = kvmFile.Close()

	// 2. Verify firecracker binary on PATH or specified path
	resolvedBin, err := exec.LookPath(r.binPath)
	if err != nil {
		return fmt.Errorf("%w: firecracker binary %q not found on PATH (download from https://github.com/firecracker-microvm/firecracker/releases)", runtime.ErrPrerequisiteFailed, r.binPath)
	}

	// Verify firecracker execution
	out, err := exec.CommandContext(ctx, resolvedBin, "--version").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: firecracker binary failed: %v (output: %s)", runtime.ErrPrerequisiteFailed, err, string(out))
	}

	// 3. Verify kernel image exists
	if _, err := os.Stat(r.kernelPath); os.IsNotExist(err) {
		return fmt.Errorf("%w: firecracker kernel image not found at %q (set DOCPINE_KERNEL_PATH)", runtime.ErrPrerequisiteFailed, r.kernelPath)
	}

	// 4. Verify rootfs image exists
	if _, err := os.Stat(r.rootfsPath); os.IsNotExist(err) {
		return fmt.Errorf("%w: firecracker rootfs image not found at %q (set DOCPINE_ROOTFS_PATH)", runtime.ErrPrerequisiteFailed, r.rootfsPath)
	}

	return nil
}

// CreateSandbox provisions, configures, and boots a new Firecracker microVM.
func (r *FirecrackerRuntime) CreateSandbox(ctx context.Context, opts runtime.SandboxOptions) (runtime.Sandbox, error) {
	sessionID := opts.SessionID
	if sessionID == "" {
		sessionID = fmt.Sprintf("fc-%d", time.Now().UnixNano())
	}

	// Create a dedicated workspace directory for this microVM
	workDir, err := os.MkdirTemp("", fmt.Sprintf("docpine-fc-%s-*", sessionID))
	if err != nil {
		return nil, fmt.Errorf("failed to create sandbox workdir: %w", err)
	}

	socketPath := filepath.Join(workDir, "firecracker.sock")
	stdinFIFO := filepath.Join(workDir, "stdin.fifo")
	stdoutFIFO := filepath.Join(workDir, "stdout.fifo")
	vmRootfs := filepath.Join(workDir, "rootfs.ext4")

	// Create named FIFOs for serial console I/O
	if err := syscall.Mkfifo(stdinFIFO, 0600); err != nil {
		_ = os.RemoveAll(workDir)
		return nil, fmt.Errorf("failed to create stdin fifo: %w", err)
	}
	if err := syscall.Mkfifo(stdoutFIFO, 0600); err != nil {
		_ = os.RemoveAll(workDir)
		return nil, fmt.Errorf("failed to create stdout fifo: %w", err)
	}

	// Create an ephemeral copy/overlay of the base rootfs
	if err := copyFile(r.rootfsPath, vmRootfs); err != nil {
		_ = os.RemoveAll(workDir)
		return nil, fmt.Errorf("failed to prepare rootfs copy: %w", err)
	}

	// Spawn the Firecracker process
	cmd := exec.CommandContext(context.Background(), r.binPath, "--api-sock", socketPath)
	cmd.Dir = workDir
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		_ = os.RemoveAll(workDir)
		return nil, fmt.Errorf("failed to start firecracker process: %w", err)
	}

	sb := &firecrackerSandbox{
		id:         sessionID,
		cmd:        cmd,
		workDir:    workDir,
		socketPath: socketPath,
		stdinFIFO:  stdinFIFO,
		stdoutFIFO: stdoutFIFO,
	}

	// Wait for Firecracker API socket to be created
	if err := waitForSocket(socketPath, 3*time.Second); err != nil {
		_ = sb.Destroy(context.Background())
		return nil, fmt.Errorf("firecracker api socket did not appear: %w (stderr: %s)", err, stderrBuf.String())
	}

	// Configure the microVM via Firecracker HTTP API
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
			},
		},
		Timeout: 5 * time.Second,
	}

	memSize := int64(128)
	if opts.MemoryLimit > 0 {
		memSize = opts.MemoryLimit / (1024 * 1024)
		if memSize < 64 {
			memSize = 64
		}
	}

	// 1. Set Machine Configuration
	machineCfg := map[string]any{
		"vcpu_count":   1,
		"mem_size_mib": memSize,
		"smt":          false,
	}
	if err := putAPI(client, "/machine-config", machineCfg); err != nil {
		_ = sb.Destroy(context.Background())
		return nil, fmt.Errorf("set machine-config failed: %w", err)
	}

	// 2. Set Boot Source
	bootSource := map[string]any{
		"kernel_image_path": r.kernelPath,
		"boot_args":         "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw init=/bin/sh",
	}
	if err := putAPI(client, "/boot-source", bootSource); err != nil {
		_ = sb.Destroy(context.Background())
		return nil, fmt.Errorf("set boot-source failed: %w", err)
	}

	// 3. Set Rootfs Drive
	driveCfg := map[string]any{
		"drive_id":       "rootfs",
		"path_on_host":   vmRootfs,
		"is_root_device": true,
		"is_read_only":   false,
	}
	if err := putAPI(client, "/drives/rootfs", driveCfg); err != nil {
		_ = sb.Destroy(context.Background())
		return nil, fmt.Errorf("set drive failed: %w", err)
	}

	// 4. Attach Serial Console FIFOs
	serialCfg := map[string]any{
		"in_path":  stdinFIFO,
		"out_path": stdoutFIFO,
	}
	if err := putAPI(client, "/serial", serialCfg); err != nil {
		_ = sb.Destroy(context.Background())
		return nil, fmt.Errorf("set serial console failed: %w", err)
	}

	// 5. Start the MicroVM Instance
	actionCfg := map[string]any{
		"action_type": "InstanceStart",
	}
	if err := putAPI(client, "/actions", actionCfg); err != nil {
		_ = sb.Destroy(context.Background())
		return nil, fmt.Errorf("instance start action failed: %w", err)
	}

	return sb, nil
}

// Close releases any global runtime state.
func (r *FirecrackerRuntime) Close() error {
	return nil
}

// firecrackerSandbox manages an active Firecracker microVM.
type firecrackerSandbox struct {
	id         string
	cmd        *exec.Cmd
	workDir    string
	socketPath string
	stdinFIFO  string
	stdoutFIFO string
	destroyMu  sync.Mutex
	destroyed  bool
}

func (s *firecrackerSandbox) ID() string {
	return s.id
}

// AttachPTY connects to the guest serial console FIFOs.
func (s *firecrackerSandbox) AttachPTY(ctx context.Context) (io.ReadWriteCloser, error) {
	s.destroyMu.Lock()
	if s.destroyed {
		s.destroyMu.Unlock()
		return nil, runtime.ErrSandboxDestroyed
	}
	s.destroyMu.Unlock()

	// Open stdout FIFO for reading (guest output)
	outF, err := os.OpenFile(s.stdoutFIFO, os.O_RDONLY|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open stdout fifo: %w", err)
	}

	// Open stdin FIFO for writing (guest input)
	inF, err := os.OpenFile(s.stdinFIFO, os.O_WRONLY, 0600)
	if err != nil {
		_ = outF.Close()
		return nil, fmt.Errorf("failed to open stdin fifo: %w", err)
	}

	return &fcSerialStream{
		reader: outF,
		writer: inF,
	}, nil
}

// Destroy terminates the Firecracker process and cleans up the temporary files and FIFOs.
func (s *firecrackerSandbox) Destroy(ctx context.Context) error {
	s.destroyMu.Lock()
	defer s.destroyMu.Unlock()

	if s.destroyed {
		return nil
	}
	s.destroyed = true

	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
		_ = s.cmd.Wait()
	}

	if s.workDir != "" {
		_ = os.RemoveAll(s.workDir)
	}

	return nil
}

type fcSerialStream struct {
	reader    *os.File
	writer    *os.File
	closeOnce sync.Once
}

func (f *fcSerialStream) Read(b []byte) (int, error) {
	for {
		n, err := f.reader.Read(b)
		if err != nil && errors.Is(err, syscall.EAGAIN) {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		return n, err
	}
}

func (f *fcSerialStream) Write(b []byte) (int, error) {
	return f.writer.Write(b)
}

func (f *fcSerialStream) Close() error {
	var err1, err2 error
	f.closeOnce.Do(func() {
		err1 = f.reader.Close()
		err2 = f.writer.Close()
	})
	if err1 != nil {
		return err1
	}
	return err2
}

func putAPI(client *http.Client, path string, body any) error {
	jsonBytes, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPut, "http://localhost"+path, bytes.NewReader(jsonBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("api %s returned HTTP %d: %s", path, resp.StatusCode, string(respBytes))
	}

	return nil
}

func waitForSocket(socketPath string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath); err == nil {
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for socket %s", socketPath)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}
