package gvisor

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	"github.com/labib0x9/docpine/internal/config"
	"github.com/labib0x9/docpine/internal/runtime"
)

/*
Architecture Tradeoff Analysis: gVisor (runsc) Integration Path
================================================================

In Docpine, we evaluated two architectural paths for running sandboxes under gVisor:

Path A: Docker Daemon with `runtime: "runsc"` (Selected Primary Path)
-------------------------------------------------------------------
- How it works: Docpine speaks to the Docker daemon and passes `HostConfig.Runtime = "runsc"`.
  Docker delegates container creation to the `runsc` OCI runtime binary.
- Pros:
  1. Image management: Leverages standard OCI registries and image caching (e.g. `alpine:3.20`).
  2. Network & Storage: Automated bridge/none networking, layer isolation, and cleanup.
  3. Seamless PTY Hijack: Standardized streaming over Docker socket without manual OCI bundle creation.
  4. Sentry Isolation: All application syscalls are intercepted and handled by gVisor's Sentry kernel in user space.
- Cons:
  1. Requires the host Docker daemon to have `runsc` registered in `/etc/docker/daemon.json`.

Path B: Direct `runsc` OCI Bundle Execution (Standalone Mode)
------------------------------------------------------------
- How it works: Docpine creates an OCI bundle on disk (`config.json` + unpacked rootfs) and directly
  invokes `runsc create`, `runsc start`, and `runsc exec` via CLI / unix domain socket console.
- Pros:
  1. Completely daemonless; operates without dockerd.
- Cons:
  1. Requires managing unpacked rootfs bundles, cgroups, network namespaces, and PTY socket multiplexing manually.

Decision:
Docpine implements Path A as the default production driver with automated `runsc` runtime detection,
while checking for both host `runsc` binary presence on $PATH and Docker runtime registration.
*/

func init() {
	runtime.Register("gvisor", func(ctx context.Context, cfg config.Runtime) (runtime.Runtime, error) {
		return New(ctx, cfg)
	})
	runtime.Register("runsc", func(ctx context.Context, cfg config.Runtime) (runtime.Runtime, error) {
		return New(ctx, cfg)
	})
}

// GvisorRuntime implements runtime.Runtime using gVisor's runsc runtime.
type GvisorRuntime struct {
	cli        *client.Client
	cfg        config.Runtime
	runscBin   string
	defaultImg string
}

// New creates a new gVisor runtime instance.
func New(ctx context.Context, cfg config.Runtime) (*GvisorRuntime, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create docker client for gvisor: %w", err)
	}

	bin := cfg.RunscPath
	if bin == "" {
		bin = "runsc"
	}

	img := cfg.Image
	if img == "" {
		img = "alpine:3.20"
	}

	return &GvisorRuntime{
		cli:        cli,
		cfg:        cfg,
		runscBin:   bin,
		defaultImg: img,
	}, nil
}

// Name returns the runtime backend identifier.
func (r *GvisorRuntime) Name() string {
	return "gvisor"
}

// CheckPrerequisites verifies that runsc is available on the host and Docker is reachable.
func (r *GvisorRuntime) CheckPrerequisites(ctx context.Context) error {
	// 1. Check if runsc binary is on PATH or executable
	binPath, err := exec.LookPath(r.runscBin)
	if err != nil {
		return fmt.Errorf("%w: gvisor binary %q not found on PATH (install runsc: https://gvisor.dev/docs/user_guide/install/)", runtime.ErrPrerequisiteFailed, r.runscBin)
	}

	// Verify runsc runs
	cmd := exec.CommandContext(ctx, binPath, "--version")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: failed executing %s --version: %v (output: %s)", runtime.ErrPrerequisiteFailed, binPath, err, string(out))
	}

	// 2. Check Docker daemon connectivity
	pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	info, err := r.cli.Info(pingCtx)
	if err != nil {
		return fmt.Errorf("%w: docker daemon unreachable for gvisor (%v)", runtime.ErrPrerequisiteFailed, err)
	}

	// 3. Verify Docker daemon has runsc runtime configured
	hasRunscRuntime := false
	for rtName := range info.Runtimes {
		if strings.Contains(strings.ToLower(rtName), "runsc") || strings.Contains(strings.ToLower(rtName), "gvisor") {
			hasRunscRuntime = true
			break
		}
	}

	if !hasRunscRuntime {
		// Log informative prerequisite error
		return fmt.Errorf("%w: docker daemon does not have 'runsc' runtime configured in /etc/docker/daemon.json (run 'runsc install' and restart docker)", runtime.ErrPrerequisiteFailed)
	}

	return nil
}

// ensureImage pulls the image if it is not already available.
func (r *GvisorRuntime) ensureImage(ctx context.Context, imgName string) error {
	inspectCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	_, err := r.cli.ImageInspect(inspectCtx, imgName)
	if err == nil {
		return nil
	}

	if strings.Contains(err.Error(), "No such image:") || client.IsErrNotFound(err) {
		pullCtx, pullCancel := context.WithTimeout(ctx, 60*time.Second)
		defer pullCancel()

		reader, err := r.cli.ImagePull(pullCtx, imgName, image.PullOptions{})
		if err != nil {
			return fmt.Errorf("failed to pull image %s: %w", imgName, err)
		}
		defer reader.Close()
		_, _ = io.Copy(io.Discard, reader)
		return nil
	}

	return err
}

// CreateSandbox provisions an Alpine container executing inside a gVisor runsc sandbox.
func (r *GvisorRuntime) CreateSandbox(ctx context.Context, opts runtime.SandboxOptions) (runtime.Sandbox, error) {
	img := opts.Image
	if img == "" {
		img = r.defaultImg
	}

	if err := r.ensureImage(ctx, img); err != nil {
		return nil, fmt.Errorf("ensure gvisor image failed: %w", err)
	}

	cmd := opts.Command
	if len(cmd) == 0 {
		cmd = []string{"/bin/sh"}
	}

	containerConfig := &container.Config{
		Image:        img,
		Cmd:          cmd,
		Env:          opts.Env,
		AttachStdin:  true,
		AttachStdout: true,
		AttachStderr: true,
		Tty:          true,
		OpenStdin:    true,
		StdinOnce:    false,
	}

	hostConfig := &container.HostConfig{
		Runtime:    "runsc", // Enforce gVisor kernel sandboxing
		AutoRemove: false,
	}

	if r.cfg.NetworkMode != "" {
		hostConfig.NetworkMode = container.NetworkMode(r.cfg.NetworkMode)
	}
	if opts.MemoryLimit > 0 {
		hostConfig.Resources.Memory = opts.MemoryLimit
	}
	if opts.CPUShares > 0 {
		hostConfig.Resources.CPUShares = opts.CPUShares
	}

	containerName := ""
	if opts.SessionID != "" {
		containerName = fmt.Sprintf("docpine-gvisor-%s", opts.SessionID)
	}

	resp, err := r.cli.ContainerCreate(ctx, containerConfig, hostConfig, nil, nil, containerName)
	if err != nil {
		return nil, fmt.Errorf("gvisor container create failed: %w", err)
	}

	if err := r.cli.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		_ = r.cli.ContainerRemove(context.Background(), resp.ID, container.RemoveOptions{Force: true})
		return nil, fmt.Errorf("gvisor container start failed: %w", err)
	}

	return &gvisorSandbox{
		id:  resp.ID,
		cli: r.cli,
	}, nil
}

// Close releases the Docker client.
func (r *GvisorRuntime) Close() error {
	return r.cli.Close()
}

// gvisorSandbox represents an active gVisor sandbox container.
type gvisorSandbox struct {
	id        string
	cli       *client.Client
	destroyMu sync.Mutex
	destroyed bool
}

func (s *gvisorSandbox) ID() string {
	return s.id
}

// CgroupID returns the 64-bit cgroup ID or init PID for the gVisor sandbox container.
func (s *gvisorSandbox) CgroupID() (uint64, error) {
	s.destroyMu.Lock()
	if s.destroyed {
		s.destroyMu.Unlock()
		return 0, runtime.ErrSandboxDestroyed
	}
	s.destroyMu.Unlock()

	inspect, err := s.cli.ContainerInspect(context.Background(), s.id)
	if err != nil {
		return 0, fmt.Errorf("failed to inspect gvisor container for cgroup: %w", err)
	}

	if inspect.State == nil || inspect.State.Pid == 0 {
		return 0, fmt.Errorf("gvisor sentry process is not running")
	}

	return uint64(inspect.State.Pid), nil
}

func (s *gvisorSandbox) AttachPTY(ctx context.Context) (io.ReadWriteCloser, error) {
	s.destroyMu.Lock()
	if s.destroyed {
		s.destroyMu.Unlock()
		return nil, runtime.ErrSandboxDestroyed
	}
	s.destroyMu.Unlock()

	hijack, err := s.cli.ContainerAttach(ctx, s.id, container.AttachOptions{
		Stream: true,
		Stdin:  true,
		Stdout: true,
		Stderr: true,
	})
	if err != nil {
		return nil, fmt.Errorf("gvisor container attach failed: %w", err)
	}

	return &gvisorPTYStream{
		reader: hijack.Reader,
		conn:   hijack.Conn,
		closeFunc: func() error {
			hijack.Close()
			return nil
		},
	}, nil
}

func (s *gvisorSandbox) Destroy(ctx context.Context) error {
	s.destroyMu.Lock()
	defer s.destroyMu.Unlock()

	if s.destroyed {
		return nil
	}
	s.destroyed = true

	timeout := 2
	_ = s.cli.ContainerStop(ctx, s.id, container.StopOptions{Timeout: &timeout})
	return s.cli.ContainerRemove(ctx, s.id, container.RemoveOptions{
		Force:         true,
		RemoveVolumes: true,
	})
}

type gvisorPTYStream struct {
	reader    *bufio.Reader
	conn      net.Conn
	closeFunc func() error
	closeOnce sync.Once
}

func (p *gvisorPTYStream) Read(b []byte) (int, error) {
	if p.reader != nil {
		return p.reader.Read(b)
	}
	return p.conn.Read(b)
}

func (p *gvisorPTYStream) Write(b []byte) (int, error) {
	return p.conn.Write(b)
}

func (p *gvisorPTYStream) Close() error {
	var err error
	p.closeOnce.Do(func() {
		if p.closeFunc != nil {
			err = p.closeFunc()
		} else if p.conn != nil {
			err = p.conn.Close()
		}
	})
	return err
}
