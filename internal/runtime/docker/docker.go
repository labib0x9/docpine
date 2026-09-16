package docker

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	"github.com/labib0x9/docpine/internal/config"
	"github.com/labib0x9/docpine/internal/runtime"
)

func init() {
	runtime.Register("docker", func(ctx context.Context, cfg config.Runtime) (runtime.Runtime, error) {
		return New(ctx, cfg)
	})
}

// DockerRuntime implements runtime.Runtime using the standard Docker Engine API.
type DockerRuntime struct {
	cli        *client.Client
	cfg        config.Runtime
	defaultImg string
}

// New creates a new Docker runtime instance.
func New(ctx context.Context, cfg config.Runtime) (*DockerRuntime, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create docker client: %w", err)
	}

	img := cfg.Image
	if img == "" {
		img = "alpine:3.20"
	}

	return &DockerRuntime{
		cli:        cli,
		cfg:        cfg,
		defaultImg: img,
	}, nil
}

// Name returns the backend identifier.
func (r *DockerRuntime) Name() string {
	return "docker"
}

// CheckPrerequisites verifies that the Docker daemon is reachable and responding.
func (r *DockerRuntime) CheckPrerequisites(ctx context.Context) error {
	pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	_, err := r.cli.Ping(pingCtx)
	if err != nil {
		return fmt.Errorf("%w: docker daemon unreachable (%v)", runtime.ErrPrerequisiteFailed, err)
	}
	return nil
}

// ensureImage pulls the image if it is not already available locally.
func (r *DockerRuntime) ensureImage(ctx context.Context, imgName string) error {
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

// CreateSandbox provisions and starts a new Docker container configured for interactive PTY shell.
func (r *DockerRuntime) CreateSandbox(ctx context.Context, opts runtime.SandboxOptions) (runtime.Sandbox, error) {
	img := opts.Image
	if img == "" {
		img = r.defaultImg
	}

	if err := r.ensureImage(ctx, img); err != nil {
		return nil, fmt.Errorf("ensure image failed: %w", err)
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
		containerName = fmt.Sprintf("docpine-%s", opts.SessionID)
	}

	resp, err := r.cli.ContainerCreate(ctx, containerConfig, hostConfig, nil, nil, containerName)
	if err != nil {
		return nil, fmt.Errorf("docker container create failed: %w", err)
	}

	if err := r.cli.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		// Attempt cleanup on failed start
		_ = r.cli.ContainerRemove(context.Background(), resp.ID, container.RemoveOptions{Force: true})
		return nil, fmt.Errorf("docker container start failed: %w", err)
	}

	return &dockerSandbox{
		id:  resp.ID,
		cli: r.cli,
	}, nil
}

// Close closes the Docker client.
func (r *DockerRuntime) Close() error {
	return r.cli.Close()
}

// dockerSandbox represents an active Docker container sandbox.
type dockerSandbox struct {
	id        string
	cli       *client.Client
	destroyMu sync.Mutex
	destroyed bool
}

// ID returns the Docker container ID.
func (s *dockerSandbox) ID() string {
	return s.id
}

// CgroupID returns the 64-bit cgroup ID or init PID for container identity.
func (s *dockerSandbox) CgroupID() (uint64, error) {
	s.destroyMu.Lock()
	if s.destroyed {
		s.destroyMu.Unlock()
		return 0, runtime.ErrSandboxDestroyed
	}
	s.destroyMu.Unlock()

	inspect, err := s.cli.ContainerInspect(context.Background(), s.id)
	if err != nil {
		return 0, fmt.Errorf("failed to inspect container for cgroup: %w", err)
	}

	if inspect.State == nil || inspect.State.Pid == 0 {
		return 0, fmt.Errorf("container init process is not running")
	}

	return uint64(inspect.State.Pid), nil
}

// AttachPTY opens a hijacked bidirectional stream to the container's TTY.
func (s *dockerSandbox) AttachPTY(ctx context.Context) (io.ReadWriteCloser, error) {
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
		return nil, fmt.Errorf("container attach failed: %w", err)
	}

	return &ptyStream{
		reader: hijack.Reader,
		conn:   hijack.Conn,
		closeFunc: func() error {
			hijack.Close()
			return nil
		},
	}, nil
}

// Destroy stops and forcefully removes the container.
func (s *dockerSandbox) Destroy(ctx context.Context) error {
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

// ptyStream wraps hijacked reader/conn into an io.ReadWriteCloser.
type ptyStream struct {
	reader    *bufio.Reader
	conn      net.Conn
	closeFunc func() error
	closeOnce sync.Once
}

func (p *ptyStream) Read(b []byte) (int, error) {
	if p.reader != nil {
		return p.reader.Read(b)
	}
	return p.conn.Read(b)
}

func (p *ptyStream) Write(b []byte) (int, error) {
	return p.conn.Write(b)
}

func (p *ptyStream) Close() error {
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
