package runner

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
)

const WorkspaceDir = "/tmp/workspace"

type Options struct {
	Image       string
	Command     []string
	WorkDir     string
	CopyDir     string
	Memory      int64
	CPUShares   int64
	NetworkMode string
}

type Runner struct {
	cli *client.Client
}

func New() (*Runner, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, err
	}
	return &Runner{cli: cli}, nil
}

func (r *Runner) Run(ctx context.Context, opts Options, onOutput func(string)) (int, error) {
	imageRef := opts.Image
	if imageRef == "" {
		imageRef = "alpine:3.20"
	}
	command := opts.Command
	if len(command) == 0 {
		command = []string{"/bin/sh"}
	}
	workDir := opts.WorkDir
	if workDir == "" {
		workDir = WorkspaceDir
	}
	if err := r.ensureImage(ctx, imageRef); err != nil {
		return 0, fmt.Errorf("prepare image: %w", err)
	}

	created, err := r.cli.ContainerCreate(ctx, &container.Config{
		Image:        imageRef,
		Cmd:          command,
		WorkingDir:   workDir,
		Tty:          true,
		AttachStdout: true,
		AttachStderr: true,
	}, &container.HostConfig{
		NetworkMode: container.NetworkMode(opts.NetworkMode),
		Resources: container.Resources{
			Memory:    opts.Memory,
			CPUShares: opts.CPUShares,
		},
	}, nil, nil, "")
	if err != nil {
		return 0, err
	}
	id := created.ID
	defer func() {
		_ = r.cli.ContainerRemove(context.Background(), id, container.RemoveOptions{Force: true, RemoveVolumes: true})
	}()

	if opts.CopyDir != "" {
		archive, err := tarDirectory(opts.CopyDir)
		if err != nil {
			return 0, fmt.Errorf("archive workspace: %w", err)
		}
		if err := r.cli.CopyToContainer(ctx, id, WorkspaceDir, archive, container.CopyToContainerOptions{}); err != nil {
			return 0, fmt.Errorf("copy workspace: %w", err)
		}
	}

	stream, err := r.cli.ContainerAttach(ctx, id, container.AttachOptions{Stream: true, Stdout: true, Stderr: true})
	if err != nil {
		return 0, err
	}
	defer stream.Close()

	if err := r.cli.ContainerStart(ctx, id, container.StartOptions{}); err != nil {
		return 0, err
	}

	statusCh, errCh := r.cli.ContainerWait(ctx, id, container.WaitConditionNotRunning)
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		buf := make([]byte, 4096)
		for {
			n, readErr := stream.Reader.Read(buf)
			if n > 0 && onOutput != nil {
				onOutput(string(buf[:n]))
			}
			if readErr != nil {
				return
			}
		}
	}()

	select {
	case err := <-errCh:
		if err != nil {
			return 0, err
		}
		<-readDone
	case status := <-statusCh:
		<-readDone
		return int(status.StatusCode), nil
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	return 0, nil
}

func (r *Runner) ensureImage(ctx context.Context, ref string) error {
	if _, _, err := r.cli.ImageInspectWithRaw(ctx, ref); err == nil {
		return nil
	}
	reader, err := r.cli.ImagePull(ctx, ref, image.PullOptions{})
	if err != nil {
		return err
	}
	defer reader.Close()
	_, err = io.Copy(io.Discard, reader)
	return err
}

func tarDirectory(root string) (io.Reader, error) {
	var buf bytes.Buffer
	writer := tar.NewWriter(&buf)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() && !info.IsDir() {
			return nil
		}
		name := filepath.ToSlash(rel)
		if info.IsDir() {
			name += "/"
		}
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = name
		if err := writer.WriteHeader(header); err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		_, err = io.Copy(writer, file)
		return err
	})
	if err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return bytes.NewReader(buf.Bytes()), nil
}

func (r *Runner) Close() error {
	return r.cli.Close()
}
