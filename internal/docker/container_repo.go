package docker

import (
	"context"
	"io"
	"os"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
)

var imageN = "alpine:3.20"

type Hijack struct {
	types.HijackedResponse
}

func (h *Hijack) Close() error {
	return h.Close()
}

func (d *docli) PullImage() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := d.ImageInspect(ctx, imageN)
	if err != nil {
		if strings.Contains(err.Error(), "No such image:") {
			reader, err := d.ImagePull(context.Background(), imageN, image.PullOptions{})
			if err != nil {
				return nil
			}
			io.Copy(os.Stdout, reader)
			reader.Close()
		} else {
			return err
		}
	}
	return nil
}

// ctx is needed...
// name = container name
func (d *docli) Create(ctx context.Context, name string) (string, error) {
	resp, err := d.ContainerCreate(ctx,
		&container.Config{
			Image:        imageN,
			Cmd:          []string{"/bin/sh"},
			AttachStdin:  true,
			AttachStdout: true,
			AttachStderr: true,
			Tty:          true,
			OpenStdin:    true,
		},
		nil, nil, nil, name,
	)
	if err != nil {
		return "", err
	}
	return resp.ID, nil
}

// id = container id
func (d *docli) Attach(ctx context.Context, id string) (*Hijack, error) {
	hijack, err := d.ContainerAttach(ctx, id, container.AttachOptions{
		Stream: true,
		Stdin:  true,
		Stdout: true,
		Stderr: true,
	})
	if err != nil {
		return nil, err
	}
	return &Hijack{hijack}, nil
}

// ctx is needed
// id = container id
func (d *docli) Start(ctx context.Context, id string) error {
	return d.ContainerStart(ctx, id, container.StartOptions{})
}

// func (d *docli) ContainerWait() error {

// }

// func (d *docli) ContainerStop() error {

// }

// func (d *docli) ContainerRemove() error {

// }
