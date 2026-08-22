package docker

import (
	"context"

	"github.com/docker/docker/client"
)

type Container interface {
	Create(ctx context.Context, name string) (string, error)
	Start(ctx context.Context, id string) error
	Attach(ctx context.Context, id string) (*Hijack, error)
	Close() error
	PullImage() error
	Stop(ctx context.Context, id string) error
}

type docli struct {
	*client.Client
}

func NewClient() Container {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		panic(err)
	}

	dc := docli{
		Client: cli,
	}

	if err := dc.PullImage(); err != nil {
		panic(err)
	}
	return &dc
}
