package worker

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/labib0x9/docpine/internal/config"
	"github.com/labib0x9/docpine/internal/model"
	"github.com/labib0x9/docpine/internal/queue"
	"github.com/labib0x9/docpine/internal/repository"
	"github.com/labib0x9/docpine/internal/runner"
	"github.com/labib0x9/docpine/internal/utils"
)

type Runner interface {
	Run(ctx context.Context, opts runner.Options, onOutput func(string)) (int, error)
}

type EventPublisher interface {
	PublishEvent(ctx context.Context, event queue.LabEvent) error
}

type Worker struct {
	repo      *repository.LabRepository
	events    EventPublisher
	runner    Runner
	image     string
	timeout   time.Duration
	memory    int64
	cpuShares int64
}

func New(repo *repository.LabRepository, events EventPublisher, testRunner Runner, cfg *config.Lab) *Worker {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	return &Worker{
		repo:      repo,
		events:    events,
		runner:    testRunner,
		image:     cfg.Image,
		timeout:   timeout,
		memory:    cfg.MemoryLimit,
		cpuShares: cfg.CPUShares,
	}
}

func (w *Worker) Process(ctx context.Context, runID int64) error {
	run, err := w.repo.GetRun(ctx, runID)
	if err != nil {
		return err
	}
	if run.Status == "passed" || run.Status == "failed" {
		return nil
	}
	lab, err := w.repo.GetLab(ctx, run.LabID)
	if err != nil {
		return err
	}
	if err := w.repo.UpdateRunStatus(ctx, run.ID, "running"); err != nil {
		return err
	}
	w.emit(ctx, run.ID, "status", "running")

	runCtx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()

	dir, err := os.MkdirTemp("", "docpine-lab-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	if err := cloneRepo(runCtx, run.GithubRepo, dir); err != nil {
		return w.complete(ctx, run, "failed", fmt.Sprintf("clone failed: %v\n", err))
	}

	var output strings.Builder
	status := "passed"
	for index, test := range lab.Tests {
		if strings.TrimSpace(test) == "" {
			continue
		}
		message := fmt.Sprintf("> test %d: %s\n", index+1, test)
		output.WriteString(message)
		w.emit(ctx, run.ID, "output", message)

		code, err := w.runner.Run(runCtx, runner.Options{
			Image:       w.image,
			Command:     []string{"/bin/sh", "-c", test},
			WorkDir:     runner.WorkspaceDir,
			CopyDir:     dir,
			Memory:      w.memory,
			CPUShares:   w.cpuShares,
			NetworkMode: "none",
		}, func(chunk string) {
			output.WriteString(chunk)
			w.emit(ctx, run.ID, "output", chunk)
		})
		if err != nil {
			return w.complete(ctx, run, "failed", fmt.Sprintf("test %d failed to run: %v\n", index+1, err))
		}
		if code != 0 {
			message = fmt.Sprintf("test %d exited with code %d\n", index+1, code)
			output.WriteString(message)
			w.emit(ctx, run.ID, "output", message)
			status = "failed"
			break
		}
	}

	return w.complete(ctx, run, status, output.String())
}

func (w *Worker) complete(ctx context.Context, run *model.LabRun, status, output string) error {
	result := model.LabResult{
		RunID:      run.ID,
		UserID:     run.UserID,
		GithubRepo: run.GithubRepo,
		LabID:      run.LabID,
		Results:    output,
	}
	if err := w.repo.SaveResult(ctx, result); err != nil {
		return err
	}
	if err := w.repo.UpdateRunStatus(ctx, run.ID, status); err != nil {
		return err
	}
	eventType := "result"
	if status == "failed" {
		eventType = "error"
	}
	w.emit(ctx, run.ID, eventType, output)
	return nil
}

func (w *Worker) emit(ctx context.Context, runID int64, eventType, data string) {
	if w.events == nil {
		return
	}
	if err := w.events.PublishEvent(ctx, queue.LabEvent{RunID: runID, Type: eventType, Data: data}); err != nil {
		slog.Warn("publish lab event failed", "run_id", runID, "event", eventType, "error", err)
	}
}

func cloneRepo(ctx context.Context, rawRepo, dest string) error {
	repoURL, ok := utils.NormalizeGithubRepo(rawRepo)
	if !ok {
		return fmt.Errorf("invalid github repo %q", rawRepo)
	}
	cmd := exec.CommandContext(ctx, "git", "clone", "--depth", "1", repoURL, dest)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w", strings.TrimSpace(string(output)), err)
	}
	return nil
}
