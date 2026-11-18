package service

import (
	"context"
	"errors"

	"github.com/labib0x9/docpine/internal/model"
	"github.com/labib0x9/docpine/internal/repository"
	"github.com/labib0x9/docpine/internal/utils"
)

var ErrInvalidGithubRepo = errors.New("invalid github repo")

type Publisher interface {
	Publish(ctx context.Context, runID int64) error
}

type LabService interface {
	ListLabs(ctx context.Context) ([]model.Lab, error)
	GetRepo(ctx context.Context, userID int64) (string, error)
	SetRepo(ctx context.Context, userID int64, rawRepo string) (string, error)
	CreateRun(ctx context.Context, userID, labID int64, rawRepo string) (*model.LabRun, error)
	GetRun(ctx context.Context, userID, runID int64) (*model.LabRun, error)
	ListRuns(ctx context.Context, userID int64) ([]model.LabRun, error)
	GetResult(ctx context.Context, userID, runID int64) (*model.LabResult, error)
}

type labService struct {
	repo      *repository.LabRepository
	publisher Publisher
}

func NewLabService(repo *repository.LabRepository, publisher Publisher) LabService {
	return &labService{repo: repo, publisher: publisher}
}

func (s *labService) ListLabs(ctx context.Context) ([]model.Lab, error) {
	return s.repo.ListLabs(ctx)
}

func (s *labService) GetRepo(ctx context.Context, userID int64) (string, error) {
	repo, err := s.repo.GetUserRepo(ctx, userID)
	if errors.Is(err, repository.ErrNotFound) {
		return "", nil
	}
	return repo, err
}

func (s *labService) SetRepo(ctx context.Context, userID int64, rawRepo string) (string, error) {
	repo, ok := utils.NormalizeGithubRepo(rawRepo)
	if !ok {
		return "", ErrInvalidGithubRepo
	}
	return repo, s.repo.SetUserRepo(ctx, userID, repo)
}

func (s *labService) CreateRun(ctx context.Context, userID, labID int64, rawRepo string) (*model.LabRun, error) {
	repo, ok := utils.NormalizeGithubRepo(rawRepo)
	if !ok {
		return nil, ErrInvalidGithubRepo
	}
	if _, err := s.repo.GetLab(ctx, labID); err != nil {
		return nil, err
	}
	if err := s.repo.SetUserRepo(ctx, userID, repo); err != nil {
		return nil, err
	}
	run, err := s.repo.CreateRun(ctx, model.LabRun{UserID: userID, LabID: labID, GithubRepo: repo})
	if err != nil {
		return nil, err
	}
	if err := s.publisher.Publish(ctx, run.ID); err != nil {
		_ = s.repo.UpdateRunStatus(ctx, run.ID, "failed")
		return nil, err
	}
	return run, nil
}

func (s *labService) GetRun(ctx context.Context, userID, runID int64) (*model.LabRun, error) {
	run, err := s.repo.GetRun(ctx, runID)
	if err != nil {
		return nil, err
	}
	if run.UserID != userID {
		return nil, repository.ErrNotFound
	}
	return run, nil
}

func (s *labService) ListRuns(ctx context.Context, userID int64) ([]model.LabRun, error) {
	return s.repo.ListRuns(ctx, userID)
}

func (s *labService) GetResult(ctx context.Context, userID, runID int64) (*model.LabResult, error) {
	result, err := s.repo.GetResult(ctx, runID)
	if err != nil {
		return nil, err
	}
	if result.UserID != userID {
		return nil, repository.ErrNotFound
	}
	return result, nil
}
