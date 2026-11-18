package repository

import (
	"context"
	"database/sql"
	"errors"

	"github.com/jmoiron/sqlx"
	"github.com/labib0x9/docpine/internal/model"
	"github.com/lib/pq"
)

type LabRepository struct {
	db sqlx.DB
}

func NewLabRepository(db sqlx.DB) *LabRepository {
	return &LabRepository{db: db}
}

func (r *LabRepository) GetLab(ctx context.Context, id int64) (*model.Lab, error) {
	query := `SELECT id, name, tests, created_at, updated_at FROM labs WHERE id = $1`
	var lab model.Lab
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&lab.ID,
		&lab.Name,
		pq.Array(&lab.Tests),
		&lab.CreatedAt,
		&lab.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &lab, nil
}

func (r *LabRepository) ListLabs(ctx context.Context) ([]model.Lab, error) {
	query := `SELECT id, name, tests, created_at, updated_at FROM labs ORDER BY id`
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	labs := make([]model.Lab, 0)
	for rows.Next() {
		var lab model.Lab
		if err := rows.Scan(&lab.ID, &lab.Name, pq.Array(&lab.Tests), &lab.CreatedAt, &lab.UpdatedAt); err != nil {
			return nil, err
		}
		labs = append(labs, lab)
	}
	return labs, rows.Err()
}

func (r *LabRepository) GetUserRepo(ctx context.Context, userID int64) (string, error) {
	var githubRepo string
	err := r.db.GetContext(ctx, &githubRepo, `SELECT github_repo FROM user_repo WHERE user_id = $1`, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", err
	}
	return githubRepo, nil
}

func (r *LabRepository) SetUserRepo(ctx context.Context, userID int64, githubRepo string) error {
	query := `
		INSERT INTO user_repo (user_id, github_repo)
		VALUES ($1, $2)
		ON CONFLICT (user_id) DO UPDATE SET
			github_repo = EXCLUDED.github_repo,
			updated_at = now()
	`
	_, err := r.db.ExecContext(ctx, query, userID, githubRepo)
	return err
}

func (r *LabRepository) CreateRun(ctx context.Context, run model.LabRun) (*model.LabRun, error) {
	query := `
		INSERT INTO lab_run (user_id, lab_id, github_repo, status)
		VALUES ($1, $2, $3, 'queued')
		RETURNING id, status, created_at, updated_at
	`
	err := r.db.QueryRowContext(ctx, query, run.UserID, run.LabID, run.GithubRepo).Scan(
		&run.ID,
		&run.Status,
		&run.CreatedAt,
		&run.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &run, nil
}

func (r *LabRepository) GetRun(ctx context.Context, id int64) (*model.LabRun, error) {
	query := `
		SELECT id, user_id, lab_id, github_repo, status, created_at, updated_at, started_at, finished_at
		FROM lab_run
		WHERE id = $1
	`
	var run model.LabRun
	if err := r.db.GetContext(ctx, &run, query, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &run, nil
}

func (r *LabRepository) ListRuns(ctx context.Context, userID int64) ([]model.LabRun, error) {
	query := `
		SELECT id, user_id, lab_id, github_repo, status, created_at, updated_at, started_at, finished_at
		FROM lab_run
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT 100
	`
	runs := make([]model.LabRun, 0)
	err := r.db.SelectContext(ctx, &runs, query, userID)
	return runs, err
}

func (r *LabRepository) UpdateRunStatus(ctx context.Context, id int64, status string) error {
	query := `
		UPDATE lab_run
		SET status = $1,
			updated_at = now(),
			started_at = CASE WHEN $1 = 'running' AND started_at IS NULL THEN now() ELSE started_at END,
			finished_at = CASE WHEN $1 IN ('passed', 'failed') THEN now() ELSE finished_at END
		WHERE id = $2
	`
	_, err := r.db.ExecContext(ctx, query, status, id)
	return err
}

func (r *LabRepository) SaveResult(ctx context.Context, result model.LabResult) error {
	query := `
		INSERT INTO lab_result (run_id, user_id, github_repo, lab_id, results)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (run_id) DO UPDATE SET results = EXCLUDED.results
	`
	_, err := r.db.ExecContext(ctx, query, result.RunID, result.UserID, result.GithubRepo, result.LabID, result.Results)
	return err
}

func (r *LabRepository) GetResult(ctx context.Context, runID int64) (*model.LabResult, error) {
	query := `
		SELECT id, run_id, user_id, github_repo, lab_id, results, created_at
		FROM lab_result
		WHERE run_id = $1
	`
	var result model.LabResult
	if err := r.db.GetContext(ctx, &result, query, runID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &result, nil
}
