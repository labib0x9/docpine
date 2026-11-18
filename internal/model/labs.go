package model

import "time"

type Lab struct {
	ID        int64     `db:"id" json:"id"`
	Name      string    `db:"name" json:"name"`
	Tests     []string  `db:"tests" json:"tests"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
}

type UserRepo struct {
	UserID     int64     `db:"user_id" json:"user_id"`
	GithubRepo string    `db:"github_repo" json:"github_repo"`
	UpdatedAt  time.Time `db:"updated_at" json:"updated_at"`
}

type LabRun struct {
	ID         int64      `db:"id" json:"id"`
	UserID     int64      `db:"user_id" json:"user_id"`
	LabID      int64      `db:"lab_id" json:"lab_id"`
	GithubRepo string     `db:"github_repo" json:"github_repo"`
	Status     string     `db:"status" json:"status"`
	CreatedAt  time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt  time.Time  `db:"updated_at" json:"updated_at"`
	StartedAt  *time.Time `db:"started_at" json:"started_at,omitempty"`
	FinishedAt *time.Time `db:"finished_at" json:"finished_at,omitempty"`
}

type LabResult struct {
	ID         int64     `db:"id" json:"id"`
	RunID      int64     `db:"run_id" json:"run_id"`
	UserID     int64     `db:"user_id" json:"user_id"`
	GithubRepo string    `db:"github_repo" json:"github_repo"`
	LabID      int64     `db:"lab_id" json:"lab_id"`
	Results    string    `db:"results" json:"results"`
	CreatedAt  time.Time `db:"created_at" json:"created_at"`
}
