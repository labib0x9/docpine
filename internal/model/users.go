package model

import "time"

type User struct {
	ID        int64     `db:"id" json:"id"`
	GithubID  int64     `db:"github_id" json:"github_id"`
	Login     string    `db:"login" json:"login"`
	AvatarURL string    `db:"avatar_url" json:"avatar_url"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
}

type Session struct {
	Token     string    `db:"-" json:"-"`
	TokenHash []byte    `db:"token_hash" json:"-"`
	UserID    int64     `db:"user_id" json:"user_id"`
	UserAgent string    `db:"user_agent" json:"user_agent"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
	ExpiresAt time.Time `db:"expires_at" json:"expires_at"`
}
