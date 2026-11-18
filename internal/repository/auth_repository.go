package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"

	"github.com/jmoiron/sqlx"
	"github.com/labib0x9/docpine/internal/model"
)

var ErrNotFound = errors.New("record not found")

type AuthRepository struct {
	db sqlx.DB
}

func NewAuthRepository(db sqlx.DB) *AuthRepository {
	return &AuthRepository{db: db}
}

func (a *AuthRepository) CreateUser(ctx context.Context, user model.User) error {
	query := `
		INSERT INTO users (github_id, login, avatar_url)
		VALUES ($1, $2, $3)
		ON CONFLICT (github_id) DO UPDATE SET
			login = EXCLUDED.login,
			avatar_url = EXCLUDED.avatar_url,
			updated_at = now()
	`
	_, err := a.db.ExecContext(ctx, query, user.GithubID, user.Login, user.AvatarURL)
	return err
}

func (a *AuthRepository) GetUserByGithubId(ctx context.Context, githubID int64) (*model.User, error) {
	query := `
		SELECT id, github_id, login, avatar_url, created_at, updated_at
		FROM users
		WHERE github_id = $1
	`
	var user model.User
	if err := a.db.GetContext(ctx, &user, query, githubID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &user, nil
}

func (a *AuthRepository) GetUserByID(ctx context.Context, id int64) (*model.User, error) {
	query := `
		SELECT id, github_id, login, avatar_url, created_at, updated_at
		FROM users
		WHERE id = $1
	`
	var user model.User
	if err := a.db.GetContext(ctx, &user, query, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &user, nil
}

func (a *AuthRepository) DeleteUser(ctx context.Context, id int64) error {
	_, err := a.db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, id)
	return err
}

func (a *AuthRepository) UpdateUser(ctx context.Context, user model.User) error {
	query := `
		UPDATE users
		SET login = $1, avatar_url = $2, updated_at = now()
		WHERE id = $3
	`
	_, err := a.db.ExecContext(ctx, query, user.Login, user.AvatarURL, user.ID)
	return err
}

func (a *AuthRepository) CreateSession(ctx context.Context, session model.Session) error {
	query := `
		INSERT INTO sessions (token_hash, user_id, user_agent, expires_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT DO NOTHING
	`
	_, err := a.db.ExecContext(ctx, query, sessionHash(session), session.UserID, session.UserAgent, session.ExpiresAt)
	return err
}

func (a *AuthRepository) GetSessionById(ctx context.Context, sessionID string) (*model.Session, error) {
	query := `
		SELECT token_hash, user_id, user_agent, created_at, expires_at
		FROM sessions
		WHERE token_hash = $1
	`
	var session model.Session
	if err := a.db.GetContext(ctx, &session, query, hashToken(sessionID)); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &session, nil
}

func (a *AuthRepository) DeleteSession(ctx context.Context, sessionID string) error {
	_, err := a.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = $1`, hashToken(sessionID))
	return err
}

func (a *AuthRepository) UpdateSession(ctx context.Context, session model.Session) error {
	query := `
		UPDATE sessions
		SET user_id = $1, user_agent = $2, expires_at = $3
		WHERE token_hash = $4
	`
	_, err := a.db.ExecContext(ctx, query, session.UserID, session.UserAgent, session.ExpiresAt, sessionHash(session))
	return err
}

func hashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

func sessionHash(session model.Session) []byte {
	if len(session.TokenHash) > 0 {
		return session.TokenHash
	}
	return hashToken(session.Token)
}
