package service

import "errors"

var (
	ErrInvalidAuthState            = errors.New("invalid auth state")
	ErrFailedToCompleteGitHubLogin = errors.New("failed to complete GitHub login")
	ErrFailedToLoadGitHubProfile   = errors.New("failed to load GitHub profile")
	ErrFailedToCreateSession       = errors.New("could not create session")
)
