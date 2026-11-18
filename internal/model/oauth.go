package model

type GithubUser struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name,omitempty"`
	AvatarURL string `json:"avatar_url,omitempty"`
}

type SessionClaims struct {
	GithubUser
	ExpiresAt int64 `json:"exp"`
}
