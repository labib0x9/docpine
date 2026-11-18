package service

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/labib0x9/docpine/internal/config"
	"github.com/labib0x9/docpine/internal/model"
	"github.com/labib0x9/docpine/internal/repository"
)

type AuthService interface {
	Login(ctx context.Context) (string, string, error)
	Callback(ctx context.Context, cookie *http.Cookie, code, state string, sessionTTL time.Duration) (string, error)
	Logout(ctx context.Context, sessionId string) error
	Me(ctx context.Context, userID int64) (*model.User, error)
}

type authService struct {
	cfg      *config.OAuthGithub
	authRepo *repository.AuthRepository
	client   *http.Client
}

func NewAuthService(cfg *config.OAuthGithub, authRepo *repository.AuthRepository) AuthService {
	return &authService{cfg: cfg, authRepo: authRepo, client: &http.Client{Timeout: 10 * time.Second}}
}

func (a *authService) Login(ctx context.Context) (string, string, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return "", "", err
	}
	state := base64.RawURLEncoding.EncodeToString(nonce)
	state += "." + signValue(a.cfg.SessionSecret, []byte(state))

	authorize, err := url.Parse(a.cfg.GithubAuthorizeURL)
	if err != nil {
		return "", "", err
	}
	q := authorize.Query()
	q.Set("client_id", a.cfg.ClientID)
	q.Set("redirect_uri", a.cfg.CallbackURL)
	q.Set("scope", "read:user")
	q.Set("state", state)
	q.Set("allow_signup", "true")
	authorize.RawQuery = q.Encode()
	return state, authorize.String(), nil
}

func (a *authService) Callback(ctx context.Context, cookie *http.Cookie, code, state string, sessionTTL time.Duration) (string, error) {
	if !verifySignedValue(a.cfg.SessionSecret, state) || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(state)) != 1 {
		return "", ErrInvalidAuthState
	}
	token, err := a.exchangeCode(ctx, code, a.cfg.CallbackURL)
	if err != nil {
		log.Printf("github token exchange failed: %v", err)
		return "", ErrFailedToCompleteGitHubLogin
	}
	user, err := a.fetchUser(ctx, token)
	if err != nil {
		log.Printf("github user fetch failed: %v", err)
		return "", ErrFailedToLoadGitHubProfile
	}
	session, err := newSessionToken(a.cfg.SessionSecret, sessionTTL, user)
	if err != nil {
		return "", ErrFailedToCreateSession
	}

	if err := a.authRepo.CreateUser(ctx, model.User{
		GithubID:  user.ID,
		Login:     user.Login,
		AvatarURL: user.AvatarURL,
	}); err != nil {
		log.Printf("failed to persist github user: %v", err)
		return "", ErrFailedToCreateSession
	}

	storedUser, err := a.authRepo.GetUserByGithubId(ctx, user.ID)
	if err != nil {
		log.Printf("failed to load persisted github user: %v", err)
		return "", ErrFailedToCreateSession
	}

	if err := a.authRepo.CreateSession(ctx, model.Session{
		Token:     session,
		UserID:    storedUser.ID,
		ExpiresAt: time.Now().Add(sessionTTL),
	}); err != nil {
		log.Printf("failed to persist session: %v", err)
		return "", ErrFailedToCreateSession
	}

	return session, nil
}

func (a *authService) Logout(ctx context.Context, sessionId string) error {
	return a.authRepo.DeleteSession(ctx, sessionId)
}

func (a *authService) Me(ctx context.Context, userID int64) (*model.User, error) {
	return a.authRepo.GetUserByID(ctx, userID)
}

func signValue(secret []byte, value []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(value)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func verifySignedValue(secret []byte, signed string) bool {
	parts := strings.Split(signed, ".")
	if len(parts) != 2 {
		return false
	}
	expected := signValue(secret, []byte(parts[0]))
	return subtle.ConstantTimeCompare([]byte(expected), []byte(parts[1])) == 1
}

func (a *authService) exchangeCode(ctx context.Context, code, redirectURI string) (string, error) {
	form := url.Values{}
	form.Set("client_id", a.cfg.ClientID)
	form.Set("client_secret", a.cfg.ClientSecret)
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := a.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("token endpoint returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var result struct {
		AccessToken      string `json:"access_token"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	if result.Error != "" {
		return "", fmt.Errorf("%s: %s", result.Error, result.ErrorDescription)
	}
	if result.AccessToken == "" {
		return "", errors.New("empty access token")
	}
	return result.AccessToken, nil
}

func (a *authService) fetchUser(ctx context.Context, token string) (model.GithubUser, error) {
	var user model.GithubUser
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.cfg.UserURL, nil)
	if err != nil {
		return user, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "docpine-oauth")
	resp, err := a.client.Do(req)
	if err != nil {
		return user, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return user, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return user, fmt.Errorf("user endpoint returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	if err := json.Unmarshal(body, &user); err != nil {
		return user, err
	}
	if user.ID == 0 || user.Login == "" {
		return user, errors.New("incomplete GitHub profile")
	}
	return user, nil
}

func newSessionToken(secret []byte, sessionTTL time.Duration, user model.GithubUser) (string, error) {
	claims := model.SessionClaims{GithubUser: user, ExpiresAt: time.Now().Add(sessionTTL).Unix()}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	return encoded + "." + signValue(secret, []byte(encoded)), nil
}
