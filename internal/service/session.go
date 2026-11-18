package service

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/labib0x9/docpine/internal/model"
)

var (
	ErrInvalidSession = errors.New("invalid session")
	ErrExpiredSession = errors.New("expired session")
)

func ParseSessionToken(secret []byte, token string) (model.SessionClaims, error) {
	var claims model.SessionClaims
	parts := strings.Split(token, ".")
	if len(parts) != 2 || !verifySignedValue(secret, token) {
		return claims, ErrInvalidSession
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return claims, ErrInvalidSession
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return claims, ErrInvalidSession
	}
	if claims.ExpiresAt <= time.Now().Unix() {
		return claims, ErrExpiredSession
	}
	if claims.ID == 0 || claims.Login == "" {
		return claims, ErrInvalidSession
	}
	return claims, nil
}
