package handler

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/labib0x9/docpine/internal/service"
)

const (
	stateCookieName   = "oauth_state"
	sessionCookieName = "session"
	stateTTL          = 10 * time.Minute
	sessionTTL        = 7 * 24 * time.Hour
)

type AuthHandler struct {
	srv           service.AuthService
	secureCookies bool
}

func NewAuthHandler(srv service.AuthService, secure ...bool) *AuthHandler {
	secureCookies := len(secure) > 0 && secure[0]
	return &AuthHandler{srv: srv, secureCookies: secureCookies}
}

func (h *AuthHandler) Login(c *gin.Context) {
	state, authorizeURL, err := h.srv.Login(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not start login"})
		return
	}
	c.SetCookieData(h.cookie(stateCookieName, state, int(stateTTL.Seconds())))
	c.Redirect(http.StatusFound, authorizeURL)
}

func (h *AuthHandler) Callback(c *gin.Context) {
	if providerError, ok := c.GetQuery("error"); ok {
		c.JSON(http.StatusBadRequest, map[string]string{"error": providerError})
		return
	}
	code, state := c.Query("code"), c.Query("state")
	if code == "" || state == "" {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "missing code or state"})
		return
	}
	cookie, err := c.Request.Cookie(stateCookieName)
	h.clearCookie(c, stateCookieName)
	if err != nil {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid oauth state"})
		return
	}

	session, err := h.srv.Callback(c.Request.Context(), cookie, code, state, sessionTTL)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidAuthState),
			errors.Is(err, service.ErrFailedToCompleteGitHubLogin),
			errors.Is(err, service.ErrFailedToLoadGitHubProfile):
			c.JSON(http.StatusBadGateway, map[string]string{"error": err.Error()})
		default:
			c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return
	}

	c.SetCookieData(h.cookie(sessionCookieName, session, int(sessionTTL.Seconds())))
	c.Redirect(http.StatusSeeOther, "/")
}

func (h *AuthHandler) Logout(c *gin.Context) {
	cookie, err := c.Request.Cookie(sessionCookieName)
	h.clearCookie(c, sessionCookieName)
	h.clearCookie(c, stateCookieName)
	if err != nil {
		c.AbortWithStatus(http.StatusNoContent)
		return
	}
	if err := h.srv.Logout(c.Request.Context(), cookie.Value); err != nil {
		c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not logout"})
		return
	}
	c.AbortWithStatus(http.StatusNoContent)
}

func (h *AuthHandler) cookie(name, value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   h.secureCookies,
		SameSite: http.SameSiteLaxMode,
	}
}

func (h *AuthHandler) clearCookie(c *gin.Context, name string) {
	cookie := h.cookie(name, "", -1)
	cookie.Expires = time.Unix(1, 0)
	c.SetCookieData(cookie)
}
