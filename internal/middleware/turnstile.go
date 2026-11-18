package middleware

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/labib0x9/docpine/internal/abuse"
)

func Turnstile(validator *abuse.TurnstileValidator) gin.HandlerFunc {
	return func(c *gin.Context) {
		if validator == nil || !validator.IsEnabled() {
			c.Next()
			return
		}
		token := turnstileToken(c)
		if token == "" {
			c.AbortWithStatusJSON(http.StatusPreconditionRequired, map[string]string{"error": "turnstile token is required"})
			return
		}
		if err := validator.Verify(c.Request.Context(), token, clientIP(c)); err != nil {
			if errors.Is(err, abuse.ErrTurnstileMissing) {
				c.AbortWithStatusJSON(http.StatusPreconditionRequired, map[string]string{"error": "turnstile token is required"})
				return
			}
			c.AbortWithStatusJSON(http.StatusBadRequest, map[string]string{"error": "turnstile verification failed"})
			return
		}
		c.Next()
	}
}

func turnstileToken(c *gin.Context) string {
	if token := c.GetHeader("CF-Turnstile-Response"); token != "" {
		return token
	}
	if token := c.Query("cf-turnstile-response"); token != "" {
		return token
	}
	return c.PostForm("cf-turnstile-response")
}

func clientIP(c *gin.Context) string {
	if forwarded := c.GetHeader("CF-Connecting-IP"); forwarded != "" {
		return strings.TrimSpace(strings.Split(forwarded, ",")[0])
	}
	return c.ClientIP()
}
