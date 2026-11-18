package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/labib0x9/docpine/internal/repository"
	"github.com/labib0x9/docpine/internal/service"
)

const userIDKey = "docpine_user_id"

func RequireAuth(secret []byte, authRepo *repository.AuthRepository) gin.HandlerFunc {
	return func(c *gin.Context) {
		cookie, err := c.Request.Cookie(sessionCookieName)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		claims, err := service.ParseSessionToken(secret, cookie.Value)
		if err != nil || authRepo == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		user, err := authRepo.GetUserByGithubId(c.Request.Context(), claims.ID)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		c.Set(userIDKey, user.ID)
		c.Next()
	}
}

func CurrentUserID(c *gin.Context) (int64, bool) {
	value, ok := c.Get(userIDKey)
	if !ok {
		return 0, false
	}
	id, ok := value.(int64)
	return id, ok
}
