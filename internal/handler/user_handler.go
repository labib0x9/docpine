package handler

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/labib0x9/docpine/internal/repository"
)

func (h *AuthHandler) Me(c *gin.Context) {
	userID, ok := CurrentUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	user, err := h.srv.Me(c.Request.Context(), userID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			c.JSON(http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not load user"})
		return
	}
	c.JSON(http.StatusOK, user)
}
