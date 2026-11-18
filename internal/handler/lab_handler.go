package handler

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/labib0x9/docpine/internal/repository"
	"github.com/labib0x9/docpine/internal/service"
	"github.com/labib0x9/docpine/internal/sse"
)

type LabHandler struct {
	srv service.LabService
	hub *sse.Hub
}

func NewLabHandler(srv service.LabService, hub *sse.Hub) *LabHandler {
	return &LabHandler{srv: srv, hub: hub}
}

func (h *LabHandler) ListLabs(c *gin.Context) {
	labs, err := h.srv.ListLabs(c.Request.Context())
	if err != nil {
		writeLabError(c, err)
		return
	}
	c.JSON(http.StatusOK, labs)
}

func (h *LabHandler) GetRepo(c *gin.Context) {
	userID, ok := currentUser(c)
	if !ok {
		return
	}
	repo, err := h.srv.GetRepo(c.Request.Context(), userID)
	if err != nil {
		writeLabError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]string{"github_repo": repo})
}

func (h *LabHandler) SetRepo(c *gin.Context) {
	userID, ok := currentUser(c)
	if !ok {
		return
	}
	var request struct {
		GithubRepo string `json:"github_repo"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	repo, err := h.srv.SetRepo(c.Request.Context(), userID, request.GithubRepo)
	if err != nil {
		writeLabError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]string{"github_repo": repo})
}

func (h *LabHandler) CreateRun(c *gin.Context) {
	userID, ok := currentUser(c)
	if !ok {
		return
	}
	labID, ok := pathID(c, "id")
	if !ok {
		return
	}
	var request struct {
		GithubRepo string `json:"github_repo"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	run, err := h.srv.CreateRun(c.Request.Context(), userID, labID, request.GithubRepo)
	if err != nil {
		writeLabError(c, err)
		return
	}
	c.JSON(http.StatusAccepted, run)
}

func (h *LabHandler) ListRuns(c *gin.Context) {
	userID, ok := currentUser(c)
	if !ok {
		return
	}
	runs, err := h.srv.ListRuns(c.Request.Context(), userID)
	if err != nil {
		writeLabError(c, err)
		return
	}
	c.JSON(http.StatusOK, runs)
}

func (h *LabHandler) GetRun(c *gin.Context) {
	userID, ok := currentUser(c)
	if !ok {
		return
	}
	runID, ok := pathID(c, "runID")
	if !ok {
		return
	}
	run, err := h.srv.GetRun(c.Request.Context(), userID, runID)
	if err != nil {
		writeLabError(c, err)
		return
	}
	c.JSON(http.StatusOK, run)
}

func (h *LabHandler) GetResult(c *gin.Context) {
	userID, ok := currentUser(c)
	if !ok {
		return
	}
	runID, ok := pathID(c, "runID")
	if !ok {
		return
	}
	result, err := h.srv.GetResult(c.Request.Context(), userID, runID)
	if err != nil {
		writeLabError(c, err)
		return
	}
	c.JSON(http.StatusOK, result)
}

func (h *LabHandler) Events(c *gin.Context) {
	userID, ok := currentUser(c)
	if !ok {
		return
	}
	runID, ok := pathID(c, "runID")
	if !ok {
		return
	}
	events, unsubscribe := h.hub.Subscribe(runID)
	defer unsubscribe()

	run, err := h.srv.GetRun(c.Request.Context(), userID, runID)
	if err != nil {
		writeLabError(c, err)
		return
	}
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")

	if len(h.hub.History(runID)) == 0 {
		c.SSEvent("status", run.Status)
		c.Writer.Flush()
		if result, err := h.srv.GetResult(c.Request.Context(), userID, runID); err == nil {
			c.SSEvent("result", result.Results)
			c.Writer.Flush()
			if run.Status == "passed" || run.Status == "failed" {
				return
			}
		}
	}

	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case event, open := <-events:
			if !open || event.Type == "shutdown" {
				return
			}
			c.SSEvent(event.Type, event.Data)
			c.Writer.Flush()
		case <-ticker.C:
			c.SSEvent("ping", "keepalive")
			c.Writer.Flush()
		case <-c.Request.Context().Done():
			return
		}
	}
}

func currentUser(c *gin.Context) (int64, bool) {
	userID, ok := CurrentUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	return userID, ok
}

func pathID(c *gin.Context, name string) (int64, bool) {
	id, err := strconv.ParseInt(c.Param(name), 10, 64)
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return 0, false
	}
	return id, true
}

func writeLabError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, repository.ErrNotFound):
		c.JSON(http.StatusNotFound, map[string]string{"error": "not found"})
	case errors.Is(err, service.ErrInvalidGithubRepo):
		c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	default:
		c.JSON(http.StatusInternalServerError, map[string]string{"error": "internal error"})
	}
}
