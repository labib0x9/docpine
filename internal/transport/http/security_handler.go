package http

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/labib0x9/docpine/internal/app/security"
	domainsec "github.com/labib0x9/docpine/internal/domain/security"
	"github.com/labib0x9/docpine/jsonio"
)

// SecurityHandler serves HTTP endpoints for runtime security findings, event timelines, and container policies.
type SecurityHandler struct {
	engine *security.Engine
}

// NewSecurityHandler constructs a new SecurityHandler.
func NewSecurityHandler(engine *security.Engine) *SecurityHandler {
	return &SecurityHandler{engine: engine}
}

// RegisterRoutes registers security endpoints on the given ServeMux.
func (h *SecurityHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.Handle("GET /containers/{id}/findings", Cors(Preflight(http.HandlerFunc(h.GetFindings))))
	mux.Handle("GET /containers/{id}/timeline", Cors(Preflight(http.HandlerFunc(h.GetTimeline))))
	mux.Handle("POST /containers/{id}/policy", Cors(Preflight(http.HandlerFunc(h.SetPolicy))))
	mux.Handle("GET /containers/{id}/policy", Cors(Preflight(http.HandlerFunc(h.GetPolicy))))
	mux.Handle("GET /security/stats", Cors(Preflight(http.HandlerFunc(h.GetStats))))
	mux.Handle("POST /security/events/simulate", Cors(Preflight(http.HandlerFunc(h.SimulateEvent))))
}

// GetFindings returns all behavioral findings generated for a specific container.
func (h *SecurityHandler) GetFindings(w http.ResponseWriter, r *http.Request) {
	containerID := r.PathValue("id")
	if containerID == "" {
		jsonio.SendError(w, "container id is required", http.StatusBadRequest)
		return
	}

	findings, err := h.engine.GetFindings(r.Context(), containerID)
	if err != nil {
		jsonio.SendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonio.SendJson(w, map[string]any{
		"container_id": containerID,
		"findings":     findings,
		"count":        len(findings),
	}, http.StatusOK)
}

// GetTimeline returns ordered kernel activity events for a specific container.
func (h *SecurityHandler) GetTimeline(w http.ResponseWriter, r *http.Request) {
	containerID := r.PathValue("id")
	if containerID == "" {
		jsonio.SendError(w, "container id is required", http.StatusBadRequest)
		return
	}

	limit := 100
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	timeline, err := h.engine.GetTimeline(r.Context(), containerID, limit)
	if err != nil {
		jsonio.SendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonio.SendJson(w, map[string]any{
		"container_id": containerID,
		"events":       timeline,
		"count":        len(timeline),
	}, http.StatusOK)
}

// SetPolicy updates and compiles in-kernel BPF policies for a container.
func (h *SecurityHandler) SetPolicy(w http.ResponseWriter, r *http.Request) {
	containerID := r.PathValue("id")
	if containerID == "" {
		jsonio.SendError(w, "container id is required", http.StatusBadRequest)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 32*1024))
	if err != nil {
		jsonio.SendError(w, "failed to read body", http.StatusBadRequest)
		return
	}

	var policy domainsec.ContainerPolicy
	if err := json.Unmarshal(body, &policy); err != nil {
		jsonio.SendError(w, "invalid JSON policy format: "+err.Error(), http.StatusBadRequest)
		return
	}
	policy.ContainerID = containerID

	if err := h.engine.SetPolicy(r.Context(), policy); err != nil {
		jsonio.SendError(w, "failed to set policy: "+err.Error(), http.StatusInternalServerError)
		return
	}

	jsonio.SendJson(w, map[string]any{
		"status":       "policy_applied",
		"container_id": containerID,
	}, http.StatusOK)
}

// GetPolicy retrieves the active security policy for a container.
func (h *SecurityHandler) GetPolicy(w http.ResponseWriter, r *http.Request) {
	containerID := r.PathValue("id")
	if containerID == "" {
		jsonio.SendError(w, "container id is required", http.StatusBadRequest)
		return
	}

	policy, err := h.engine.GetPolicy(r.Context(), containerID)
	if err != nil {
		jsonio.SendError(w, "policy not found: "+err.Error(), http.StatusNotFound)
		return
	}

	jsonio.SendJson(w, policy, http.StatusOK)
}

// GetStats returns aggregated security metrics.
func (h *SecurityHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.engine.Stats(r.Context())
	if err != nil {
		jsonio.SendError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonio.SendJson(w, stats, http.StatusOK)
}

// SimulateEvent allows lab testing and attack simulations to inject synthetic kernel events.
func (h *SecurityHandler) SimulateEvent(w http.ResponseWriter, r *http.Request) {
	var event domainsec.EventRecord
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		jsonio.SendError(w, "invalid event record payload: "+err.Error(), http.StatusBadRequest)
		return
	}

	finding, err := h.engine.IngestEvent(r.Context(), event)
	if err != nil {
		jsonio.SendError(w, "ingest error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	jsonio.SendJson(w, map[string]any{
		"status":  "event_ingested",
		"finding": finding,
	}, http.StatusOK)
}
