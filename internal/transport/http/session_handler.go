package http

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"

	"github.com/labib0x9/docpine/internal/abuse"
	"github.com/labib0x9/docpine/internal/session"
	"github.com/labib0x9/docpine/jsonio"
)

// SessionHandler serves HTTP REST endpoints for sandbox sessions and challenges.
type SessionHandler struct {
	mngr  *session.Manager
	guard *abuse.Guard
}

// NewSessionHandler constructs a new SessionHandler.
func NewSessionHandler(mngr *session.Manager, guard *abuse.Guard) *SessionHandler {
	return &SessionHandler{
		mngr:  mngr,
		guard: guard,
	}
}

// RegisterRoutes registers HTTP routes on the serve mux.
func (h *SessionHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.Handle(
		"POST /sessions",
		Cors(Preflight(http.HandlerFunc(h.Create))),
	)
	mux.Handle(
		"GET /challenges/pow",
		Cors(Preflight(http.HandlerFunc(h.GetPoWChallenge))),
	)
	mux.Handle(
		"GET /healthz",
		Cors(Preflight(http.HandlerFunc(h.Health))),
	)
}

// Create handles anonymous sandbox creation protected by the multi-layered abuse guard.
func (h *SessionHandler) Create(w http.ResponseWriter, r *http.Request) {
	var payload *abuse.CreateRequestPayload

	if r.Body != nil {
		bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 16*1024))
		if err == nil && len(bodyBytes) > 0 {
			var p abuse.CreateRequestPayload
			if err := json.Unmarshal(bodyBytes, &p); err == nil {
				payload = &p
			}
		}
	}

	// 1. Abuse Protection Gate
	passed, releaseSlot := h.guard.CheckAnonymousCreate(w, r, payload)
	if !passed {
		return
	}

	// 2. Provision Ephemeral Sandbox
	sessionID, err := h.mngr.Create(r.Context())
	if err != nil {
		releaseSlot()
		slog.Error("Session creation failed", "error", err)
		jsonio.SendError(w, "internal server error provisioning sandbox", http.StatusInternalServerError)
		return
	}

	_ = releaseSlot // Held for lifetime of session

	jsonio.SendJson(w, map[string]any{
		"session_id":     sessionID,
		"expires_in_sec": 300,
	}, http.StatusCreated)
}

// GetPoWChallenge returns a fresh signed Proof-of-Work challenge for client pre-computation.
func (h *SessionHandler) GetPoWChallenge(w http.ResponseWriter, r *http.Request) {
	chal := h.guard.IssuePoWChallenge()
	jsonio.SendJson(w, chal, http.StatusOK)
}

// Health reports service status and active session count.
func (h *SessionHandler) Health(w http.ResponseWriter, r *http.Request) {
	jsonio.SendJson(w, map[string]any{
		"status":          "ok",
		"active_sessions": h.mngr.ActiveCount(),
	}, http.StatusOK)
}
