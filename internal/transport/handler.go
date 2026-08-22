package transport

import (
	"log/slog"
	"net/http"

	"github.com/labib0x9/docpine/internal/session"
	"github.com/labib0x9/docpine/jsonio"
)

type Handler struct {
	mngr *session.Manager
}

func NewHandler(mngr *session.Manager) *Handler {
	return &Handler{mngr: mngr}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.Handle(
		"POST /sessions",
		Cors(Preflight(http.HandlerFunc(h.Create))),
	)
}

func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	id, err := h.mngr.Start(r.Context())
	if err != nil {
		jsonio.SendError(w, "internal server error", http.StatusInternalServerError)
		slog.Error("Create() Handler Failed", "error", err)
		return
	}
	jsonio.SendJson(w, map[string]string{
		"container_id": id,
	}, http.StatusCreated)
}
