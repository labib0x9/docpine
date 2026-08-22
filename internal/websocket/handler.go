package websocket

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
	"github.com/labib0x9/docpine/internal/session"
	"github.com/labib0x9/docpine/jsonio"
)

type Handler struct {
	mngr     *session.Manager
	upgrader websocket.Upgrader
}

func NewHandler(mngr *session.Manager) *Handler {
	return &Handler{
		mngr: mngr,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		},
	}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.Handle(
		"GET /sessions/{id}/attach",
		http.HandlerFunc(h.Attach),
	)
}

// frontend must reutrn with new line for cmd's
func (h *Handler) Attach(w http.ResponseWriter, r *http.Request) {
	sessionId := r.PathValue("id")
	if sessionId == "" {
		jsonio.SendError(w, "must be present it", http.StatusBadRequest)
		return
	}
	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		jsonio.SendError(w, "internal server error", http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	containerId := h.mngr.GetId(sessionId)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	session, err := h.mngr.Attach(ctx, containerId)
	if err != nil {
		slog.Error("attach failed", "error", err)
		return
	}
	defer session.Close()

	// go func(ctx context.Context) {
	// 	io.Copy(session.Conn, conn.NetConn())
	// 	<-ctx.Done()
	// }(ctx)

	// go func(ctx context.Context) {
	// 	// io.Copy(conn.NetConn(), session.Conn)
	// 	io.Copy(os.Stdout, session.Conn)
	// 	<-ctx.Done()
	// }(ctx)

	// <-ctx.Done()

	// if deadline, ok := ctx.Deadline(); ok {
	// 	conn.SetReadDeadline(deadline)
	// } else {
	// 	slog.Error("fetch deadline failed", "error", err)
	// 	return
	// }

	// for {
	// 	_, msg, err := conn.ReadMessage()
	// 	if err != nil {
	// 		break
	// 	}
	// 	fmt.Println("CMD:", string(msg))

	// 	session.Conn.Write(msg)
	// 	resp := make([]byte, 1024)
	// 	n, err := session.Conn.Read(resp)
	// 	if err != nil {
	// 		break
	// 	}

	// 	fmt.Println("CMD OUT", string(resp[:n]))

	// 	if err := conn.WriteMessage(1, resp[:n]); err != nil {
	// 		break
	// 	}
	// }

	errCh := make(chan error, 2)

	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := session.Conn.Read(buf)
			if err != nil {
				errCh <- err
				return
			}

			if err := conn.WriteMessage(1, buf[:n]); err != nil {
				errCh <- err
				return
			}
		}
	}()

	if _, err := session.Conn.Write([]byte("\n")); err != nil {
		errCh <- err
	}

	r.Context().Deadline()

	go func() {
		if deadline, ok := ctx.Deadline(); ok {
			conn.SetReadDeadline(deadline)
		} else {
			slog.Error("fetch deadline failed", "error", err)
			errCh <- err
			return
		}
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				errCh <- err
				return
			}

			_, err = session.Conn.Write(msg)
			if err != nil {
				errCh <- err
				return
			}
		}
	}()

	err = <-errCh
	if err := h.mngr.Stop(r.Context(), containerId); err != nil {
		//
	}
}
