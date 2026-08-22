package jsonio

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/gorilla/websocket"
)

func SendJson(w http.ResponseWriter, v any, statusCode int) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	if err := encoder.Encode(v); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	buf.WriteTo(w)
}

func SendError(w http.ResponseWriter, v string, statusCode int) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	if err := encoder.Encode(map[string]any{
		"error": v,
		"code":  statusCode,
	}); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	buf.WriteTo(w)
}

// websocket error json
func SendErrorW(w *websocket.Conn, v string) {

}
