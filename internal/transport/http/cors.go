package http

import "net/http"

// Cors provides cross-origin resource sharing headers for web terminals.
func Cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		allowedOrigins := map[string]bool{
			"http://localhost:5173":  true,
			"http://127.0.0.1:5173":  true,
			"http://localhost:5173/": true,
			"http://127.0.0.1:5173/": true,
			"http://127.0.0.1:8080":  true,
		}
		if allowedOrigins[origin] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.Header().Set("Vary", "Origin")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, content-type, CF-Turnstile-Response")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, DELETE")
		next.ServeHTTP(w, r)
	})
}

// Preflight handles HTTP OPTIONS preflight requests.
func Preflight(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
