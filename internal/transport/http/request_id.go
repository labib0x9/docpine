package http

import (
	"context"
	"net/http"

	"github.com/google/uuid"
)

type requestIDKey struct{}

var rKey = requestIDKey{}

// WithRequestID returns a copy of ctx with the request ID attached.
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, rKey, requestID)
}

// GetRequestID extracts the request ID from the context if present.
func GetRequestID(ctx context.Context) string {
	id, _ := ctx.Value(rKey).(string)
	return id
}

// RequestId injects a unique X-Request-Id header into the request context and response headers.
func RequestId(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if id == "" {
			id = uuid.NewString()
		}
		w.Header().Set("X-Request-Id", id)
		ctx := WithRequestID(r.Context(), id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
