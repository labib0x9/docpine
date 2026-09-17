package utils

import (
	"net/http"

	"github.com/labib0x9/docpine/internal/config"
)

var allowedOrigins map[string]bool

func InitAllowedOrigins(cnf *config.Config) {
	allowedOrigins = make(map[string]bool)
	for _, origin := range cnf.AllowedOrigins {
		allowedOrigins[origin] = true
	}
}

func CheckOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	return allowedOrigins[origin]
}
