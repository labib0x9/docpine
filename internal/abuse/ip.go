package abuse

import (
	"net"
	"net/http"
	"strings"
)

// GetClientIP extracts the real client IP address from request headers.
// Since Docpine runs behind Cloudflare Tunnel (cloudflared), the TCP connection's
// remote address will always be localhost. Therefore, CF-Connecting-IP is the primary
// trusted source, followed by X-Forwarded-For, with RemoteAddr as a final fallback.
func GetClientIP(r *http.Request) string {
	// 1. Primary: Cloudflare connecting IP header
	if cfIP := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); cfIP != "" {
		if ip := net.ParseIP(cfIP); ip != nil {
			return ip.String()
		}
	}

	// 2. Secondary: X-Forwarded-For (client IP is the first entry)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		for _, part := range parts {
			trimmed := strings.TrimSpace(part)
			if ip := net.ParseIP(trimmed); ip != nil {
				return ip.String()
			}
		}
	}

	// 3. Fallback: Direct RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		if ip := net.ParseIP(host); ip != nil {
			return ip.String()
		}
		return host
	}

	return strings.TrimSpace(r.RemoteAddr)
}
