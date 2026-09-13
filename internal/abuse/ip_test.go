package abuse

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		remoteAddr string
		expected   string
	}{
		{
			name: "CF-Connecting-IP preferred",
			headers: map[string]string{
				"CF-Connecting-IP": "203.0.113.195",
				"X-Forwarded-For":  "198.51.100.1, 192.0.2.1",
			},
			remoteAddr: "127.0.0.1:45678",
			expected:   "203.0.113.195",
		},
		{
			name: "X-Forwarded-For first entry fallback",
			headers: map[string]string{
				"X-Forwarded-For": "198.51.100.42, 192.0.2.1",
			},
			remoteAddr: "127.0.0.1:45678",
			expected:   "198.51.100.42",
		},
		{
			name:       "RemoteAddr fallback without headers",
			headers:    map[string]string{},
			remoteAddr: "192.0.2.99:1234",
			expected:   "192.0.2.99",
		},
		{
			name: "IPv6 CF-Connecting-IP support",
			headers: map[string]string{
				"CF-Connecting-IP": "2001:db8::8a2e:370:7334",
			},
			remoteAddr: "127.0.0.1:45678",
			expected:   "2001:db8::8a2e:370:7334",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/sessions", nil)
			req.RemoteAddr = tc.remoteAddr
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}

			ip := GetClientIP(req)
			if ip != tc.expected {
				t.Fatalf("expected IP %s, got %s", tc.expected, ip)
			}
		})
	}
}
