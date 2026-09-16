package abuse

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDeviceCookieManager(t *testing.T) {
	secret := []byte("test-secret-32-byte-long-key-1234")
	mgr := NewDeviceCookieManager(secret)

	// 1. Initial request (no cookie) -> sets new signed cookie
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	deviceID := mgr.GetOrSet(w, req)
	if deviceID == "" {
		t.Fatal("expected non-empty deviceID")
	}

	cookies := w.Result().Cookies()
	var devCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == DeviceCookieName {
			devCookie = c
			break
		}
	}

	if devCookie == nil {
		t.Fatal("expected __dp_dev cookie to be set")
	}

	// 2. Subsequent request with valid cookie -> recovers same device ID
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.AddCookie(devCookie)
	w2 := httptest.NewRecorder()

	recoveredID := mgr.GetOrSet(w2, req2)
	if recoveredID != deviceID {
		t.Fatalf("expected recovered deviceID %s, got %s", deviceID, recoveredID)
	}

	// 3. Tampered cookie -> rejected and reset
	tamperedCookie := &http.Cookie{
		Name:  DeviceCookieName,
		Value: devCookie.Value + "tamper",
	}
	req3 := httptest.NewRequest(http.MethodGet, "/", nil)
	req3.AddCookie(tamperedCookie)
	w3 := httptest.NewRecorder()

	newID := mgr.GetOrSet(w3, req3)
	if newID == deviceID {
		t.Fatal("expected tampered cookie to be rejected and new ID generated")
	}
}
