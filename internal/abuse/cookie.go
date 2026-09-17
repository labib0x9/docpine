package abuse

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	// DeviceCookieName is the HTTP cookie name for the anonymous device identifier.
	DeviceCookieName = "__dp_dev"
	// DeviceCookieMaxAge specifies cookie validity (10 Minutes).
	DeviceCookieMaxAge = 10 * 60
)

// DeviceCookieManager generates, signs, and validates anonymous device cookies.
type DeviceCookieManager struct {
	secret []byte
}

// NewDeviceCookieManager constructs a new cookie manager with the given secret.
func NewDeviceCookieManager(secret []byte) *DeviceCookieManager {
	return &DeviceCookieManager{secret: secret}
}

// Sign creates an HMAC-SHA256 signature for a device ID and timestamp.
func (m *DeviceCookieManager) Sign(deviceID string, timestamp int64) string {
	payload := fmt.Sprintf("%s.%d", deviceID, timestamp)
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify checks the validity and signature of a cookie value.
func (m *DeviceCookieManager) Verify(cookieVal string) (string, bool) {
	parts := strings.Split(cookieVal, ".")
	if len(parts) != 3 {
		return "", false
	}

	deviceID, tsStr, signature := parts[0], parts[1], parts[2]
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return "", false
	}

	// Verify cookie expiration
	cookieTime := time.Unix(ts, 0)
	if time.Since(cookieTime) > time.Duration(DeviceCookieMaxAge)*time.Second || time.Until(cookieTime) > 5*time.Minute {
		return "", false
	}

	expectedSig := m.Sign(deviceID, ts)
	if !hmac.Equal([]byte(signature), []byte(expectedSig)) {
		return "", false
	}

	return deviceID, true
}

// GetOrSet extracts an existing valid device ID from request cookies, or issues a new signed cookie.
func (m *DeviceCookieManager) GetOrSet(w http.ResponseWriter, r *http.Request) string {
	if cookie, err := r.Cookie(DeviceCookieName); err == nil {
		if deviceID, valid := m.Verify(cookie.Value); valid {
			return deviceID
		}
	}

	// Generate new signed device cookie
	newID := uuid.New().String()
	now := time.Now().Unix()
	sig := m.Sign(newID, now)
	val := fmt.Sprintf("%s.%d.%s", newID, now, sig)

	http.SetCookie(w, &http.Cookie{
		Name:     DeviceCookieName,
		Value:    val,
		Path:     "/",
		MaxAge:   DeviceCookieMaxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	})

	return newID
}
