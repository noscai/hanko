package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/teamhanko/hanko/backend/v2/test"
)

// ClearDeviceTrust only reads the session from the echo context and writes
// cookies - it never touches the persister, session manager, or audit
// logger - so this test exercises the handler directly against a plain
// echo.Context, without the Postgres-backed test.Suite the other handler
// tests use.

func TestUserHandler_ClearDeviceTrust_ClearsBothDeviceTrustCookies(t *testing.T) {
	cfg := test.DefaultConfig
	cfg.MFA.DeviceTrustCookieName = "test-legacy-device-trust-token"
	cfg.MFA.DeviceTrustDeviceCookieName = "test-device-id"

	h := NewUserHandler(&cfg, nil, nil, nil)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/device-trust/clear", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("session", jwt.New())

	err := h.ClearDeviceTrust(c)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusNoContent, rec.Code)

	setCookieHeaders := rec.Header()["Set-Cookie"]
	assert.Len(t, setCookieHeaders, 2, "expected one Set-Cookie header per device-trust cookie name, got: %v", setCookieHeaders)

	cookiesByName := map[string]*http.Cookie{}
	for _, cookie := range rec.Result().Cookies() {
		cookiesByName[cookie.Name] = cookie
	}

	for _, name := range []string{cfg.MFA.DeviceTrustCookieName, cfg.MFA.DeviceTrustDeviceCookieName} {
		cookie, ok := cookiesByName[name]
		if !assert.True(t, ok, "expected a Set-Cookie header for %q", name) {
			continue
		}
		assert.Equal(t, "/", cookie.Path, "cookie %q: Path", name)
		assert.Equal(t, -1, cookie.MaxAge, "cookie %q: MaxAge", name)
		assert.True(t, cookie.HttpOnly, "cookie %q: HttpOnly", name)
		assert.True(t, cookie.Secure, "cookie %q: Secure", name)
		assert.Equal(t, http.SameSiteNoneMode, cookie.SameSite, "cookie %q: SameSite", name)
	}
}

func TestUserHandler_ClearDeviceTrust_RequiresSession(t *testing.T) {
	cfg := test.DefaultConfig
	h := NewUserHandler(&cfg, nil, nil, nil)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/device-trust/clear", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	// no "session" set on the context - simulates a request that never
	// passed sessionMiddleware.

	err := h.ClearDeviceTrust(c)
	assert.Error(t, err)
	assert.Empty(t, rec.Header()["Set-Cookie"], "no cookies should be cleared without a session")
}
