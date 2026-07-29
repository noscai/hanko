package session

import (
	"errors"
	"net/http"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/teamhanko/hanko/backend/v2/config"
	"github.com/teamhanko/hanko/backend/v2/dto"
	"github.com/teamhanko/hanko/backend/v2/test"
)

// failingGenerator is a jwk.Generator whose Sign always fails -- it drives GenerateJWT's signing
// error return, which the real test.JwkManager never triggers.
type failingGenerator struct{}

func (failingGenerator) Sign(jwt.Token) ([]byte, error)  { return nil, errors.New("sign boom") }
func (failingGenerator) Verify([]byte) (jwt.Token, error) { return nil, errors.New("verify boom") }

// NewManager maps each configured SameSite string to the right http.SameSite mode; GenerateCookie
// then carries it onto the emitted cookie. Verifying via the cookie exercises both functions.
func TestNewManager_SameSiteMapping_AndGenerateCookie(t *testing.T) {
	cases := []struct {
		configured string
		want       http.SameSite
	}{
		{"lax", http.SameSiteLaxMode},
		{"strict", http.SameSiteStrictMode},
		{"none", http.SameSiteNoneMode},
		{"", http.SameSiteDefaultMode},
		{"garbage", http.SameSiteDefaultMode},
	}
	for _, tc := range cases {
		t.Run(tc.configured, func(t *testing.T) {
			cfg := config.Config{Session: config.Session{Lifespan: "5m"}}
			cfg.Session.Cookie.SameSite = tc.configured

			mgr, err := NewManager(&test.JwkManager{}, cfg)
			require.NoError(t, err)

			cookie, err := mgr.GenerateCookie("the-token")
			require.NoError(t, err)
			assert.Equal(t, tc.want, cookie.SameSite)
			assert.Equal(t, "the-token", cookie.Value)
			assert.Equal(t, "/", cookie.Path)
			assert.Equal(t, 300, cookie.MaxAge, "MaxAge is the session lifespan in seconds")
			assert.Equal(t, "hanko", cookie.Name)
		})
	}
}

// GenerateJWT applies a JWT claim template, and stamps username, tenant_id and any extra claims
// supplied via WithValue options.
func TestGenerateJWT_TemplateUsernameTenantAndOptions(t *testing.T) {
	tenantID := "tenant-xyz"
	cfg := config.Config{
		Session: config.Session{
			Lifespan:    "5m",
			JWTTemplate: &config.JWTTemplate{Claims: map[string]interface{}{"role": "admin"}},
		},
	}
	mgr, err := NewManager(&test.JwkManager{}, cfg)
	require.NoError(t, err)

	userID := uuid.Must(uuid.NewV4())
	signed, token, err := mgr.GenerateJWT(
		dto.UserJWT{UserID: userID.String(), Username: "alice", TenantID: &tenantID},
		WithValue("custom", "extra"),
	)
	require.NoError(t, err)
	require.NotEmpty(t, signed)

	username, ok := token.Get("username")
	assert.True(t, ok)
	assert.Equal(t, "alice", username)

	tenant, ok := token.Get("tenant_id")
	assert.True(t, ok)
	assert.Equal(t, tenantID, tenant)

	role, ok := token.Get("role")
	assert.True(t, ok)
	assert.Equal(t, "admin", role, "the JWT claim template must be applied")

	custom, ok := token.Get("custom")
	assert.True(t, ok)
	assert.Equal(t, "extra", custom, "a WithValue option must land on the token")
}

// A signing failure propagates as an error and yields no token.
func TestGenerateJWT_SignError(t *testing.T) {
	cfg := config.Config{Session: config.Session{Lifespan: "5m"}}
	mgr, err := NewManager(failingGenerator{}, cfg)
	require.NoError(t, err)

	signed, token, err := mgr.GenerateJWT(dto.UserJWT{UserID: uuid.Must(uuid.NewV4()).String()})
	require.Error(t, err)
	assert.Empty(t, signed)
	assert.Nil(t, token)
}
