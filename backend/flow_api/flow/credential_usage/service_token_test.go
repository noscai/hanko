package credential_usage

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testSecret = "test-service-token-secret-do-not-use-in-prod"
	testIssuer = "clinic-os-backend"
	testUserID = "8f14e45f-ceea-467a-9575-28db8d0bd0f5"
	testTenant = "b1e0f5c2-3a4d-4e6f-8a9b-0c1d2e3f4a5b"
)

// mintToken signs a service token the way medusa's generateServiceToken does:
// HS256, `sub` + `tenant_id`, an issuer, and an expiry.
func mintToken(t *testing.T, secret, issuer, sub, tenantID string, expiresIn time.Duration) string {
	t.Helper()

	claims := ServiceTokenClaims{
		UserID:   sub,
		TenantID: tenantID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	require.NoError(t, err)

	return signed
}

// TestValidateServiceToken_AcceptsLegitimateToken is the regression guard: whatever else the
// adversarial cases below tighten, the pre-authenticated login that verify-pin depends on must
// keep working. If this test breaks, login is broken for every tenant.
func TestValidateServiceToken_AcceptsLegitimateToken(t *testing.T) {
	token := mintToken(t, testSecret, testIssuer, testUserID, testTenant, time.Hour)

	claims, err := validateServiceToken(token, testSecret, testIssuer)

	require.NoError(t, err)
	require.NotNil(t, claims)
	assert.Equal(t, testUserID, claims.UserID)
	assert.Equal(t, testTenant, claims.TenantID)
	assert.Equal(t, testIssuer, claims.Issuer)
}

// TestValidateServiceToken_Rejects covers the adversarial set. The service token is the only
// thing standing between an HTTP request and "log in as any user" -- every rejection here is a
// guard that already exists in the source but has never been asserted.
func TestValidateServiceToken_Rejects(t *testing.T) {
	tests := []struct {
		name  string
		token func(t *testing.T) string
		// secret/issuer as configured on the hanko side
		secret string
		issuer string
	}{
		{
			// SEC-1: alg confusion. An unsigned token must never forge a login.
			//
			// Mutation-check result: removing the *jwt.SigningMethodHMAC check in
			// service_token.go does NOT make this test fail. golang-jwt/v5 already enforces
			// the property -- our keyfunc hands back []byte(secret), and SigningMethodNone
			// only verifies against the sentinel UnsafeAllowNoneSignatureType key, so a none
			// token is rejected on key type before our check is ever consulted. The same is
			// true of RS256/ES256: []byte is not an *rsa.PublicKey.
			//
			// So the explicit method check is redundant defense-in-depth, not the thing that
			// stops this attack. The test is kept because the *security property* is what
			// matters and must stay pinned -- but it does not guard that line, and claiming
			// otherwise would be the "green CI, false confidence" failure this suite exists
			// to prevent. The guard earns its keep only if the keyfunc is ever changed to
			// return a non-[]byte key.
			name: "alg=none is rejected",
			token: func(t *testing.T) string {
				claims := ServiceTokenClaims{
					UserID:   testUserID,
					TenantID: testTenant,
					RegisteredClaims: jwt.RegisteredClaims{
						Issuer:    testIssuer,
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
					},
				}
				signed, err := jwt.NewWithClaims(jwt.SigningMethodNone, claims).
					SignedString(jwt.UnsafeAllowNoneSignatureType)
				require.NoError(t, err)
				return signed
			},
			secret: testSecret,
			issuer: testIssuer,
		},
		{
			name: "token signed with the wrong secret is rejected",
			token: func(t *testing.T) string {
				return mintToken(t, "a-different-secret-entirely", testIssuer, testUserID, testTenant, time.Hour)
			},
			secret: testSecret,
			issuer: testIssuer,
		},
		{
			name: "expired token is rejected",
			token: func(t *testing.T) string {
				return mintToken(t, testSecret, testIssuer, testUserID, testTenant, -time.Minute)
			},
			secret: testSecret,
			issuer: testIssuer,
		},
		{
			name: "issuer mismatch is rejected",
			token: func(t *testing.T) string {
				return mintToken(t, testSecret, "some-other-issuer", testUserID, testTenant, time.Hour)
			},
			secret: testSecret,
			issuer: testIssuer,
		},
		{
			name: "empty subject is rejected",
			token: func(t *testing.T) string {
				return mintToken(t, testSecret, testIssuer, "", testTenant, time.Hour)
			},
			secret: testSecret,
			issuer: testIssuer,
		},
		{
			name: "tampered payload is rejected",
			token: func(t *testing.T) string {
				token := mintToken(t, testSecret, testIssuer, testUserID, testTenant, time.Hour)
				// Flip a byte in the payload segment; the signature no longer matches.
				b := []byte(token)
				for i := 0; i < len(b); i++ {
					if b[i] == '.' {
						b[i+1] = 'X'
						break
					}
				}
				return string(b)
			},
			secret: testSecret,
			issuer: testIssuer,
		},
		{
			name:   "garbage is rejected",
			token:  func(t *testing.T) string { return "not-a-jwt-at-all" },
			secret: testSecret,
			issuer: testIssuer,
		},
		{
			name: "empty secret on the hanko side rejects even a well-formed token",
			token: func(t *testing.T) string {
				return mintToken(t, testSecret, testIssuer, testUserID, testTenant, time.Hour)
			},
			secret: "",
			issuer: testIssuer,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims, err := validateServiceToken(tt.token(t), tt.secret, tt.issuer)

			require.Error(t, err, "token must be rejected")
			assert.Nil(t, claims, "no claims may be returned for a rejected token")
		})
	}
}

// TestValidateServiceToken_EmptyExpectedIssuerSkipsIssuerCheck characterizes the existing
// behaviour: an empty expectedIssuer disables the issuer comparison entirely. This is a
// deliberate escape hatch in the source, not an oversight -- pinning it here so that a future
// change to make the issuer mandatory is a visible, intentional break rather than a silent one.
func TestValidateServiceToken_EmptyExpectedIssuerSkipsIssuerCheck(t *testing.T) {
	token := mintToken(t, testSecret, "literally-any-issuer", testUserID, testTenant, time.Hour)

	claims, err := validateServiceToken(token, testSecret, "")

	require.NoError(t, err)
	assert.Equal(t, "literally-any-issuer", claims.Issuer)
}
