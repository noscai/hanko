package credential_usage

import (
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/teamhanko/hanko/backend/v2/config"
	"github.com/teamhanko/hanko/backend/v2/persistence/models"
)

// The tenant boundary on the pre-authenticated login path (archon#1668).
//
// validateServiceToken decodes claims.TenantID and never looks at it again; the caller then
// resolves the user through UserPersister.Get(uuid), the ONE lookup with no tenant filter. In
// prod, hanko is a single shared Deployment with one database, multi_tenant.enabled: true, and
// one global service-token secret -- so all tenants' users live in one table with no boundary
// over them. A secret-holder can pre-authenticate any user in any tenant, and because
// PreAuthenticatedContinue seeds trusted identity for a fresh WebAuthn registration, for any
// victim with is_2fa_setup=false that is account takeover, not merely an MFA skip.
//
// Cases 1-3 are the bug: they must fail before the fix and pass after.
// Cases 4-8 are the GUARD: they must pass BOTH before and after.
//
// A fix that closes 1-3 but breaks any of 4-8 is not a fix, it is an outage. Case 5 (the
// frontend does not send X-Tenant-ID) and case 6 (a global user with a NULL tenant) are the
// two that #1668's literal §4 wording would have broken.

var (
	tenantA = uuid.FromStringOrNil("aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa")
	tenantB = uuid.FromStringOrNil("bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb")
	userID  = uuid.FromStringOrNil("cccccccc-3333-4333-8333-cccccccccccc")
)

func multiTenantOn() config.MultiTenant {
	cfg := config.DefaultMultiTenantConfig()
	cfg.Enabled = true
	cfg.AllowGlobalUsers = true
	return cfg
}

func multiTenantOff() config.MultiTenant {
	cfg := config.DefaultMultiTenantConfig()
	cfg.Enabled = false
	return cfg
}

func multiTenantStrict() config.MultiTenant {
	cfg := config.DefaultMultiTenantConfig()
	cfg.Enabled = true
	cfg.AllowGlobalUsers = false
	return cfg
}

// userIn builds a user row belonging to the given tenant. A nil tenant is a "global user" --
// legitimate under allow_global_users: true, which is what prod configures.
func userIn(tenant *uuid.UUID) *models.User {
	return &models.User{ID: userID, TenantID: tenant}
}

func TestValidateTenantBoundary(t *testing.T) {
	tests := []struct {
		name          string
		claimsTenant  string
		userTenant    *uuid.UUID
		requestTenant *uuid.UUID
		cfg           config.MultiTenant
		wantErr       bool
		why           string
	}{
		// ---- The bug (archon#1668 §5) ----
		{
			name:          "rejects a token whose tenant does not match the request tenant",
			claimsTenant:  tenantB.String(),
			userTenant:    &tenantB,
			requestTenant: &tenantA,
			cfg:           multiTenantOn(),
			wantErr:       true,
			why:           "#1668 §5.1 -- tenant-B token presented on a tenant-A request",
		},
		{
			name:          "rejects a token whose tenant does not match the RESOLVED USER's tenant",
			claimsTenant:  tenantA.String(),
			userTenant:    &tenantB,
			requestTenant: &tenantA,
			cfg:           multiTenantOn(),
			wantErr:       true,
			why:           "#1668 §5.2 -- THE CORE DEFECT. The claim is never compared to the user row.",
		},
		{
			name:          "rejects an empty tenant claim (fail closed)",
			claimsTenant:  "",
			userTenant:    &tenantA,
			requestTenant: &tenantA,
			cfg:           multiTenantOn(),
			wantErr:       true,
			why:           "#1668 §5.3 -- a token with no tenant must not be a wildcard",
		},
		{
			name:          "rejects a malformed tenant claim",
			claimsTenant:  "not-a-uuid",
			userTenant:    &tenantA,
			requestTenant: &tenantA,
			cfg:           multiTenantOn(),
			wantErr:       true,
			why:           "garbage must not match anything",
		},

		// ---- The guard: these MUST keep passing, or login breaks ----
		{
			name:          "allows the legitimate login",
			claimsTenant:  tenantA.String(),
			userTenant:    &tenantA,
			requestTenant: &tenantA,
			cfg:           multiTenantOn(),
			wantErr:       false,
			why:           "#1668 §5.4 -- the happy path verify-pin depends on",
		},
		{
			name:          "allows the login when the client sends no X-Tenant-ID header",
			claimsTenant:  tenantA.String(),
			userTenant:    &tenantA,
			requestTenant: nil,
			cfg:           multiTenantOn(),
			wantErr:       false,
			why: "CORRECTION 1. The header is optional -- hanko-frontend-sdk HttpClient.ts:185 " +
				"sends it only when a tenantId was passed, and middleware/tenant.go:80 lets the " +
				"request through with a nil tenant under allow_global_users. Requiring the request " +
				"tenant to match, as #1668 §4 step 2 literally says, would reject every such login.",
		},
		{
			name:          "allows a global user with a NULL tenant (caller adopts)",
			claimsTenant:  tenantA.String(),
			userTenant:    nil,
			requestTenant: &tenantA,
			cfg:           multiTenantOn(),
			wantErr:       false,
			why: "CORRECTION 2. allow_global_users: true is what prod runs, so NULL-tenant users " +
				"exist by design. #1668 §4 step 4 says fail closed here -- that would lock every " +
				"one of them out. action_password_login.go:75-81 adopts instead; so do we.",
		},
		{
			name:          "is a no-op when multi-tenant mode is disabled",
			claimsTenant:  tenantB.String(),
			userTenant:    &tenantA,
			requestTenant: nil,
			cfg:           multiTenantOff(),
			wantErr:       false,
			why:           "single-tenant deploys have no boundary to enforce",
		},
		{
			name:          "rejects a global user when global users are disabled",
			claimsTenant:  tenantA.String(),
			userTenant:    nil,
			requestTenant: &tenantA,
			cfg:           multiTenantStrict(),
			wantErr:       true,
			why: "with allow_global_users: false a NULL-tenant user is not permitted at all -- " +
				"this is the ONLY config under which #1668 §4 step 4's fail-closed is correct",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := &ServiceTokenClaims{UserID: userID.String(), TenantID: tt.claimsTenant}

			err := validateTenantBoundary(claims, userIn(tt.userTenant), tt.requestTenant, tt.cfg)

			if tt.wantErr {
				require.Error(t, err, "MUST be rejected: %s", tt.why)
			} else {
				require.NoError(t, err, "MUST be allowed: %s", tt.why)
			}
		})
	}
}

// TestShouldAdoptGlobalUser pins the adoption predicate the caller uses. Adoption only ever
// applies to a user with no tenant -- AdoptUserToTenant's SQL is guarded by
// "AND tenant_id IS NULL", so it cannot re-home a user who already belongs somewhere, but the
// predicate must not even ask it to.
func TestShouldAdoptGlobalUser(t *testing.T) {
	cfg := multiTenantOn()

	t.Run("adopts a global user into the claimed tenant", func(t *testing.T) {
		adopt, tenant := shouldAdoptGlobalUser(userIn(nil), tenantA.String(), cfg)
		assert.True(t, adopt)
		assert.Equal(t, tenantA, tenant)
	})

	t.Run("does not adopt a user who already has a tenant", func(t *testing.T) {
		adopt, _ := shouldAdoptGlobalUser(userIn(&tenantA), tenantA.String(), cfg)
		assert.False(t, adopt)
	})

	t.Run("does not adopt when multi-tenant mode is off", func(t *testing.T) {
		adopt, _ := shouldAdoptGlobalUser(userIn(nil), tenantA.String(), multiTenantOff())
		assert.False(t, adopt)
	})

	t.Run("does not adopt into a malformed tenant claim", func(t *testing.T) {
		adopt, _ := shouldAdoptGlobalUser(userIn(nil), "not-a-uuid", cfg)
		assert.False(t, adopt)
	})
}
