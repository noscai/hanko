package credential_usage

import (
	"errors"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/teamhanko/hanko/backend/v2/config"
	"github.com/teamhanko/hanko/backend/v2/persistence"
	"github.com/teamhanko/hanko/backend/v2/persistence/models"
)

// These tests drive the real resolution path -- the one PreAuthenticatedContinue.Execute calls --
// rather than the boundary function in isolation. Testing validateTenantBoundary alone would prove
// only that the check works, not that anything invokes it; a future edit could drop the call and
// every test would stay green. That is the "guarded invariant tested via bypass" antipattern.
//
// A fake persister keeps this a unit test: no dockertest, no Postgres, no CI time.

type fakeUserLookup struct {
	user *models.User
	err  error

	adoptedUser   uuid.UUID
	adoptedTenant uuid.UUID
	adoptCalls    int
	adoptErr      error
}

func (f *fakeUserLookup) Get(id uuid.UUID) (*models.User, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.user, nil
}

func (f *fakeUserLookup) AdoptUserToTenant(userID uuid.UUID, tenantID uuid.UUID) error {
	f.adoptCalls++
	f.adoptedUser = userID
	f.adoptedTenant = tenantID
	return f.adoptErr
}

func claimsFor(userID uuid.UUID, tenantID string) *ServiceTokenClaims {
	return &ServiceTokenClaims{UserID: userID.String(), TenantID: tenantID}
}

// THE BUG (archon#1668). Before the fix, this returned tenant B's user to a tenant-A caller and
// the flow went on to seed trusted identity for them.
func TestResolveServiceTokenUser_RefusesUserFromAnotherTenant(t *testing.T) {
	lookup := &fakeUserLookup{user: &models.User{ID: userID, TenantID: &tenantB}}

	user, err := resolveServiceTokenUser(
		claimsFor(userID, tenantA.String()),
		lookup,
		&tenantA,
		multiTenantOn(),
	)

	require.Error(t, err)
	assert.Nil(t, user, "a user from another tenant must never be returned")
	assert.Zero(t, lookup.adoptCalls, "a foreign user must not be adopted")
}

// The error must not distinguish "belongs to another tenant" from "does not exist", or a holder of
// the shared secret could enumerate user IDs across every tenant in the shared hanko database.
func TestResolveServiceTokenUser_ForeignTenantIsIndistinguishableFromMissingUser(t *testing.T) {
	foreign := &fakeUserLookup{user: &models.User{ID: userID, TenantID: &tenantB}}
	missing := &fakeUserLookup{user: nil}

	_, foreignErr := resolveServiceTokenUser(claimsFor(userID, tenantA.String()), foreign, &tenantA, multiTenantOn())
	_, missingErr := resolveServiceTokenUser(claimsFor(userID, tenantA.String()), missing, &tenantA, multiTenantOn())

	require.Error(t, foreignErr)
	require.Error(t, missingErr)
	assert.Contains(t, foreignErr.Error(), "user not found")
	assert.Contains(t, missingErr.Error(), "user not found")
}

// THE GUARD. The legitimate pre-authenticated login that verify-pin depends on must keep working.
func TestResolveServiceTokenUser_AllowsLegitimateLogin(t *testing.T) {
	lookup := &fakeUserLookup{user: &models.User{ID: userID, TenantID: &tenantA}}

	user, err := resolveServiceTokenUser(
		claimsFor(userID, tenantA.String()),
		lookup,
		&tenantA,
		multiTenantOn(),
	)

	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, userID, user.ID)
	assert.Zero(t, lookup.adoptCalls, "a user who already has a tenant must not be adopted")
}

// THE GUARD (correction 1). The admin frontend sends X-Tenant-ID only when a tenantId was passed to
// getHankoClient, so a nil request tenant is normal, not an attack. Rejecting it would be an outage.
func TestResolveServiceTokenUser_AllowsLoginWithNoRequestTenantHeader(t *testing.T) {
	lookup := &fakeUserLookup{user: &models.User{ID: userID, TenantID: &tenantA}}

	user, err := resolveServiceTokenUser(
		claimsFor(userID, tenantA.String()),
		lookup,
		nil,
		multiTenantOn(),
	)

	require.NoError(t, err)
	assert.NotNil(t, user)
}

// THE GUARD (correction 2). Global users exist by design under allow_global_users: true, which is
// what production runs. They are adopted into the claimed tenant, not rejected.
func TestResolveServiceTokenUser_AdoptsGlobalUser(t *testing.T) {
	lookup := &fakeUserLookup{user: &models.User{ID: userID, TenantID: nil}}

	user, err := resolveServiceTokenUser(
		claimsFor(userID, tenantA.String()),
		lookup,
		&tenantA,
		multiTenantOn(),
	)

	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, 1, lookup.adoptCalls, "the global user must be adopted")
	assert.Equal(t, userID, lookup.adoptedUser)
	assert.Equal(t, tenantA, lookup.adoptedTenant)
	require.NotNil(t, user.TenantID)
	assert.Equal(t, tenantA, *user.TenantID, "the returned user must carry the adopted tenant")
}

func TestResolveServiceTokenUser_FailsWhenAdoptionFails(t *testing.T) {
	lookup := &fakeUserLookup{
		user:     &models.User{ID: userID, TenantID: nil},
		adoptErr: errors.New("db is down"),
	}

	user, err := resolveServiceTokenUser(
		claimsFor(userID, tenantA.String()),
		lookup,
		&tenantA,
		multiTenantOn(),
	)

	require.Error(t, err, "a failed adoption must not silently pre-authenticate an unscoped user")
	assert.Nil(t, user)
}

func TestResolveServiceTokenUser_RejectsMissingAndMalformedSubject(t *testing.T) {
	lookup := &fakeUserLookup{user: &models.User{ID: userID, TenantID: &tenantA}}

	for _, sub := range []string{"", "not-a-uuid", uuid.Nil.String()} {
		t.Run("subject="+sub, func(t *testing.T) {
			user, err := resolveServiceTokenUser(
				&ServiceTokenClaims{UserID: sub, TenantID: tenantA.String()},
				lookup,
				&tenantA,
				multiTenantOn(),
			)

			require.Error(t, err)
			assert.Nil(t, user)
		})
	}
}

func TestResolveServiceTokenUser_PropagatesLookupFailure(t *testing.T) {
	lookup := &fakeUserLookup{err: errors.New("connection refused")}

	user, err := resolveServiceTokenUser(
		claimsFor(userID, tenantA.String()),
		lookup,
		&tenantA,
		multiTenantOn(),
	)

	require.Error(t, err)
	assert.Nil(t, user)
}

// Single-tenant deployments have no boundary to enforce; the fix must be inert there.
func TestResolveServiceTokenUser_IsInertWhenMultiTenantDisabled(t *testing.T) {
	lookup := &fakeUserLookup{user: &models.User{ID: userID, TenantID: &tenantA}}

	user, err := resolveServiceTokenUser(
		claimsFor(userID, tenantB.String()),
		lookup,
		nil,
		multiTenantOff(),
	)

	require.NoError(t, err)
	assert.NotNil(t, user)
	assert.Zero(t, lookup.adoptCalls)
}

// Compile-time proof that the REAL persistence.UserPersister -- the concrete type the action
// passes in via deps.Persister.GetUserPersisterWithConnection(...) -- satisfies the narrow
// serviceTokenUserLookup interface. If upstream changes UserPersister.Get or AdoptUserToTenant's
// signature, this stops compiling. (Asserting against an anonymous identical interface would be
// tautological and would NOT catch an upstream shape change.)
var _ serviceTokenUserLookup = persistence.UserPersister(nil)

var _ = config.DefaultMultiTenantConfig
