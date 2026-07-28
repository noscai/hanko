package credential_usage

import (
	"fmt"

	"github.com/gofrs/uuid"

	"github.com/teamhanko/hanko/backend/v2/config"
	"github.com/teamhanko/hanko/backend/v2/persistence/models"
)

// validateTenantBoundary enforces the tenant boundary on the pre-authenticated login path.
//
// It is a free function rather than a method on the action because the action is only reachable
// through a flowpilot ExecutionContext (stash, deps, tx), which would drag dockertest and a live
// Postgres into what is pure decision logic. The boundary is the most security-relevant rule on
// this path; it has to be assertable without a database.
//
// The load-bearing check is user.TenantID == claims.TenantID. Both are server-side truths: the
// claim is HMAC-signed by clinic-os and cannot be forged without the shared secret, and the user
// row is the database. The request tenant (X-Tenant-ID) is NOT load-bearing -- the client sets
// that header and may omit it entirely -- so it is only ever checked as defense in depth.
func validateTenantBoundary(
	claims *ServiceTokenClaims,
	user *models.User,
	requestTenantID *uuid.UUID,
	cfg config.MultiTenant,
) error {
	if !cfg.Enabled {
		return nil
	}

	if claims.TenantID == "" {
		return fmt.Errorf("service token carries no tenant_id claim")
	}

	claimedTenant, err := uuid.FromString(claims.TenantID)
	if err != nil {
		return fmt.Errorf("service token carries a malformed tenant_id claim")
	}

	if requestTenantID != nil && *requestTenantID != claimedTenant {
		return fmt.Errorf("service token tenant does not match the request tenant")
	}

	// A global user (tenant_id IS NULL) is legitimate under allow_global_users, which is what
	// production configures. Rejecting them here would lock every legacy user out of login. The
	// caller adopts them into the claimed tenant instead -- see shouldAdoptGlobalUser, mirroring
	// action_password_login.go.
	if user.TenantID == nil {
		if !cfg.AllowGlobalUsers {
			return fmt.Errorf("user has no tenant and global users are disabled")
		}
		return nil
	}

	if *user.TenantID != claimedTenant {
		return fmt.Errorf("service token tenant does not match the user's tenant")
	}

	return nil
}

// shouldAdoptGlobalUser reports whether a user with no tenant should be adopted into the tenant
// named by the service token, and into which tenant.
//
// Split from validateTenantBoundary so the boundary stays a pure decision: adoption writes to the
// database and therefore belongs with the lookup.
func shouldAdoptGlobalUser(
	user *models.User,
	claimsTenantID string,
	cfg config.MultiTenant,
) (bool, uuid.UUID) {
	if !cfg.Enabled || user.TenantID != nil {
		return false, uuid.Nil
	}

	tenant, err := uuid.FromString(claimsTenantID)
	if err != nil {
		return false, uuid.Nil
	}

	return true, tenant
}

// serviceTokenUserLookup is the slice of persistence resolveServiceTokenUser needs. Narrow by
// design: two methods is what makes the boundary unit-testable with a fake and no Postgres.
type serviceTokenUserLookup interface {
	Get(id uuid.UUID) (*models.User, error)
	AdoptUserToTenant(userID uuid.UUID, tenantID uuid.UUID) error
}

// resolveServiceTokenUser resolves the pre-authenticated user and returns them ONLY if the tenant
// boundary holds.
//
// The boundary lives inside the lookup on purpose. If it were a separate call the caller had to
// remember to make, a future edit could drop it and every test here would still pass -- the check
// would be a guard in name only. Because the action cannot obtain a *models.User by any other
// route, the boundary cannot be bypassed without deleting this function outright.
//
// Errors are deliberately uniform: a caller must not be able to tell "this user belongs to another
// tenant" from "no such user", or a secret-holder could enumerate user IDs across tenants.
func resolveServiceTokenUser(
	claims *ServiceTokenClaims,
	users serviceTokenUserLookup,
	requestTenantID *uuid.UUID,
	cfg config.MultiTenant,
) (*models.User, error) {
	userID, err := uuid.FromString(claims.UserID)
	if err != nil || userID.IsNil() {
		return nil, fmt.Errorf("invalid user_id in service token")
	}

	user, err := users.Get(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	if err := validateTenantBoundary(claims, user, requestTenantID, cfg); err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	if adopt, tenant := shouldAdoptGlobalUser(user, claims.TenantID, cfg); adopt {
		if err := users.AdoptUserToTenant(user.ID, tenant); err != nil {
			return nil, fmt.Errorf("failed to adopt user to tenant: %w", err)
		}
		user.TenantID = &tenant
	}

	return user, nil
}
