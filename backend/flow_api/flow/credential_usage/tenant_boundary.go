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
// For a tenant-bound user the load-bearing check is user.TenantID == claims.TenantID. Both are
// server-side truths: the claim is HMAC-signed by clinic-os and cannot be forged without the shared
// secret, and the user row is the database. The request tenant (X-Tenant-ID) is NOT load-bearing
// for them -- the client sets that header and may omit it entirely -- so it is only ever checked
// as defense in depth.
//
// A global user (tenant_id IS NULL) has no row tenant to compare. Without keep_users_global they
// are adopted into the claimed tenant on first use, and the check above binds them from then on.
// Under keep_users_global they are never adopted, so they are bound only by the signed claim and,
// when the header is sent, by claim == X-Tenant-ID: a token naming any tenant is accepted for them.
// Which clinics such a user belongs to is decided by clinic-os, which signs the claim, and the
// flow is then pinned to the claimed tenant (serviceTokenFlowTenant), so its device trust and the
// session it issues are that clinic's.
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
	// caller adopts them into the claimed tenant instead (see shouldAdoptGlobalUser, mirroring
	// action_password_login.go), unless keep_users_global is on: then they stay global, and the
	// claim == request-tenant check above is the only tenant check they get here.
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
//
// Under keep_users_global a global user is never adopted, the same rule as the password and
// login-identifier flows (shouldAdoptUserToTenant): their identity serves every clinic they
// belong to, and an adoption here would lock them out of the next clinic's step-up.
func shouldAdoptGlobalUser(
	user *models.User,
	claimsTenantID string,
	cfg config.MultiTenant,
) (bool, uuid.UUID) {
	if !cfg.Enabled {
		return false, uuid.Nil
	}

	tenant, err := uuid.FromString(claimsTenantID)
	if err != nil {
		return false, uuid.Nil
	}

	return shouldAdoptUserToTenant(user.TenantID == nil, &tenant, cfg.KeepUsersGlobal), tenant
}

// serviceTokenFlowTenant returns the tenant a pre-authenticated flow runs under: the one the
// service token names (archon#1085 Q18). Call it only with claims resolveServiceTokenUser has
// accepted: by then the claim is a well-formed tenant equal to the request tenant when a header
// was sent, and to the user's own tenant when they have one.
//
// It matters for a user kept global. They have no row tenant, and the admin app may send no
// X-Tenant-ID, so without the pin the flow ran under no tenant: device trust from a legacy row
// skipped the second factor, and the session named no clinic. Pinning to the claim also covers a
// tenant-bound user's flow sent without the header, whose claim is their own tenant.
//
// A header-less pre-authenticated flow's tenant therefore comes from clinic-os's signed claim
// alone: unlike a header, it never passes the tenant middleware, so Hanko does not check that the
// tenant exists or that tenant.enabled is set. clinic-os refuses suspended tenants itself, and the
// same flow skipped the middleware's gate before (it ran with no tenant).
func serviceTokenFlowTenant(claims *ServiceTokenClaims, cfg config.MultiTenant) *uuid.UUID {
	if !cfg.Enabled {
		return nil
	}

	tenant, err := uuid.FromString(claims.TenantID)
	if err != nil {
		return nil
	}

	return &tenant
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
		// Bare, detail-free: a foreign-tenant user must be indistinguishable from a missing one at
		// EVERY layer, including a debug-mode caller that surfaces the wrapped cause. Wrapping the
		// boundary reason here (%w) would let a secret-holder enumerate user IDs across tenants.
		return nil, fmt.Errorf("user not found")
	}

	if adopt, tenant := shouldAdoptGlobalUser(user, claims.TenantID, cfg); adopt {
		if err := users.AdoptUserToTenant(user.ID, tenant); err != nil {
			return nil, fmt.Errorf("failed to adopt user to tenant: %w", err)
		}

		// AdoptUserToTenant is a conditional UPDATE (... WHERE tenant_id IS NULL). A concurrent
		// pre-auth flow may have adopted this global user into a DIFFERENT tenant first, in which
		// case our UPDATE matched zero rows and `user` is now stale. The database is authoritative:
		// re-read the row and re-check the boundary, so a race cannot pre-authenticate the user into
		// a tenant they no longer belong to. Setting the stale model to the claimed tenant would.
		user, err = users.Get(user.ID)
		if err != nil || user == nil {
			return nil, fmt.Errorf("user not found")
		}
		if err := validateTenantBoundary(claims, user, requestTenantID, cfg); err != nil {
			return nil, fmt.Errorf("user not found")
		}
	}

	return user, nil
}
