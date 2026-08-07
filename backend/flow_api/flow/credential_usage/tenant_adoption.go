package credential_usage

import "github.com/gofrs/uuid"

// shouldAdoptUserToTenant decides whether a user found during login should be
// bound (adopted) to the login tenant.
//
// Adoption only ever applies to a user resolved via the global fallback
// (tenant_id IS NULL) when a tenant context is present. When keepUsersGlobal is
// true, adoption is suppressed so the identity stays global and can authenticate
// against every tenant it belongs to — the ClinicOS org-switch prerequisite
// (Archon #1085 §8.8). Tenant membership is then governed by the control-plane
// registry rather than Hanko's single user.tenant_id.
func shouldAdoptUserToTenant(isGlobalFallback bool, tenantID *uuid.UUID, keepUsersGlobal bool) bool {
	return isGlobalFallback && tenantID != nil && !keepUsersGlobal
}
