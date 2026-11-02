package credential_usage

import (
	"testing"

	"github.com/gofrs/uuid"
)

// All eight (isGlobalFallback, tenant present, keepUsersGlobal) combinations. Only a global-fallback
// hit with a tenant and adoption allowed adopts. The callers dereference the tenant when this
// returns true, so a true without a tenant (fallback, no tenant, keep) would panic.
func TestShouldAdoptUserToTenant(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV4())

	cases := []struct {
		name             string
		isGlobalFallback bool
		tenantID         *uuid.UUID
		keepUsersGlobal  bool
		want             bool
	}{
		{"global fallback, tenant, adoption on -> adopt (legacy behaviour)", true, &tenantID, false, true},
		{"global fallback, tenant, keep-global -> do NOT adopt (org-switch)", true, &tenantID, true, false},
		{"global fallback, no tenant, adoption on -> never adopt", true, nil, false, false},
		{"global fallback, no tenant, keep-global -> never adopt", true, nil, true, false},
		{"tenant-scoped hit, tenant, adoption on -> never adopt", false, &tenantID, false, false},
		{"tenant-scoped hit, tenant, keep-global -> never adopt", false, &tenantID, true, false},
		{"tenant-scoped hit, no tenant, adoption on -> never adopt", false, nil, false, false},
		{"tenant-scoped hit, no tenant, keep-global -> never adopt", false, nil, true, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldAdoptUserToTenant(tc.isGlobalFallback, tc.tenantID, tc.keepUsersGlobal)
			if got != tc.want {
				t.Fatalf("shouldAdoptUserToTenant(%v, %v, %v) = %v, want %v",
					tc.isGlobalFallback, tc.tenantID != nil, tc.keepUsersGlobal, got, tc.want)
			}
		})
	}
}
