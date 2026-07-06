package credential_usage

import (
	"testing"

	"github.com/gofrs/uuid"
)

func TestShouldAdoptUserToTenant(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV4())

	cases := []struct {
		name             string
		isGlobalFallback bool
		tenantID         *uuid.UUID
		keepUsersGlobal  bool
		want             bool
	}{
		{
			name:             "global fallback with tenant, adoption enabled -> adopt (legacy behaviour)",
			isGlobalFallback: true,
			tenantID:         &tenantID,
			keepUsersGlobal:  false,
			want:             true,
		},
		{
			name:             "global fallback with tenant, keep-global -> do NOT adopt (org-switch)",
			isGlobalFallback: true,
			tenantID:         &tenantID,
			keepUsersGlobal:  true,
			want:             false,
		},
		{
			name:             "tenant-scoped hit (not global fallback) -> never adopt",
			isGlobalFallback: false,
			tenantID:         &tenantID,
			keepUsersGlobal:  false,
			want:             false,
		},
		{
			name:             "no tenant context -> never adopt",
			isGlobalFallback: true,
			tenantID:         nil,
			keepUsersGlobal:  false,
			want:             false,
		},
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
