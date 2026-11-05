package models

import (
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
)

// archon#1085 6.2 #20. One Hanko user now signs in to several clinics, so device trust is recorded
// per clinic (Q15): a browser trusted while signing in to clinic A must not skip clinic B's second
// factor. Before this change trust was matched by device token and user only, so it did.
func TestTrustedDevice_MatchesTenant(t *testing.T) {
	tenantA := uuid.FromStringOrNil("aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa")
	tenantB := uuid.FromStringOrNil("bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb")
	sameAsA := uuid.FromStringOrNil(tenantA.String())

	tests := []struct {
		name       string
		rowTenant  *uuid.UUID
		flowTenant *uuid.UUID
		want       bool
	}{
		{"trust under A answers a flow under A", &tenantA, &sameAsA, true},
		{"trust under A does not answer a flow under B", &tenantA, &tenantB, false},
		{"trust under A does not answer a flow without a tenant", &tenantA, nil, false},
		{"a legacy row answers a flow without a tenant", nil, nil, true},
		{"a legacy row does not answer a flow under a tenant", nil, &tenantA, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			row := TrustedDevice{TenantID: tc.rowTenant}
			assert.Equal(t, tc.want, row.MatchesTenant(tc.flowTenant))
		})
	}
}
