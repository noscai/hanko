package shared

import (
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/teamhanko/hanko/backend/v2/flowpilot"
)

var (
	flowTenantA = uuid.FromStringOrNil("aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa")
	flowTenantB = uuid.FromStringOrNil("bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb")
)

// The flow tenant is what device trust is created and matched under and what a global user's
// session names (archon#1085 Q15, Q18). X-Tenant-ID is a client header sent on every request of a
// flow, so it is only the flow tenant until the flow pins one: from then on a later request cannot
// move the flow to another clinic by sending another header.
func TestFlowTenantID(t *testing.T) {
	t.Run("an unpinned flow runs under the request tenant", func(t *testing.T) {
		stash := flowpilot.NewMockHookExecutionContext().Stash()

		assert.Equal(t, &flowTenantA, FlowTenantID(stash, &flowTenantA))
		assert.Nil(t, FlowTenantID(stash, nil))
	})

	t.Run("a pinned tenant outlives a later request's header", func(t *testing.T) {
		stash := flowpilot.NewMockHookExecutionContext().Stash()
		require.NoError(t, PinFlowTenantID(stash, &flowTenantB))

		assert.Equal(t, &flowTenantB, FlowTenantID(stash, &flowTenantA))
		assert.Equal(t, &flowTenantB, FlowTenantID(stash, nil))
	})

	t.Run("a flow pinned without a tenant stays without one", func(t *testing.T) {
		stash := flowpilot.NewMockHookExecutionContext().Stash()
		require.NoError(t, PinFlowTenantID(stash, nil))

		assert.Nil(t, FlowTenantID(stash, &flowTenantA))
	})
}
