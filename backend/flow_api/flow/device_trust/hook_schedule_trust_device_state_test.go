package device_trust

import (
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/teamhanko/hanko/backend/v2/flow_api/flow/shared"
	"github.com/teamhanko/hanko/backend/v2/flowpilot"
)

type fakeScheduleCtx struct {
	*fakeIssueCookieCtx
	scheduled []flowpilot.StateName
}

func (f *fakeScheduleCtx) IsFlow(flowpilot.FlowName) bool { return false }

func (f *fakeScheduleCtx) ScheduleStates(names ...flowpilot.StateName) {
	f.scheduled = append(f.scheduled, names...)
}

func scheduleCtx(t *testing.T, tenantID *uuid.UUID) *fakeScheduleCtx {
	deps, _ := trustDeps("prompt", time.Hour, &fakeTrustedDevicePersister{}, "")
	deps.Cfg.MFA.Enabled = true
	deps.Cfg.MultiTenant.Enabled = true
	deps.Cfg.MultiTenant.AllowGlobalUsers = true
	deps.Cfg.MultiTenant.KeepUsersGlobal = true
	deps.TenantID = tenantID
	c := &fakeScheduleCtx{fakeIssueCookieCtx: newIssueCookieCtx(deps)}
	require.NoError(t, c.Stash().Set(shared.StashPathUserID, uuid.Must(uuid.NewV4()).String()))
	require.NoError(t, c.Stash().Set(shared.StashPathUserHasOTPSecret, true))
	return c
}

func TestScheduleTrustDeviceState_TenantlessGlobalFlowDoesNotPrompt(t *testing.T) {
	c := scheduleCtx(t, nil)
	require.NoError(t, (ScheduleTrustDeviceState{}).Execute(c))
	assert.Empty(t, c.scheduled, "IssueTrustDeviceCookie discards the answer for this flow, so it must not be asked")
}

func TestScheduleTrustDeviceState_TenantFlowStillPrompts(t *testing.T) {
	tenant := uuid.Must(uuid.NewV4())
	c := scheduleCtx(t, &tenant)
	require.NoError(t, (ScheduleTrustDeviceState{}).Execute(c))
	assert.Equal(t, []flowpilot.StateName{shared.StateDeviceTrust}, c.scheduled)
}
