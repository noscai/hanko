package login

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/teamhanko/hanko/backend/v2/config"
	"github.com/teamhanko/hanko/backend/v2/flow_api/flow/shared"
	"github.com/teamhanko/hanko/backend/v2/flow_api/services"
	"github.com/teamhanko/hanko/backend/v2/flowpilot"
	"github.com/teamhanko/hanko/backend/v2/persistence"
	"github.com/teamhanko/hanko/backend/v2/persistence/models"
)

// These tests drive the login flow's real trust decision (ScheduleOnboardingStates, which asks
// DeviceTrustService whether the second factor may be skipped) with a fake flowpilot context and
// an in-memory trust store: no Postgres. archon#1085 6.2 #20 at the flow level: trust recorded
// while signing in to clinic A must not skip clinic B's code, and the tenant the decision was made
// under is pinned for the request that later writes the trust row and issues the session.

var (
	onboardingTenantA = uuid.FromStringOrNil("aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa")
	onboardingTenantB = uuid.FromStringOrNil("bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb")
	onboardingUserID  = uuid.FromStringOrNil("cccccccc-3333-4333-8333-cccccccccccc")
	onboardingToken   = strings.Repeat("t", 64)
)

const onboardingDeviceCookie = "clinicos-2fa-device-id"

// trustStore is the trust table: FindValidTrust filters as the real persister's SQL does.
type trustStore struct {
	rows []models.TrustedDevice
}

func (s *trustStore) Create(td models.TrustedDevice) error {
	s.rows = append(s.rows, td)
	return nil
}

func (s *trustStore) FindByDeviceToken(token string) (*models.TrustedDevice, error) {
	for i := range s.rows {
		if s.rows[i].DeviceToken == token {
			return &s.rows[i], nil
		}
	}
	return nil, nil
}

func (s *trustStore) FindValidTrust(token string, userID uuid.UUID, tenantID *uuid.UUID, now time.Time) (*models.TrustedDevice, error) {
	for i := range s.rows {
		row := s.rows[i]
		if row.DeviceToken == token && row.UserID == userID && row.MatchesTenant(tenantID) && row.ExpiresAt.After(now) {
			return &row, nil
		}
	}
	return nil, nil
}

func (s *trustStore) DeleteByUserID(uuid.UUID) error { return nil }

type fakeOnboardingPersister struct {
	persistence.Persister
	trust persistence.TrustedDevicePersister
}

func (f *fakeOnboardingPersister) GetTrustedDevicePersisterWithConnection(_ *pop.Connection) persistence.TrustedDevicePersister {
	return f.trust
}

// fakeOnboardingCtx overrides the flow-graph methods the hook calls, which the mock backing cannot
// serve without a flow, and records the states it schedules.
type fakeOnboardingCtx struct {
	flowpilot.HookExecutionContext
	deps      *shared.Dependencies
	scheduled []flowpilot.StateName
}

func (f *fakeOnboardingCtx) Get(key string) interface{} {
	if key == "deps" {
		return f.deps
	}
	return f.HookExecutionContext.Get(key)
}

func (f *fakeOnboardingCtx) ScheduleStates(states ...flowpilot.StateName) {
	f.scheduled = append(f.scheduled, states...)
}

func (f *fakeOnboardingCtx) ExecuteHook(hook flowpilot.HookAction) error {
	return hook.Execute(f)
}

func (f *fakeOnboardingCtx) IsFlow(name flowpilot.FlowName) bool {
	return name == shared.FlowLogin
}

// newOnboardingCtx is a password login of a user with a TOTP secret, on a browser that carries the
// device cookie, sending requestTenant as X-Tenant-ID. trustedUnder is the tenant the browser's
// trust row was recorded under.
func newOnboardingCtx(t *testing.T, requestTenant *uuid.UUID, trustedUnder *uuid.UUID) *fakeOnboardingCtx {
	t.Helper()

	cfg := config.Config{}
	cfg.MFA.Enabled = true
	cfg.MFA.TOTP.Enabled = true
	cfg.MFA.DeviceTrustPolicy = "prompt"
	cfg.MFA.DeviceTrustIDCookieName = onboardingDeviceCookie
	cfg.MFA.DeviceTrustDuration = time.Hour

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(&http.Cookie{Name: onboardingDeviceCookie, Value: services.FormatDeviceIDCookie(onboardingToken)})

	store := &trustStore{rows: []models.TrustedDevice{{
		ID:          uuid.Must(uuid.NewV4()),
		UserID:      onboardingUserID,
		TenantID:    trustedUnder,
		DeviceToken: onboardingToken,
		ExpiresAt:   time.Now().Add(time.Hour).UTC(),
	}}}

	ctx := &fakeOnboardingCtx{
		HookExecutionContext: flowpilot.NewMockHookExecutionContext(),
		deps: &shared.Dependencies{
			Cfg:         cfg,
			HttpContext: echo.New().NewContext(req, httptest.NewRecorder()),
			Persister:   &fakeOnboardingPersister{trust: store},
			TenantID:    requestTenant,
		},
	}
	require.NoError(t, ctx.Stash().Set(shared.StashPathUserID, onboardingUserID.String()))
	require.NoError(t, ctx.Stash().Set(shared.StashPathUserHasOTPSecret, true))
	require.NoError(t, ctx.Stash().Set(shared.StashPathLoginMethod, "password"))
	return ctx
}

func TestScheduleOnboardingStates_TrustUnderFlowTenantSkipsOTP(t *testing.T) {
	ctx := newOnboardingCtx(t, &onboardingTenantA, &onboardingTenantA)

	require.NoError(t, ScheduleOnboardingStates{}.Execute(ctx))

	assert.NotContains(t, ctx.scheduled, shared.StateLoginOTP, "trust recorded under A must skip A's code")
	assert.NotContains(t, ctx.scheduled, shared.StateDeviceTrust, "an already trusted browser is not asked to trust again")
	assert.Equal(t, &onboardingTenantA, shared.FlowTenantID(ctx.Stash(), &onboardingTenantB),
		"the tenant the trust was decided under must be pinned for the rest of the flow")
}

func TestScheduleOnboardingStates_TrustUnderAnotherTenantDoesNotSkipOTP(t *testing.T) {
	ctx := newOnboardingCtx(t, &onboardingTenantB, &onboardingTenantA)

	require.NoError(t, ScheduleOnboardingStates{}.Execute(ctx))

	assert.Contains(t, ctx.scheduled, shared.StateLoginOTP, "trust recorded under A must not skip B's code")
	assert.Contains(t, ctx.scheduled, shared.StateDeviceTrust, "the browser may then be trusted for B")
	assert.Equal(t, &onboardingTenantB, shared.FlowTenantID(ctx.Stash(), &onboardingTenantA),
		"a later request's header must not move the flow to the clinic the browser is trusted for")
}

// A pre-authenticated flow is pinned to its service token's tenant before this hook runs; a header
// naming the clinic the browser is trusted for does not move it there.
func TestScheduleOnboardingStates_KeepsAPreAuthenticatedFlowsPin(t *testing.T) {
	ctx := newOnboardingCtx(t, &onboardingTenantA, &onboardingTenantA)
	require.NoError(t, shared.PinFlowTenantID(ctx.Stash(), &onboardingTenantB))

	require.NoError(t, ScheduleOnboardingStates{}.Execute(ctx))

	assert.Contains(t, ctx.scheduled, shared.StateLoginOTP)
	assert.Equal(t, &onboardingTenantB, shared.FlowTenantID(ctx.Stash(), &onboardingTenantA))
}
