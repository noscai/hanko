package credential_usage

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sethvargo/go-limiter/memorystore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/teamhanko/hanko/backend/v2/config"
	"github.com/teamhanko/hanko/backend/v2/flow_api/flow/shared"
	"github.com/teamhanko/hanko/backend/v2/flowpilot"
	"github.com/teamhanko/hanko/backend/v2/persistence"
	"github.com/teamhanko/hanko/backend/v2/persistence/models"
	"github.com/teamhanko/hanko/backend/v2/rate_limiter"
)

// These tests drive the real PreAuthenticatedContinue.Execute -- the archon#1668 tenant-boundary
// enforcement path -- through a fake flowpilot ExecutionContext, with no Postgres and no FlowDB.
//
// The fake is the embed-and-override idiom: it embeds a real flowpilot.ExecutionContext (built by
// flowpilot.NewMockExecutionContext, which owns the unexported stash / payload / input types) and
// overrides ONLY the capture methods the action calls whose signatures are expressible outside
// flowpilot -- Get (inject deps), Continue / Error (capture the accept-vs-reject decision), and
// PreventRevert. Stash() / Payload() / Input() are inherited from the real backing, so stash writes
// and the payload are observable exactly as the action performs them.

// fakePreAuthUserPersister satisfies persistence.UserPersister via embedding; only the two methods
// resolveServiceTokenUser reaches through -- Get and AdoptUserToTenant -- are real.
type fakePreAuthUserPersister struct {
	persistence.UserPersister
	user       *models.User
	getErr     error
	adoptCalls int
}

func (f *fakePreAuthUserPersister) Get(id uuid.UUID) (*models.User, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.user, nil
}

func (f *fakePreAuthUserPersister) AdoptUserToTenant(userID uuid.UUID, tenantID uuid.UUID) error {
	f.adoptCalls++
	if f.user != nil && f.user.TenantID == nil {
		t := tenantID
		f.user.TenantID = &t
	}
	return nil
}

// fakePreAuthPersister satisfies persistence.Persister via embedding; only the accessor the action
// calls -- GetUserPersisterWithConnection -- is real.
type fakePreAuthPersister struct {
	persistence.Persister
	users persistence.UserPersister
}

func (f *fakePreAuthPersister) GetUserPersisterWithConnection(_ *pop.Connection) persistence.UserPersister {
	return f.users
}

// fakePreAuthCtx captures the action's accept-vs-reject decision.
type fakePreAuthCtx struct {
	flowpilot.ExecutionContext
	deps *shared.Dependencies

	continued           bool
	continuedStates     []flowpilot.StateName
	errored             bool
	capturedErr         flowpilot.FlowError
	preventRevertCalled bool
}

func (f *fakePreAuthCtx) Get(key string) interface{} {
	if key == "deps" {
		return f.deps
	}
	return f.ExecutionContext.Get(key)
}

func (f *fakePreAuthCtx) Continue(states ...flowpilot.StateName) error {
	f.continued = true
	f.continuedStates = states
	return nil
}

func (f *fakePreAuthCtx) Error(err flowpilot.FlowError) error {
	f.errored = true
	f.capturedErr = err
	return nil
}

func (f *fakePreAuthCtx) PreventRevert() { f.preventRevertCalled = true }

// fakeInitCtx covers Initialize, which calls only Get, SuspendAction and AddInputs -- all with
// exported-only signatures -- so the embedded InitializationContext can stay nil (never
// dereferenced) and every called method is overridden.
type fakeInitCtx struct {
	flowpilot.InitializationContext
	deps        *shared.Dependencies
	suspended   bool
	addedInputs []flowpilot.Input
}

func (f *fakeInitCtx) Get(key string) interface{} {
	if key == "deps" {
		return f.deps
	}
	return nil
}

func (f *fakeInitCtx) SuspendAction() { f.suspended = true }

func (f *fakeInitCtx) AddInputs(inputs ...flowpilot.Input) {
	f.addedInputs = append(f.addedInputs, inputs...)
}

func newPreAuthCtx(token string, deps *shared.Dependencies) *fakePreAuthCtx {
	backing := flowpilot.NewMockExecutionContext(map[string]interface{}{"service_token": token})
	return &fakePreAuthCtx{ExecutionContext: backing, deps: deps}
}

// preAuthDeps wires the Dependencies the action reads. Rate limiting is off by default; multi-tenant
// is on with request tenant = tenantA.
func preAuthDeps(user *models.User) (*shared.Dependencies, *fakePreAuthUserPersister) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	httpCtx := e.NewContext(req, rec)

	cfg := config.Config{}
	cfg.ServiceToken.Secret = testSecret
	cfg.ServiceToken.Issuer = testIssuer
	cfg.MultiTenant = multiTenantOn()
	cfg.RateLimiter.Enabled = false

	users := &fakePreAuthUserPersister{user: user}
	deps := &shared.Dependencies{
		Cfg:         cfg,
		HttpContext: httpCtx,
		Persister:   &fakePreAuthPersister{users: users},
		TenantID:    &tenantA,
	}
	return deps, users
}

// Happy path: a valid service token whose claimed tenant matches both the request tenant and the
// resolved user's tenant continues the flow and seeds trusted identity into the stash.
func TestPreAuthenticatedContinue_Execute_AcceptsUserInClaimedTenant(t *testing.T) {
	user := &models.User{
		ID:       userID,
		TenantID: &tenantA,
		Emails: models.Emails{
			models.Email{
				Address:      "user@example.com",
				PrimaryEmail: &models.PrimaryEmail{ID: uuid.Must(uuid.NewV4())},
			},
		},
	}
	deps, _ := preAuthDeps(user)
	token := mintToken(t, testSecret, testIssuer, userID.String(), tenantA.String(), time.Hour)
	ctx := newPreAuthCtx(token, deps)

	err := PreAuthenticatedContinue{}.Execute(ctx)

	require.NoError(t, err)
	assert.True(t, ctx.continued, "a valid same-tenant service token must continue the flow")
	assert.False(t, ctx.errored)
	assert.True(t, ctx.preventRevertCalled, "the pre-authenticated identity must not be revertible")
	assert.Equal(t, userID.String(), ctx.Stash().Get(shared.StashPathUserID).String(),
		"the resolved user id must be seeded into the stash")
	assert.Equal(t, "user@example.com", ctx.Stash().Get(shared.StashPathEmail).String(),
		"the primary email must be seeded into the stash")
	assert.Equal(t, "preauthenticated", ctx.Stash().Get(shared.StashPathLoginMethod).String())
}

// archon#1668: the service token claims (and the request carries) tenantA, but the resolved user
// row belongs to tenantB. Before the boundary landed, the flow seeded trusted identity for that
// foreign user. The action must reject via c.Error and NEVER continue or seed the stash.
//
// This is the guarded invariant. Bypassing the tenant arg on resolveServiceTokenUser (the §6.2 #1
// mutation) turns this test red.
func TestPreAuthenticatedContinue_Execute_RejectsUserFromAnotherTenant(t *testing.T) {
	deps, _ := preAuthDeps(&models.User{ID: userID, TenantID: &tenantB})
	token := mintToken(t, testSecret, testIssuer, userID.String(), tenantA.String(), time.Hour)
	ctx := newPreAuthCtx(token, deps)

	err := PreAuthenticatedContinue{}.Execute(ctx)

	require.NoError(t, err)
	assert.True(t, ctx.errored, "a foreign-tenant user must be rejected")
	assert.False(t, ctx.continued, "the flow must NOT continue for a foreign-tenant user")
	require.NotNil(t, ctx.capturedErr)
	assert.False(t, ctx.Stash().Get(shared.StashPathUserID).Exists(),
		"no trusted identity may be seeded for a rejected user")
}

// A malformed service token is rejected before any user is resolved.
func TestPreAuthenticatedContinue_Execute_RejectsInvalidServiceToken(t *testing.T) {
	deps, _ := preAuthDeps(&models.User{ID: userID, TenantID: &tenantA})
	ctx := newPreAuthCtx("not-a-valid-jwt", deps)

	err := PreAuthenticatedContinue{}.Execute(ctx)

	require.NoError(t, err)
	assert.True(t, ctx.errored)
	assert.False(t, ctx.continued)
	assert.False(t, ctx.Stash().Get(shared.StashPathUserID).Exists())
}

// The rate-limit branch: when the service-token limiter is exhausted for this IP, the action
// rejects and records retry_after on the payload before returning.
func TestPreAuthenticatedContinue_Execute_RejectsWhenRateLimited(t *testing.T) {
	deps, _ := preAuthDeps(&models.User{ID: userID, TenantID: &tenantA})
	deps.Cfg.RateLimiter.Enabled = true

	store, err := memorystore.New(&memorystore.Config{Tokens: 1, Interval: time.Minute})
	require.NoError(t, err)
	deps.ServiceTokenRateLimiter = store

	// Exhaust the single token for this IP's key so the action's own Limit2 call is denied.
	key := rate_limiter.CreateRateLimitServiceTokenKey(deps.HttpContext.RealIP())
	_, ok, err := rate_limiter.Limit2(store, key)
	require.NoError(t, err)
	require.True(t, ok)

	token := mintToken(t, testSecret, testIssuer, userID.String(), tenantA.String(), time.Hour)
	ctx := newPreAuthCtx(token, deps)

	err = PreAuthenticatedContinue{}.Execute(ctx)

	require.NoError(t, err)
	assert.True(t, ctx.errored, "a rate-limited request must be rejected")
	assert.False(t, ctx.continued)
	assert.True(t, ctx.Payload().Get("retry_after").Exists(),
		"retry_after must be recorded on the payload when rate limited")
}

// A global user (tenant_id IS NULL) under allow_global_users is adopted into the claimed tenant and
// the flow continues -- the production configuration for legacy users.
func TestPreAuthenticatedContinue_Execute_AdoptsGlobalUser(t *testing.T) {
	deps, users := preAuthDeps(&models.User{ID: userID, TenantID: nil})
	token := mintToken(t, testSecret, testIssuer, userID.String(), tenantA.String(), time.Hour)
	ctx := newPreAuthCtx(token, deps)

	err := PreAuthenticatedContinue{}.Execute(ctx)

	require.NoError(t, err)
	assert.True(t, ctx.continued)
	assert.False(t, ctx.errored)
	assert.Equal(t, 1, users.adoptCalls, "a global user must be adopted into the claimed tenant")
}

func TestPreAuthenticatedContinue_Metadata(t *testing.T) {
	a := PreAuthenticatedContinue{}
	assert.Equal(t, shared.ActionPreAuthenticatedContinue, a.GetName())
	assert.NotEmpty(t, a.GetDescription())
}

// Initialize suspends the action when no service-token secret is configured (the feature is off).
func TestPreAuthenticatedContinue_Initialize_SuspendsWhenNoSecret(t *testing.T) {
	ctx := &fakeInitCtx{deps: &shared.Dependencies{Cfg: config.Config{}}}

	PreAuthenticatedContinue{}.Initialize(ctx)

	assert.True(t, ctx.suspended, "the action must suspend when no secret is configured")
	assert.Empty(t, ctx.addedInputs)
}

// Initialize registers the service_token input when a secret is configured.
func TestPreAuthenticatedContinue_Initialize_AddsInputWhenSecretSet(t *testing.T) {
	cfg := config.Config{}
	cfg.ServiceToken.Secret = testSecret
	ctx := &fakeInitCtx{deps: &shared.Dependencies{Cfg: cfg}}

	PreAuthenticatedContinue{}.Initialize(ctx)

	assert.False(t, ctx.suspended)
	require.Len(t, ctx.addedInputs, 1, "the service_token input must be registered")
}
