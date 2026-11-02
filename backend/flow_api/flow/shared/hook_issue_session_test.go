package shared

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/teamhanko/hanko/backend/v2/config"
	"github.com/teamhanko/hanko/backend/v2/flowpilot"
	"github.com/teamhanko/hanko/backend/v2/persistence"
	"github.com/teamhanko/hanko/backend/v2/persistence/models"
	"github.com/teamhanko/hanko/backend/v2/session"
	"github.com/teamhanko/hanko/backend/v2/test"
)

// These tests drive the real IssueSession hook with a real session manager, fake user and session
// persisters and the flowpilot mock context: no Postgres. They prove the wiring between the flow
// tenant and the session JWT (archon#1085 Q18): a kept-global user's issued session names the
// tenant the flow runs under. WithFlowTenant's own rule is covered in session/session_test.go.

var issueSessionUserID = uuid.FromStringOrNil("cccccccc-3333-4333-8333-cccccccccccc")

type fakeIssueSessionUsers struct {
	persistence.UserPersister
	user *models.User
}

func (f *fakeIssueSessionUsers) Get(uuid.UUID) (*models.User, error) { return f.user, nil }

type fakeIssueSessionSessions struct {
	persistence.SessionPersister
	created []models.Session
}

func (f *fakeIssueSessionSessions) ListActive(uuid.UUID) ([]models.Session, error) { return nil, nil }

func (f *fakeIssueSessionSessions) Create(s models.Session) error {
	f.created = append(f.created, s)
	return nil
}

type fakeIssueSessionPersister struct {
	persistence.Persister
	users    *fakeIssueSessionUsers
	sessions *fakeIssueSessionSessions
}

func (f *fakeIssueSessionPersister) GetUserPersisterWithConnection(*pop.Connection) persistence.UserPersister {
	return f.users
}

func (f *fakeIssueSessionPersister) GetSessionPersisterWithConnection(*pop.Connection) persistence.SessionPersister {
	return f.sessions
}

type fakeIssueSessionCtx struct {
	flowpilot.HookExecutionContext
	deps *Dependencies
}

func (f *fakeIssueSessionCtx) Get(key string) interface{} {
	if key == "deps" {
		return f.deps
	}
	return f.HookExecutionContext.Get(key)
}

// IsFlow is false for every flow, which skips the login audit log: it is not under test here.
func (f *fakeIssueSessionCtx) IsFlow(flowpilot.FlowName) bool { return false }

// issueSession runs IssueSession for user under requestTenant (X-Tenant-ID), after pin, and
// returns the tenant_id claim of the session JWT it issued, if any.
func issueSession(t *testing.T, user *models.User, requestTenant *uuid.UUID, pin func(ctx *fakeIssueSessionCtx)) (interface{}, bool) {
	t.Helper()

	cfg := config.Config{}
	cfg.Session.Lifespan = "5m"
	cfg.Session.Limit = 5
	cfg.Session.EnableAuthTokenHeader = true
	manager, err := session.NewManager(&test.JwkManager{}, cfg)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	ctx := &fakeIssueSessionCtx{
		HookExecutionContext: flowpilot.NewMockHookExecutionContext(),
		deps: &Dependencies{
			Cfg:            cfg,
			HttpContext:    echo.New().NewContext(httptest.NewRequest(http.MethodPost, "/", nil), rec),
			SessionManager: manager,
			TenantID:       requestTenant,
			Persister: &fakeIssueSessionPersister{
				users:    &fakeIssueSessionUsers{user: user},
				sessions: &fakeIssueSessionSessions{},
			},
		},
	}
	require.NoError(t, ctx.Stash().Set(StashPathUserID, user.ID.String()))
	if pin != nil {
		pin(ctx)
	}

	require.NoError(t, IssueSession{}.Execute(ctx))

	signed := rec.Header().Get("X-Auth-Token")
	require.NotEmpty(t, signed, "the hook must issue a session token")
	token, err := jwt.ParseString(signed, jwt.WithVerify(false))
	require.NoError(t, err)

	return token.Get("tenant_id")
}

func TestIssueSession_KeptGlobalUserSessionNamesThePinnedFlowTenant(t *testing.T) {
	user := &models.User{ID: issueSessionUserID}

	tenant, ok := issueSession(t, user, &flowTenantA, func(ctx *fakeIssueSessionCtx) {
		require.NoError(t, PinFlowTenantID(ctx.Stash(), &flowTenantB))
	})

	require.True(t, ok, "a kept-global user's session must name a tenant")
	assert.Equal(t, flowTenantB.String(), tenant,
		"the session names the tenant the flow is pinned to, not a later request's header")
}

func TestIssueSession_KeptGlobalUserSessionNamesTheRequestTenantOfAnUnpinnedFlow(t *testing.T) {
	user := &models.User{ID: issueSessionUserID}

	tenant, ok := issueSession(t, user, &flowTenantA, nil)

	require.True(t, ok)
	assert.Equal(t, flowTenantA.String(), tenant)
}

func TestIssueSession_AdoptedUserSessionKeepsTheUsersTenant(t *testing.T) {
	user := &models.User{ID: issueSessionUserID, TenantID: &flowTenantA}

	tenant, ok := issueSession(t, user, &flowTenantA, func(ctx *fakeIssueSessionCtx) {
		require.NoError(t, PinFlowTenantID(ctx.Stash(), &flowTenantB))
	})

	require.True(t, ok)
	assert.Equal(t, flowTenantA.String(), tenant, "the flow tenant never replaces the user's own tenant")
}

func TestIssueSession_GlobalUserInAFlowWithoutTenantGetsNoTenantClaim(t *testing.T) {
	user := &models.User{ID: issueSessionUserID}

	_, ok := issueSession(t, user, nil, nil)

	assert.False(t, ok)
}
