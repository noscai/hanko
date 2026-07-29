package credential_usage

import (
	"net/http"
	"net/http/httptest"

	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	auditlog "github.com/teamhanko/hanko/backend/v2/audit_log"
	"github.com/teamhanko/hanko/backend/v2/flow_api/flow/shared"
	"github.com/teamhanko/hanko/backend/v2/flow_api/services"
	"github.com/teamhanko/hanko/backend/v2/flowpilot"
	"github.com/teamhanko/hanko/backend/v2/persistence"
	"github.com/teamhanko/hanko/backend/v2/persistence/models"
)

// Shared harness for the two login-flow action tests (action_password_login, action_continue_with_
// login_identifier). Same embed-and-override idiom as action_preauthenticated_continue_test.go:
// fakeLoginCtx embeds a real flowpilot.ExecutionContext (NewMockExecutionContext, which owns the
// unexported stash/payload/input types) and overrides only the capture methods these actions call.
// GetFlowID is overridden because the mock leaves flowModel nil (it would otherwise panic).

var testFlowID = uuid.Must(uuid.FromString("dddddddd-4444-4444-8444-dddddddddddd"))

type fakeLoginCtx struct {
	flowpilot.ExecutionContext
	deps *shared.Dependencies

	validInput      bool
	continued       bool
	continuedStates []flowpilot.StateName
	errored         bool
	capturedErr     flowpilot.FlowError
	preventRevert   bool
	hookErr         error
	hookCalled      bool
}

func (f *fakeLoginCtx) Get(key string) interface{} {
	if key == "deps" {
		return f.deps
	}
	return f.ExecutionContext.Get(key)
}

func (f *fakeLoginCtx) ValidateInputData() bool { return f.validInput }

func (f *fakeLoginCtx) Continue(states ...flowpilot.StateName) error {
	f.continued = true
	f.continuedStates = states
	return nil
}

func (f *fakeLoginCtx) Error(err flowpilot.FlowError) error {
	f.errored = true
	f.capturedErr = err
	return nil
}

func (f *fakeLoginCtx) PreventRevert() { f.preventRevert = true }

func (f *fakeLoginCtx) ExecuteHook(_ flowpilot.HookAction) error {
	f.hookCalled = true
	return f.hookErr
}

func (f *fakeLoginCtx) GetFlowID() uuid.UUID { return testFlowID }

func newLoginCtx(deps *shared.Dependencies, input map[string]interface{}) *fakeLoginCtx {
	return &fakeLoginCtx{
		ExecutionContext: flowpilot.NewMockExecutionContext(input),
		deps:             deps,
		validInput:       true,
	}
}

// firstContinuedState returns the state the action continued to, or "" if none / the default.
func (f *fakeLoginCtx) firstContinuedState() flowpilot.StateName {
	if len(f.continuedStates) == 0 {
		return ""
	}
	return f.continuedStates[0]
}

// --- fake persisters (only the methods the actions reach are real) ---

type fakeEmailPersister struct {
	persistence.EmailPersister
	email    *models.Email
	isGlobal bool
	err      error
}

func (f *fakeEmailPersister) FindByAddressWithTenantFallback(_ string, _ *uuid.UUID) (*models.Email, bool, error) {
	return f.email, f.isGlobal, f.err
}

type fakeUsernamePersister struct {
	persistence.UsernamePersister
	username *models.Username
	isGlobal bool
	err      error
}

func (f *fakeUsernamePersister) GetByNameWithTenantFallback(_ string, _ *uuid.UUID) (*models.Username, bool, error) {
	return f.username, f.isGlobal, f.err
}

type fakeLoginUserPersister struct {
	persistence.UserPersister
	user       *models.User
	getErr     error
	adoptErr   error
	adoptCalls int
}

func (f *fakeLoginUserPersister) Get(_ uuid.UUID) (*models.User, error) {
	return f.user, f.getErr
}

func (f *fakeLoginUserPersister) AdoptUserToTenant(_ uuid.UUID, _ uuid.UUID) error {
	f.adoptCalls++
	return f.adoptErr
}

type fakeLoginPersister struct {
	persistence.Persister
	emails    *fakeEmailPersister
	usernames *fakeUsernamePersister
	users     *fakeLoginUserPersister
}

func (f *fakeLoginPersister) GetEmailPersisterWithConnection(_ *pop.Connection) persistence.EmailPersister {
	return f.emails
}

func (f *fakeLoginPersister) GetUsernamePersisterWithConnection(_ *pop.Connection) persistence.UsernamePersister {
	return f.usernames
}

func (f *fakeLoginPersister) GetUserPersisterWithConnection(_ *pop.Connection) persistence.UserPersister {
	return f.users
}

type fakePasswordSvc struct {
	services.Password
	err error
}

func (f *fakePasswordSvc) VerifyPassword(_ *pop.Connection, _ uuid.UUID, _ string) error {
	return f.err
}

type fakeAuditLogger struct {
	auditlog.Logger
	err    error
	called bool
}

func (f *fakeAuditLogger) CreateWithConnection(_ *pop.Connection, _ echo.Context, _ models.AuditLogType, _ *models.User, _ error, _ ...auditlog.DetailOption) error {
	f.called = true
	return f.err
}

// loginDeps builds Dependencies wired with the fakes above. Multi-tenant is on with request tenant
// tenantA; rate limiting off; config is otherwise zero-valued and set per test.
func loginDeps() (*shared.Dependencies, *fakeLoginPersister, *fakePasswordSvc, *fakeAuditLogger) {
	e := echo.New()
	httpCtx := e.NewContext(httptest.NewRequest(http.MethodPost, "/", nil), httptest.NewRecorder())

	persister := &fakeLoginPersister{
		emails:    &fakeEmailPersister{},
		usernames: &fakeUsernamePersister{},
		users:     &fakeLoginUserPersister{},
	}
	pw := &fakePasswordSvc{}
	al := &fakeAuditLogger{}

	deps := &shared.Dependencies{
		HttpContext:     httpCtx,
		Persister:       persister,
		PasswordService: pw,
		AuditLogger:     al,
		TenantID:        &tenantA,
	}
	return deps, persister, pw, al
}

// userWithPrimaryEmail builds a user model that owns the given email address as its primary.
func userWithPrimaryEmail(id uuid.UUID, address string) *models.User {
	return &models.User{
		ID: id,
		Emails: models.Emails{
			models.Email{
				UserID:       &id,
				Address:      address,
				PrimaryEmail: &models.PrimaryEmail{ID: uuid.Must(uuid.NewV4())},
			},
		},
	}
}
