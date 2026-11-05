package credential_usage

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	auditlog "github.com/teamhanko/hanko/backend/v2/audit_log"
	"github.com/teamhanko/hanko/backend/v2/flow_api/flow/shared"
	"github.com/teamhanko/hanko/backend/v2/flow_api/services"
	"github.com/teamhanko/hanko/backend/v2/flowpilot"
	"github.com/teamhanko/hanko/backend/v2/persistence"
	"github.com/teamhanko/hanko/backend/v2/persistence/models"
	"golang.org/x/crypto/bcrypt"
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
	passwords fakePasswordCredentials
}

func (f *fakeLoginPersister) GetPasswordCredentialPersisterWithConnection(_ *pop.Connection) persistence.PasswordCredentialPersister {
	return f.passwords
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
	err         error
	verifiedFor uuid.UUID
}

func (f *fakePasswordSvc) VerifyPassword(_ *pop.Connection, userID uuid.UUID, _ string) error {
	f.verifiedFor = userID
	return f.err
}

// fakePasswordCredentials is the password_credentials table the real password service reads.
type fakePasswordCredentials struct {
	persistence.PasswordCredentialPersister
	byUser map[uuid.UUID]*models.PasswordCredential
}

func (f fakePasswordCredentials) GetByUserID(id uuid.UUID) (*models.PasswordCredential, error) {
	return f.byUser[id], nil
}

// knownPassword is the password whose bcrypt hash withRealPasswordCheck stores for the user.
const knownPassword = "secret"

// withRealPasswordCheck replaces the fake password service with the real one, reading a password
// credential that holds the bcrypt hash of knownPassword for id, so a test proves the password is
// actually checked against that user rather than that a fake was called.
func withRealPasswordCheck(t *testing.T, deps *shared.Dependencies, id uuid.UUID) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(knownPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash the known password: %v", err)
	}
	passwords := fakePasswordCredentials{byUser: map[uuid.UUID]*models.PasswordCredential{
		id: {ID: uuid.Must(uuid.NewV4()), UserId: id, Password: string(hash)},
	}}
	switch p := deps.Persister.(type) {
	case *fakeLoginPersister:
		p.passwords = passwords
	case *tenantBoundPersister:
		p.passwords = passwords
	default:
		t.Fatalf("withRealPasswordCheck: unsupported persister %T", deps.Persister)
	}
	deps.PasswordService = services.NewPasswordService(deps.Persister)
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

// --- stateful tenant fakes: one user row seen from several tenants (archon#1085 6.2 #19) ---

// tenantBoundUsers holds the one user row the stateful email fake reads. AdoptUserToTenant binds
// it like the real conditional UPDATE (... WHERE tenant_id IS NULL).
type tenantBoundUsers struct {
	persistence.UserPersister
	user       *models.User
	adoptCalls int
}

func (f *tenantBoundUsers) Get(_ uuid.UUID) (*models.User, error) { return f.user, nil }

func (f *tenantBoundUsers) AdoptUserToTenant(_ uuid.UUID, tenantID uuid.UUID) error {
	f.adoptCalls++
	if f.user.TenantID == nil {
		t := tenantID
		f.user.TenantID = &t
	}
	return nil
}

// tenantBoundEmails mirrors FindByAddressWithTenantFallback against that row: a global row matches
// any tenant as the global fallback, a bound row matches only its own tenant, so once the user is
// adopted the fallback stops matching for every other tenant.
type tenantBoundEmails struct {
	persistence.EmailPersister
	users   *tenantBoundUsers
	address string
}

func (f *tenantBoundEmails) FindByAddressWithTenantFallback(address string, tenantID *uuid.UUID) (*models.Email, bool, error) {
	user := f.users.user
	if address != f.address {
		return nil, false, nil
	}
	email := &models.Email{UserID: &user.ID, Address: address, TenantID: user.TenantID}
	switch {
	case user.TenantID == nil:
		return email, tenantID != nil, nil
	case tenantID != nil && *user.TenantID == *tenantID:
		return email, false, nil
	default:
		return nil, false, nil
	}
}

type tenantBoundPersister struct {
	persistence.Persister
	emails    *tenantBoundEmails
	users     *tenantBoundUsers
	passwords fakePasswordCredentials
}

func (f *tenantBoundPersister) GetPasswordCredentialPersisterWithConnection(_ *pop.Connection) persistence.PasswordCredentialPersister {
	return f.passwords
}

func (f *tenantBoundPersister) GetEmailPersisterWithConnection(_ *pop.Connection) persistence.EmailPersister {
	return f.emails
}

func (f *tenantBoundPersister) GetUserPersisterWithConnection(_ *pop.Connection) persistence.UserPersister {
	return f.users
}

// withGlobalUser swaps deps' persister for the stateful fakes, seeded with one global user who owns
// address, and returns the row so a test can watch its tenant.
func withGlobalUser(deps *shared.Dependencies, address string) *tenantBoundUsers {
	users := &tenantBoundUsers{user: &models.User{ID: userID}}
	deps.Persister = &tenantBoundPersister{
		emails: &tenantBoundEmails{users: users, address: address},
		users:  users,
	}
	return users
}
