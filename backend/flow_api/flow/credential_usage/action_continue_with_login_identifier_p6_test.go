package credential_usage

import (
	"errors"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/teamhanko/hanko/backend/v2/config"
	saml "github.com/teamhanko/hanko/backend/v2/ee/saml"
	samlprovider "github.com/teamhanko/hanko/backend/v2/ee/saml/provider"
	"github.com/teamhanko/hanko/backend/v2/flow_api/flow/shared"
	"github.com/teamhanko/hanko/backend/v2/flow_api/services"
	"github.com/teamhanko/hanko/backend/v2/persistence/models"
)

// fakeSamlProvider is a non-nil ServiceProvider; the action only checks it for nil and hands it to
// GetAuthUrl (faked on fakeSamlService), so none of its methods are ever invoked.
type fakeSamlProvider struct {
	samlprovider.ServiceProvider
}

// fakeSamlService fakes only the two methods the email SAML branch reaches.
type fakeSamlService struct {
	saml.Service
	provider   samlprovider.ServiceProvider
	getURLErr  error
	authURL    string
}

func (f *fakeSamlService) GetProviderByDomain(_ string) (samlprovider.ServiceProvider, error) {
	return f.provider, nil
}

func (f *fakeSamlService) GetAuthUrl(_ samlprovider.ServiceProvider, _ string, _ bool) (string, error) {
	if f.getURLErr != nil {
		return "", f.getURLErr
	}
	return f.authURL, nil
}

// fakeWebauthnSvc fakes only GenerateRequestOptionsPasskey (the passkeys-available branch).
type fakeWebauthnSvc struct {
	services.WebauthnService
	err error
}

func (f *fakeWebauthnSvc) GenerateRequestOptionsPasskey(_ services.GenerateRequestOptionsPasskeyParams) (*models.WebauthnSessionData, *protocol.CredentialAssertion, error) {
	if f.err != nil {
		return nil, nil, f.err
	}
	return &models.WebauthnSessionData{ID: uuid.Must(uuid.NewV4())}, &protocol.CredentialAssertion{}, nil
}

func userWithPasskey(id uuid.UUID) *models.User {
	return &models.User{
		ID:                  id,
		WebauthnCredentials: models.WebauthnCredentials{models.WebauthnCredential{MFAOnly: false}},
	}
}

// loginIdentifierCfg turns on email+username as login identifiers, password auth and email-for-auth
// -- the fully-enabled baseline; individual tests narrow it.
func loginIdentifierCfg() config.Config {
	cfg := config.Config{}
	cfg.Email.Enabled = true
	cfg.Email.UseAsLoginIdentifier = true
	cfg.Email.UseForAuthentication = true
	cfg.Username.Enabled = true
	cfg.Username.UseAsLoginIdentifier = true
	cfg.Password.Enabled = true
	return cfg
}

func TestContinueWithLoginIdentifier_Metadata(t *testing.T) {
	a := ContinueWithLoginIdentifier{}
	assert.Equal(t, shared.ActionContinueWithLoginIdentifier, a.GetName())
	assert.NotEmpty(t, a.GetDescription())
}

func TestContinueWithLoginIdentifier_Initialize(t *testing.T) {
	// Both identifiers + password -> "identifier" input registered, active.
	both := &fakeInitCtx{deps: &shared.Dependencies{Cfg: loginIdentifierCfg()}}
	ContinueWithLoginIdentifier{}.Initialize(both)
	assert.False(t, both.suspended)
	require.Len(t, both.addedInputs, 1)

	// Email only.
	emailCfg := loginIdentifierCfg()
	emailCfg.Username.UseAsLoginIdentifier = false
	emailOnly := &fakeInitCtx{deps: &shared.Dependencies{Cfg: emailCfg}}
	ContinueWithLoginIdentifier{}.Initialize(emailOnly)
	assert.False(t, emailOnly.suspended)
	require.Len(t, emailOnly.addedInputs, 1)

	// Username only.
	usernameCfg := loginIdentifierCfg()
	usernameCfg.Email.UseAsLoginIdentifier = false
	usernameOnly := &fakeInitCtx{deps: &shared.Dependencies{Cfg: usernameCfg}}
	ContinueWithLoginIdentifier{}.Initialize(usernameOnly)
	assert.False(t, usernameOnly.suspended)
	require.Len(t, usernameOnly.addedInputs, 1)

	// Neither identifier -> suspended, no input.
	noneCfg := config.Config{}
	none := &fakeInitCtx{deps: &shared.Dependencies{Cfg: noneCfg}}
	ContinueWithLoginIdentifier{}.Initialize(none)
	assert.True(t, none.suspended)
	assert.Empty(t, none.addedInputs)

	// Identifier present but no auth method (password off, email-for-auth off, no saml) -> suspended.
	noAuthCfg := config.Config{}
	noAuthCfg.Email.Enabled = true
	noAuthCfg.Email.UseAsLoginIdentifier = true
	noAuthCfg.Email.UseForAuthentication = false
	noAuthCfg.Password.Enabled = false
	noAuth := &fakeInitCtx{deps: &shared.Dependencies{Cfg: noAuthCfg}}
	ContinueWithLoginIdentifier{}.Initialize(noAuth)
	assert.True(t, noAuth.suspended)
}

// Invalid input short-circuits.
func TestContinueWithLoginIdentifier_Execute_InvalidInput(t *testing.T) {
	deps, _, _, _ := loginDeps()
	deps.Cfg = loginIdentifierCfg()
	ctx := newLoginCtx(deps, map[string]interface{}{"identifier": "user@example.com"})
	ctx.validInput = false

	require.NoError(t, ContinueWithLoginIdentifier{}.Execute(ctx))
	assert.True(t, ctx.errored)
	assert.False(t, ctx.continued)
}

// An empty identifier value is a form-data error.
func TestContinueWithLoginIdentifier_Execute_EmptyIdentifier(t *testing.T) {
	deps, _, _, _ := loginDeps()
	deps.Cfg = loginIdentifierCfg()
	ctx := newLoginCtx(deps, map[string]interface{}{"identifier": ""})

	require.NoError(t, ContinueWithLoginIdentifier{}.Execute(ctx))
	assert.True(t, ctx.errored)
	assert.False(t, ctx.continued)
}

// An email that resolves to a user, with both email-for-auth and password enabled, routes to the
// method chooser.
func TestContinueWithLoginIdentifier_Execute_EmailUser_MethodChooser(t *testing.T) {
	deps, p, _, _ := loginDeps()
	deps.Cfg = loginIdentifierCfg()
	p.emails.email = &models.Email{UserID: &userID, Address: "user@example.com"}
	p.users.user = userWithPrimaryEmail(userID, "user@example.com")

	ctx := newLoginCtx(deps, map[string]interface{}{"identifier": "user@example.com"})

	require.NoError(t, ContinueWithLoginIdentifier{}.Execute(ctx))
	assert.True(t, ctx.continued)
	assert.Equal(t, shared.StateLoginMethodChooser, ctx.firstContinuedState())
	assert.Equal(t, userID.String(), ctx.Stash().Get(shared.StashPathUserID).String())
}

// Email user, password only (email-for-auth off) -> password state.
func TestContinueWithLoginIdentifier_Execute_EmailUser_PasswordOnly(t *testing.T) {
	deps, p, _, _ := loginDeps()
	cfg := loginIdentifierCfg()
	cfg.Email.UseForAuthentication = false
	deps.Cfg = cfg
	p.emails.email = &models.Email{UserID: &userID, Address: "user@example.com"}
	p.users.user = userWithPrimaryEmail(userID, "user@example.com")

	ctx := newLoginCtx(deps, map[string]interface{}{"identifier": "user@example.com"})

	require.NoError(t, ContinueWithLoginIdentifier{}.Execute(ctx))
	assert.Equal(t, shared.StateLoginPassword, ctx.firstContinuedState())
}

// Email user, passcode only (password off) -> passcode confirmation, with the login template
// because the user id is known.
func TestContinueWithLoginIdentifier_Execute_EmailUser_PasscodeOnly(t *testing.T) {
	deps, p, _, _ := loginDeps()
	cfg := loginIdentifierCfg()
	cfg.Password.Enabled = false
	deps.Cfg = cfg
	p.emails.email = &models.Email{UserID: &userID, Address: "user@example.com"}
	p.users.user = userWithPrimaryEmail(userID, "user@example.com")

	ctx := newLoginCtx(deps, map[string]interface{}{"identifier": "user@example.com"})

	require.NoError(t, ContinueWithLoginIdentifier{}.Execute(ctx))
	assert.Equal(t, shared.StatePasscodeConfirmation, ctx.firstContinuedState())
	assert.Equal(t, "passcode", ctx.Stash().Get(shared.StashPathLoginMethod).String())
	assert.Equal(t, string(shared.PasscodeTemplateLogin), ctx.Stash().Get(shared.StashPathPasscodeTemplate).String())
}

// Unknown email + existence hints on -> audit log + unknown-email error.
func TestContinueWithLoginIdentifier_Execute_EmailUnknown_HintsOn(t *testing.T) {
	deps, p, _, al := loginDeps()
	cfg := loginIdentifierCfg()
	cfg.Privacy.ShowAccountExistenceHints = true
	deps.Cfg = cfg
	p.emails.email = nil

	ctx := newLoginCtx(deps, map[string]interface{}{"identifier": "ghost@example.com"})

	require.NoError(t, ContinueWithLoginIdentifier{}.Execute(ctx))
	assert.True(t, al.called)
	assert.True(t, ctx.errored)
	assert.False(t, ctx.continued)
}

// Unknown email + hints off -> the flow still proceeds (privacy: don't reveal), and the passcode
// template with no user id records the email-login-attempted template.
func TestContinueWithLoginIdentifier_Execute_EmailUnknown_HintsOff_Passcode(t *testing.T) {
	deps, p, _, _ := loginDeps()
	cfg := loginIdentifierCfg()
	cfg.Password.Enabled = false // passcode only -> continueToPasscodeConfirmation
	deps.Cfg = cfg
	p.emails.email = nil

	ctx := newLoginCtx(deps, map[string]interface{}{"identifier": "ghost@example.com"})

	require.NoError(t, ContinueWithLoginIdentifier{}.Execute(ctx))
	assert.Equal(t, shared.StatePasscodeConfirmation, ctx.firstContinuedState())
	assert.Equal(t, "ghost@example.com", ctx.Stash().Get(shared.StashPathEmail).String())
	assert.Equal(t, string(shared.PasscodeTemplateEmailLoginAttempted), ctx.Stash().Get(shared.StashPathPasscodeTemplate).String())
}

// A global email user is adopted into the tenant.
func TestContinueWithLoginIdentifier_Execute_EmailGlobalAdopts(t *testing.T) {
	deps, p, _, _ := loginDeps()
	deps.Cfg = loginIdentifierCfg()
	p.emails.email = &models.Email{UserID: &userID, Address: "user@example.com"}
	p.emails.isGlobal = true
	p.users.user = userWithPrimaryEmail(userID, "user@example.com")

	ctx := newLoginCtx(deps, map[string]interface{}{"identifier": "user@example.com"})

	require.NoError(t, ContinueWithLoginIdentifier{}.Execute(ctx))
	assert.Equal(t, 1, p.users.adoptCalls)
}

func TestContinueWithLoginIdentifier_Execute_EmailLookupError(t *testing.T) {
	deps, p, _, _ := loginDeps()
	deps.Cfg = loginIdentifierCfg()
	p.emails.err = errors.New("db down")

	ctx := newLoginCtx(deps, map[string]interface{}{"identifier": "user@example.com"})
	require.Error(t, ContinueWithLoginIdentifier{}.Execute(ctx))
}

func TestContinueWithLoginIdentifier_Execute_EmailAdoptError(t *testing.T) {
	deps, p, _, _ := loginDeps()
	deps.Cfg = loginIdentifierCfg()
	p.emails.email = &models.Email{UserID: &userID, Address: "user@example.com"}
	p.emails.isGlobal = true
	p.users.adoptErr = errors.New("adopt failed")

	ctx := newLoginCtx(deps, map[string]interface{}{"identifier": "user@example.com"})
	require.Error(t, ContinueWithLoginIdentifier{}.Execute(ctx))
}

func TestContinueWithLoginIdentifier_Execute_EmailGetUserError(t *testing.T) {
	deps, p, _, _ := loginDeps()
	deps.Cfg = loginIdentifierCfg()
	p.emails.email = &models.Email{UserID: &userID, Address: "user@example.com"}
	p.users.getErr = errors.New("get failed")

	ctx := newLoginCtx(deps, map[string]interface{}{"identifier": "user@example.com"})
	require.Error(t, ContinueWithLoginIdentifier{}.Execute(ctx))
}

// A username identifier resolving to a user with a primary email routes to the method chooser.
func TestContinueWithLoginIdentifier_Execute_UsernameUser_MethodChooser(t *testing.T) {
	deps, p, _, _ := loginDeps()
	deps.Cfg = loginIdentifierCfg()
	p.usernames.username = &models.Username{UserId: userID, Username: "alice"}
	p.users.user = userWithPrimaryEmail(userID, "alice@example.com")

	ctx := newLoginCtx(deps, map[string]interface{}{"identifier": "alice"})

	require.NoError(t, ContinueWithLoginIdentifier{}.Execute(ctx))
	assert.Equal(t, shared.StateLoginMethodChooser, ctx.firstContinuedState())
	assert.Equal(t, "alice", ctx.Stash().Get(shared.StashPathUsername).String())
	assert.Equal(t, userID.String(), ctx.Stash().Get(shared.StashPathUserID).String())
}

// A username user without a primary email, both email+password on, routes to password.
func TestContinueWithLoginIdentifier_Execute_UsernameUser_NoEmail_Password(t *testing.T) {
	deps, p, _, _ := loginDeps()
	deps.Cfg = loginIdentifierCfg()
	p.usernames.username = &models.Username{UserId: userID, Username: "bob"}
	p.users.user = &models.User{ID: userID}

	ctx := newLoginCtx(deps, map[string]interface{}{"identifier": "bob"})

	require.NoError(t, ContinueWithLoginIdentifier{}.Execute(ctx))
	assert.Equal(t, shared.StateLoginPassword, ctx.firstContinuedState())
}

// Unknown username -> audit + unknown-username error.
func TestContinueWithLoginIdentifier_Execute_UsernameUnknown(t *testing.T) {
	deps, p, _, al := loginDeps()
	deps.Cfg = loginIdentifierCfg()
	p.usernames.username = nil

	ctx := newLoginCtx(deps, map[string]interface{}{"identifier": "ghost"})

	require.NoError(t, ContinueWithLoginIdentifier{}.Execute(ctx))
	assert.True(t, al.called)
	assert.True(t, ctx.errored)
}

func TestContinueWithLoginIdentifier_Execute_UsernameGlobalAdopts(t *testing.T) {
	deps, p, _, _ := loginDeps()
	deps.Cfg = loginIdentifierCfg()
	p.usernames.username = &models.Username{UserId: userID, Username: "alice"}
	p.usernames.isGlobal = true
	p.users.user = &models.User{ID: userID}

	ctx := newLoginCtx(deps, map[string]interface{}{"identifier": "alice"})

	require.NoError(t, ContinueWithLoginIdentifier{}.Execute(ctx))
	assert.Equal(t, 1, p.users.adoptCalls)
}

func TestContinueWithLoginIdentifier_Execute_UsernameLookupError(t *testing.T) {
	deps, p, _, _ := loginDeps()
	deps.Cfg = loginIdentifierCfg()
	p.usernames.err = errors.New("db down")

	ctx := newLoginCtx(deps, map[string]interface{}{"identifier": "alice"})
	require.Error(t, ContinueWithLoginIdentifier{}.Execute(ctx))
}

func TestContinueWithLoginIdentifier_Execute_UsernameGetUserError(t *testing.T) {
	deps, p, _, _ := loginDeps()
	deps.Cfg = loginIdentifierCfg()
	p.usernames.username = &models.Username{UserId: userID, Username: "alice"}
	p.users.getErr = errors.New("get failed")

	ctx := newLoginCtx(deps, map[string]interface{}{"identifier": "alice"})
	require.Error(t, ContinueWithLoginIdentifier{}.Execute(ctx))
}

// A username user with no email address while passwords are disabled is a flow discontinuity.
func TestContinueWithLoginIdentifier_Execute_UsernameNoEmail_PasswordDisabled_Discontinuity(t *testing.T) {
	deps, p, _, _ := loginDeps()
	cfg := config.Config{}
	cfg.Username.Enabled = true
	cfg.Username.UseAsLoginIdentifier = true
	cfg.Password.Enabled = false
	deps.Cfg = cfg
	p.usernames.username = &models.Username{UserId: userID, Username: "bob"}
	p.users.user = &models.User{ID: userID}

	ctx := newLoginCtx(deps, map[string]interface{}{"username": "bob"})

	require.NoError(t, ContinueWithLoginIdentifier{}.Execute(ctx))
	assert.True(t, ctx.errored)
	assert.False(t, ctx.continued)
}

// No authentication method enabled at all -> discontinuity error at the end.
func TestContinueWithLoginIdentifier_Execute_NoAuthMethod(t *testing.T) {
	deps, p, _, _ := loginDeps()
	cfg := config.Config{}
	cfg.Email.Enabled = true
	cfg.Email.UseAsLoginIdentifier = true
	cfg.Email.UseForAuthentication = false
	cfg.Password.Enabled = false
	deps.Cfg = cfg
	p.emails.email = &models.Email{UserID: &userID, Address: "user@example.com"}
	p.users.user = userWithPrimaryEmail(userID, "user@example.com")

	ctx := newLoginCtx(deps, map[string]interface{}{"email": "user@example.com"})

	require.NoError(t, ContinueWithLoginIdentifier{}.Execute(ctx))
	assert.True(t, ctx.errored)
	assert.False(t, ctx.continued)
}

// OnlyShowActualLoginMethods: more than one method available -> chooser.
func TestContinueWithLoginIdentifier_Execute_OnlyShow_MultipleMethods_Chooser(t *testing.T) {
	deps, p, _, _ := loginDeps()
	cfg := loginIdentifierCfg()
	cfg.Privacy.OnlyShowActualLoginMethods = true
	deps.Cfg = cfg
	user := userWithPrimaryEmail(userID, "user@example.com")
	user.PasswordCredential = &models.PasswordCredential{}
	p.emails.email = &models.Email{UserID: &userID, Address: "user@example.com"}
	p.users.user = user

	ctx := newLoginCtx(deps, map[string]interface{}{"identifier": "user@example.com"})

	require.NoError(t, ContinueWithLoginIdentifier{}.Execute(ctx))
	assert.Equal(t, shared.StateLoginMethodChooser, ctx.firstContinuedState())
}

// OnlyShow: only email available -> passcode.
func TestContinueWithLoginIdentifier_Execute_OnlyShow_EmailOnly_Passcode(t *testing.T) {
	deps, p, _, _ := loginDeps()
	cfg := loginIdentifierCfg()
	cfg.Privacy.OnlyShowActualLoginMethods = true
	cfg.Password.Enabled = false
	deps.Cfg = cfg
	p.emails.email = &models.Email{UserID: &userID, Address: "user@example.com"}
	p.users.user = userWithPrimaryEmail(userID, "user@example.com")

	ctx := newLoginCtx(deps, map[string]interface{}{"identifier": "user@example.com"})

	require.NoError(t, ContinueWithLoginIdentifier{}.Execute(ctx))
	assert.Equal(t, shared.StatePasscodeConfirmation, ctx.firstContinuedState())
}

// OnlyShow: only password available -> password.
func TestContinueWithLoginIdentifier_Execute_OnlyShow_PasswordOnly(t *testing.T) {
	deps, p, _, _ := loginDeps()
	cfg := loginIdentifierCfg()
	cfg.Privacy.OnlyShowActualLoginMethods = true
	cfg.Email.UseForAuthentication = false
	deps.Cfg = cfg
	user := userWithPrimaryEmail(userID, "user@example.com")
	user.PasswordCredential = &models.PasswordCredential{}
	p.emails.email = &models.Email{UserID: &userID, Address: "user@example.com"}
	p.users.user = user

	ctx := newLoginCtx(deps, map[string]interface{}{"identifier": "user@example.com"})

	require.NoError(t, ContinueWithLoginIdentifier{}.Execute(ctx))
	assert.Equal(t, shared.StateLoginPassword, ctx.firstContinuedState())
}

// Unknown email + hints on + a failing audit-log write becomes a hard error.
func TestContinueWithLoginIdentifier_Execute_EmailUnknown_HintsOn_AuditError(t *testing.T) {
	deps, p, _, al := loginDeps()
	cfg := loginIdentifierCfg()
	cfg.Privacy.ShowAccountExistenceHints = true
	deps.Cfg = cfg
	p.emails.email = nil
	al.err = errors.New("audit store down")

	ctx := newLoginCtx(deps, map[string]interface{}{"identifier": "ghost@example.com"})
	require.Error(t, ContinueWithLoginIdentifier{}.Execute(ctx))
}

// A failing tenant adoption in the username path surfaces as a hard error.
func TestContinueWithLoginIdentifier_Execute_UsernameAdoptError(t *testing.T) {
	deps, p, _, _ := loginDeps()
	deps.Cfg = loginIdentifierCfg()
	p.usernames.username = &models.Username{UserId: userID, Username: "alice"}
	p.usernames.isGlobal = true
	p.users.adoptErr = errors.New("adopt failed")

	ctx := newLoginCtx(deps, map[string]interface{}{"identifier": "alice"})
	require.Error(t, ContinueWithLoginIdentifier{}.Execute(ctx))
}

// Unknown username + a failing audit-log write becomes a hard error.
func TestContinueWithLoginIdentifier_Execute_UsernameUnknown_AuditError(t *testing.T) {
	deps, p, _, al := loginDeps()
	deps.Cfg = loginIdentifierCfg()
	p.usernames.username = nil
	al.err = errors.New("audit store down")

	ctx := newLoginCtx(deps, map[string]interface{}{"identifier": "ghost"})
	require.Error(t, ContinueWithLoginIdentifier{}.Execute(ctx))
}

// An email that maps to a configured SAML provider redirects to the third-party state.
func TestContinueWithLoginIdentifier_Execute_SamlRedirect(t *testing.T) {
	deps, _, _, _ := loginDeps()
	cfg := loginIdentifierCfg()
	cfg.Saml.Enabled = true
	deps.Cfg = cfg
	deps.SamlService = &fakeSamlService{provider: &fakeSamlProvider{}, authURL: "https://idp.example/auth"}

	ctx := newLoginCtx(deps, map[string]interface{}{"identifier": "user@saml-domain.com"})

	require.NoError(t, ContinueWithLoginIdentifier{}.Execute(ctx))
	assert.Equal(t, shared.StateThirdParty, ctx.firstContinuedState())
	assert.Equal(t, "https://idp.example/auth", ctx.Payload().Get("redirect_url").String())
}

// A SAML provider whose auth-url generation fails surfaces as a hard error.
func TestContinueWithLoginIdentifier_Execute_SamlAuthUrlError(t *testing.T) {
	deps, _, _, _ := loginDeps()
	cfg := loginIdentifierCfg()
	cfg.Saml.Enabled = true
	deps.Cfg = cfg
	deps.SamlService = &fakeSamlService{provider: &fakeSamlProvider{}, getURLErr: errors.New("no auth url")}

	ctx := newLoginCtx(deps, map[string]interface{}{"identifier": "user@saml-domain.com"})
	require.Error(t, ContinueWithLoginIdentifier{}.Execute(ctx))
}

// OnlyShow with only passkeys available -> a passkey request is generated and the flow continues to
// the passkey state.
func TestContinueWithLoginIdentifier_Execute_OnlyShow_PasskeyOnly(t *testing.T) {
	deps, p, _, _ := loginDeps()
	cfg := loginIdentifierCfg()
	cfg.Privacy.OnlyShowActualLoginMethods = true
	cfg.Email.UseForAuthentication = false
	cfg.Password.Enabled = false
	cfg.Passkey.Enabled = true
	deps.Cfg = cfg
	deps.WebauthnService = &fakeWebauthnSvc{}
	p.emails.email = &models.Email{UserID: &userID, Address: "user@example.com"}
	p.users.user = userWithPasskey(userID)

	ctx := newLoginCtx(deps, map[string]interface{}{"identifier": "user@example.com"})

	require.NoError(t, ContinueWithLoginIdentifier{}.Execute(ctx))
	assert.Equal(t, shared.StateLoginPasskey, ctx.firstContinuedState())
	assert.True(t, ctx.Payload().Get("request_options").Exists())
}

// A failing passkey-options generation surfaces as a hard error.
func TestContinueWithLoginIdentifier_Execute_OnlyShow_PasskeyError(t *testing.T) {
	deps, p, _, _ := loginDeps()
	cfg := loginIdentifierCfg()
	cfg.Privacy.OnlyShowActualLoginMethods = true
	cfg.Email.UseForAuthentication = false
	cfg.Password.Enabled = false
	cfg.Passkey.Enabled = true
	deps.Cfg = cfg
	deps.WebauthnService = &fakeWebauthnSvc{err: errors.New("webauthn down")}
	p.emails.email = &models.Email{UserID: &userID, Address: "user@example.com"}
	p.users.user = userWithPasskey(userID)

	ctx := newLoginCtx(deps, map[string]interface{}{"identifier": "user@example.com"})
	require.Error(t, ContinueWithLoginIdentifier{}.Execute(ctx))
}

// OnlyShow: nothing available -> the final discontinuity error.
func TestContinueWithLoginIdentifier_Execute_OnlyShow_NothingAvailable(t *testing.T) {
	deps, p, _, _ := loginDeps()
	cfg := loginIdentifierCfg()
	cfg.Privacy.OnlyShowActualLoginMethods = true
	cfg.Email.UseForAuthentication = false
	cfg.Password.Enabled = false
	deps.Cfg = cfg
	p.emails.email = &models.Email{UserID: &userID, Address: "user@example.com"}
	p.users.user = userWithPrimaryEmail(userID, "user@example.com")

	ctx := newLoginCtx(deps, map[string]interface{}{"identifier": "user@example.com"})

	require.NoError(t, ContinueWithLoginIdentifier{}.Execute(ctx))
	assert.True(t, ctx.errored)
	assert.False(t, ctx.continued)
}
