package credential_usage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sethvargo/go-limiter/memorystore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/teamhanko/hanko/backend/v2/config"
	"github.com/teamhanko/hanko/backend/v2/flow_api/flow/shared"
	"github.com/teamhanko/hanko/backend/v2/flow_api/services"
	"github.com/teamhanko/hanko/backend/v2/persistence/models"
	"github.com/teamhanko/hanko/backend/v2/rate_limiter"
)

func TestPasswordLogin_Metadata(t *testing.T) {
	a := PasswordLogin{}
	assert.Equal(t, shared.ActionPasswordLogin, a.GetName())
	assert.NotEmpty(t, a.GetDescription())
}

func TestPasswordLogin_Initialize(t *testing.T) {
	// Password disabled -> the action suspends.
	suspendCfg := config.Config{}
	suspendCfg.Password.Enabled = false
	ctxSuspend := &fakeInitCtx{deps: &shared.Dependencies{Cfg: suspendCfg}}
	PasswordLogin{}.Initialize(ctxSuspend)
	assert.True(t, ctxSuspend.suspended)
	require.Len(t, ctxSuspend.addedInputs, 1, "the password input is always registered")

	// Password enabled -> the action stays active.
	enableCfg := config.Config{}
	enableCfg.Password.Enabled = true
	ctxActive := &fakeInitCtx{deps: &shared.Dependencies{Cfg: enableCfg}}
	PasswordLogin{}.Initialize(ctxActive)
	assert.False(t, ctxActive.suspended)
}

// Invalid input data short-circuits into a form-data error before anything else runs.
func TestPasswordLogin_Execute_InvalidInput(t *testing.T) {
	deps, _, _, _ := loginDeps()
	ctx := newLoginCtx(deps, map[string]interface{}{"password": "secret"})
	ctx.validInput = false

	require.NoError(t, PasswordLogin{}.Execute(ctx))
	assert.True(t, ctx.errored)
	assert.False(t, ctx.continued)
}

// No email and no username in the stash -> wrong-credentials error.
func TestPasswordLogin_Execute_NoIdentifierInStash(t *testing.T) {
	deps, _, _, _ := loginDeps()
	ctx := newLoginCtx(deps, map[string]interface{}{"password": "secret"})

	require.NoError(t, PasswordLogin{}.Execute(ctx))
	assert.True(t, ctx.errored)
	assert.False(t, ctx.continued)
}

// Happy path via email: a matched user with a valid password continues the flow, prevents revert,
// runs the MFA-scheduling hook, and records the login method.
func TestPasswordLogin_Execute_EmailHappyPath(t *testing.T) {
	deps, p, _, _ := loginDeps()
	p.emails.email = &models.Email{UserID: &userID, Address: "user@example.com"}

	ctx := newLoginCtx(deps, map[string]interface{}{"password": "secret"})
	require.NoError(t, ctx.Stash().Set(shared.StashPathEmail, "user@example.com"))

	require.NoError(t, PasswordLogin{}.Execute(ctx))
	assert.True(t, ctx.continued)
	assert.True(t, ctx.preventRevert)
	assert.True(t, ctx.hookCalled)
	assert.Equal(t, "password", ctx.Stash().Get(shared.StashPathLoginMethod).String())
}

// Unknown email -> wrong credentials, no continue.
func TestPasswordLogin_Execute_EmailNotFound(t *testing.T) {
	deps, p, _, _ := loginDeps()
	p.emails.email = nil

	ctx := newLoginCtx(deps, map[string]interface{}{"password": "secret"})
	require.NoError(t, ctx.Stash().Set(shared.StashPathEmail, "ghost@example.com"))

	require.NoError(t, PasswordLogin{}.Execute(ctx))
	assert.True(t, ctx.errored)
	assert.False(t, ctx.continued)
}

// A global user matched via email fallback is adopted into the request tenant before login proceeds.
func TestPasswordLogin_Execute_EmailGlobalFallbackAdopts(t *testing.T) {
	deps, p, _, _ := loginDeps()
	p.emails.email = &models.Email{UserID: &userID, Address: "user@example.com"}
	p.emails.isGlobal = true

	ctx := newLoginCtx(deps, map[string]interface{}{"password": "secret"})
	require.NoError(t, ctx.Stash().Set(shared.StashPathEmail, "user@example.com"))

	require.NoError(t, PasswordLogin{}.Execute(ctx))
	assert.Equal(t, 1, p.users.adoptCalls, "a global user must be adopted into the tenant")
	assert.True(t, ctx.continued)
}

// A persister failure while resolving the email surfaces as a hard error.
func TestPasswordLogin_Execute_EmailLookupError(t *testing.T) {
	deps, p, _, _ := loginDeps()
	p.emails.err = errors.New("db down")

	ctx := newLoginCtx(deps, map[string]interface{}{"password": "secret"})
	require.NoError(t, ctx.Stash().Set(shared.StashPathEmail, "user@example.com"))

	require.Error(t, PasswordLogin{}.Execute(ctx))
}

// A failing tenant adoption surfaces as a hard error.
func TestPasswordLogin_Execute_EmailAdoptError(t *testing.T) {
	deps, p, _, _ := loginDeps()
	p.emails.email = &models.Email{UserID: &userID, Address: "user@example.com"}
	p.emails.isGlobal = true
	p.users.adoptErr = errors.New("adopt failed")

	ctx := newLoginCtx(deps, map[string]interface{}{"password": "secret"})
	require.NoError(t, ctx.Stash().Set(shared.StashPathEmail, "user@example.com"))

	require.Error(t, PasswordLogin{}.Execute(ctx))
}

// Happy path via username.
func TestPasswordLogin_Execute_UsernameHappyPath(t *testing.T) {
	deps, p, _, _ := loginDeps()
	p.usernames.username = &models.Username{UserId: userID, Username: "alice"}

	ctx := newLoginCtx(deps, map[string]interface{}{"password": "secret"})
	require.NoError(t, ctx.Stash().Set(shared.StashPathUsername, "alice"))

	require.NoError(t, PasswordLogin{}.Execute(ctx))
	assert.True(t, ctx.continued)
	assert.True(t, ctx.preventRevert)
}

// Unknown username -> wrong credentials.
func TestPasswordLogin_Execute_UsernameNotFound(t *testing.T) {
	deps, p, _, _ := loginDeps()
	p.usernames.username = nil

	ctx := newLoginCtx(deps, map[string]interface{}{"password": "secret"})
	require.NoError(t, ctx.Stash().Set(shared.StashPathUsername, "ghost"))

	require.NoError(t, PasswordLogin{}.Execute(ctx))
	assert.True(t, ctx.errored)
	assert.False(t, ctx.continued)
}

// Global username fallback is adopted.
func TestPasswordLogin_Execute_UsernameGlobalFallbackAdopts(t *testing.T) {
	deps, p, _, _ := loginDeps()
	p.usernames.username = &models.Username{UserId: userID, Username: "alice"}
	p.usernames.isGlobal = true

	ctx := newLoginCtx(deps, map[string]interface{}{"password": "secret"})
	require.NoError(t, ctx.Stash().Set(shared.StashPathUsername, "alice"))

	require.NoError(t, PasswordLogin{}.Execute(ctx))
	assert.Equal(t, 1, p.users.adoptCalls)
	assert.True(t, ctx.continued)
}

// A failing tenant adoption in the username path surfaces as a hard error.
func TestPasswordLogin_Execute_UsernameAdoptError(t *testing.T) {
	deps, p, _, _ := loginDeps()
	p.usernames.username = &models.Username{UserId: userID, Username: "alice"}
	p.usernames.isGlobal = true
	p.users.adoptErr = errors.New("adopt failed")

	ctx := newLoginCtx(deps, map[string]interface{}{"password": "secret"})
	require.NoError(t, ctx.Stash().Set(shared.StashPathUsername, "alice"))

	require.Error(t, PasswordLogin{}.Execute(ctx))
}

// Username lookup failure surfaces as an error.
func TestPasswordLogin_Execute_UsernameLookupError(t *testing.T) {
	deps, p, _, _ := loginDeps()
	p.usernames.err = errors.New("db down")

	ctx := newLoginCtx(deps, map[string]interface{}{"password": "secret"})
	require.NoError(t, ctx.Stash().Set(shared.StashPathUsername, "alice"))

	require.Error(t, PasswordLogin{}.Execute(ctx))
}

// A wrong password is audit-logged and returned as wrong credentials (not a hard error).
func TestPasswordLogin_Execute_WrongPassword_AuditsAndRejects(t *testing.T) {
	deps, p, pw, al := loginDeps()
	p.emails.email = &models.Email{UserID: &userID, Address: "user@example.com"}
	pw.err = services.ErrorPasswordInvalid

	ctx := newLoginCtx(deps, map[string]interface{}{"password": "wrong"})
	require.NoError(t, ctx.Stash().Set(shared.StashPathEmail, "user@example.com"))

	require.NoError(t, PasswordLogin{}.Execute(ctx))
	assert.True(t, al.called, "a failed password must be audit-logged")
	assert.True(t, ctx.errored)
	assert.False(t, ctx.continued)
}

// If the audit log write itself fails on a wrong password, that becomes a hard error.
func TestPasswordLogin_Execute_WrongPassword_AuditError(t *testing.T) {
	deps, p, pw, al := loginDeps()
	p.emails.email = &models.Email{UserID: &userID, Address: "user@example.com"}
	pw.err = services.ErrorPasswordInvalid
	al.err = errors.New("audit store down")

	ctx := newLoginCtx(deps, map[string]interface{}{"password": "wrong"})
	require.NoError(t, ctx.Stash().Set(shared.StashPathEmail, "user@example.com"))

	require.Error(t, PasswordLogin{}.Execute(ctx))
}

// A non-"invalid" verification error is a hard error.
func TestPasswordLogin_Execute_VerifyPasswordError(t *testing.T) {
	deps, p, pw, _ := loginDeps()
	p.emails.email = &models.Email{UserID: &userID, Address: "user@example.com"}
	pw.err = errors.New("bcrypt exploded")

	ctx := newLoginCtx(deps, map[string]interface{}{"password": "secret"})
	require.NoError(t, ctx.Stash().Set(shared.StashPathEmail, "user@example.com"))

	require.Error(t, PasswordLogin{}.Execute(ctx))
}

// A failing MFA-scheduling hook propagates.
func TestPasswordLogin_Execute_HookError(t *testing.T) {
	deps, p, _, _ := loginDeps()
	p.emails.email = &models.Email{UserID: &userID, Address: "user@example.com"}

	ctx := newLoginCtx(deps, map[string]interface{}{"password": "secret"})
	require.NoError(t, ctx.Stash().Set(shared.StashPathEmail, "user@example.com"))
	ctx.hookErr = errors.New("mfa hook failed")

	require.Error(t, PasswordLogin{}.Execute(ctx))
}

// Rate limiting: enabled and within budget -> login proceeds.
func TestPasswordLogin_Execute_RateLimitedAllowed(t *testing.T) {
	deps, p, _, _ := loginDeps()
	deps.Cfg.RateLimiter.Enabled = true
	store, err := memorystore.New(&memorystore.Config{Tokens: 5, Interval: time.Minute})
	require.NoError(t, err)
	deps.PasswordRateLimiter = store
	p.emails.email = &models.Email{UserID: &userID, Address: "user@example.com"}

	ctx := newLoginCtx(deps, map[string]interface{}{"password": "secret"})
	require.NoError(t, ctx.Stash().Set(shared.StashPathUserIdentification, "user@example.com"))
	require.NoError(t, ctx.Stash().Set(shared.StashPathEmail, "user@example.com"))

	require.NoError(t, PasswordLogin{}.Execute(ctx))
	assert.True(t, ctx.continued)
}

// Rate limiting: budget exhausted -> rejected with retry_after recorded.
func TestPasswordLogin_Execute_RateLimitedDenied(t *testing.T) {
	deps, _, _, _ := loginDeps()
	deps.Cfg.RateLimiter.Enabled = true
	store, err := memorystore.New(&memorystore.Config{Tokens: 1, Interval: time.Minute})
	require.NoError(t, err)
	deps.PasswordRateLimiter = store

	ctx := newLoginCtx(deps, map[string]interface{}{"password": "secret"})
	require.NoError(t, ctx.Stash().Set(shared.StashPathUserIdentification, "user@example.com"))
	require.NoError(t, ctx.Stash().Set(shared.StashPathEmail, "user@example.com"))

	// Exhaust the one token so the action's own Limit2 is denied.
	key := rate_limiter.CreateRateLimitPasswordKey(deps.HttpContext.RealIP(), "user@example.com")
	_, ok, err := rate_limiter.Limit2(store, key)
	require.NoError(t, err)
	require.True(t, ok)

	require.NoError(t, PasswordLogin{}.Execute(ctx))
	assert.True(t, ctx.errored)
	assert.False(t, ctx.continued)
	assert.True(t, ctx.Payload().Get("retry_after").Exists())
}

// Rate limiting: a stopped store surfaces the limiter error as a hard error.
func TestPasswordLogin_Execute_RateLimiterError(t *testing.T) {
	deps, _, _, _ := loginDeps()
	deps.Cfg.RateLimiter.Enabled = true
	store, err := memorystore.New(&memorystore.Config{Tokens: 5, Interval: time.Minute})
	require.NoError(t, err)
	require.NoError(t, store.Close(context.Background()))
	deps.PasswordRateLimiter = store

	ctx := newLoginCtx(deps, map[string]interface{}{"password": "secret"})
	require.NoError(t, ctx.Stash().Set(shared.StashPathUserIdentification, "user@example.com"))
	require.NoError(t, ctx.Stash().Set(shared.StashPathEmail, "user@example.com"))

	require.Error(t, PasswordLogin{}.Execute(ctx))
}
