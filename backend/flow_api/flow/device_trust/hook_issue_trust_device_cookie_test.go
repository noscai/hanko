package device_trust

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/teamhanko/hanko/backend/v2/config"
	"github.com/teamhanko/hanko/backend/v2/flow_api/flow/shared"
	"github.com/teamhanko/hanko/backend/v2/flowpilot"
	"github.com/teamhanko/hanko/backend/v2/persistence"
	"github.com/teamhanko/hanko/backend/v2/persistence/models"
)

// These tests drive the real IssueTrustDeviceCookie.Execute -- the archon#1667 OQ3 guard -- through
// a fake flowpilot HookExecutionContext, with no Postgres. The hook's only context dependencies are
// c.Stash() (user id + device_trust_granted) and GetDeps(c) -> c.Get("deps"), so the fake embeds a
// real HookExecutionContext (flowpilot.NewMockHookExecutionContext, which owns the unexported stash)
// and overrides only Get to inject deps. Cookie writes are asserted against the echo response
// recorder; phantom persistence against the fake trusted-device persister.

const testCookieName = "clinicos-2fa-device-token"

// fakeTrustedDevicePersister is the whole persistence dependency the hook reaches (Create only;
// FindByDeviceToken is unused on the issue path).
type fakeTrustedDevicePersister struct {
	created   []models.TrustedDevice
	createErr error
}

func (f *fakeTrustedDevicePersister) Create(td models.TrustedDevice) error {
	if f.createErr != nil {
		return f.createErr
	}
	f.created = append(f.created, td)
	return nil
}

func (f *fakeTrustedDevicePersister) FindByDeviceToken(string) (*models.TrustedDevice, error) {
	return nil, nil
}

// FindValidTrust is likewise unused on the issue path -- stubbed only to satisfy
// persistence.TrustedDevicePersister.
func (f *fakeTrustedDevicePersister) FindValidTrust(string, uuid.UUID, time.Time) (*models.TrustedDevice, error) {
	return nil, nil
}

// fakeTrustPersister satisfies persistence.Persister via embedding; only the accessor the hook
// calls -- GetTrustedDevicePersisterWithConnection -- is real.
type fakeTrustPersister struct {
	persistence.Persister
	trusted persistence.TrustedDevicePersister
}

func (f *fakeTrustPersister) GetTrustedDevicePersisterWithConnection(_ *pop.Connection) persistence.TrustedDevicePersister {
	return f.trusted
}

type fakeIssueCookieCtx struct {
	flowpilot.HookExecutionContext
	deps *shared.Dependencies
}

func (f *fakeIssueCookieCtx) Get(key string) interface{} {
	if key == "deps" {
		return f.deps
	}
	return f.HookExecutionContext.Get(key)
}

func newIssueCookieCtx(deps *shared.Dependencies) *fakeIssueCookieCtx {
	backing := flowpilot.NewMockHookExecutionContext()
	return &fakeIssueCookieCtx{HookExecutionContext: backing, deps: deps}
}

// trustDeps wires the Dependencies the hook reads. existingCookie (when non-empty) is placed on the
// request so the multi-user merge branch is exercised.
func trustDeps(policy string, duration time.Duration, persister persistence.TrustedDevicePersister, existingCookie string) (*shared.Dependencies, *httptest.ResponseRecorder) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	if existingCookie != "" {
		req.AddCookie(&http.Cookie{Name: testCookieName, Value: existingCookie})
	}
	rec := httptest.NewRecorder()
	httpCtx := e.NewContext(req, rec)

	cfg := config.Config{}
	cfg.MFA.DeviceTrustPolicy = policy
	cfg.MFA.DeviceTrustDuration = duration
	cfg.MFA.DeviceTrustCookieName = testCookieName
	cfg.MFA.DeviceTrustMaxUsersPerDevice = 20

	deps := &shared.Dependencies{
		Cfg:         cfg,
		HttpContext: httpCtx,
		Persister:   &fakeTrustPersister{trusted: persister},
	}
	return deps, rec
}

// archon#1667 OQ3: when the trust lifetime is not positive (a config set to 0), device trust is
// disabled for this login. The hook must write NO Set-Cookie header and persist NO trusted-device
// row -- writing here is the phantom entry that evicts a genuinely-trusted user while never
// validating itself.
//
// This is the guarded invariant. Deleting the `if !active { return nil }` guard in the source (the
// §6.2 #2 mutation) turns this test red.
func TestIssueTrustDeviceCookie_Execute_WritesNothingWhenDurationNonPositive(t *testing.T) {
	persister := &fakeTrustedDevicePersister{}
	deps, rec := trustDeps("always", 0, persister, "")
	ctx := newIssueCookieCtx(deps)
	require.NoError(t, ctx.Stash().Set(shared.StashPathUserID, uuid.Must(uuid.NewV4()).String()))

	err := IssueTrustDeviceCookie{}.Execute(ctx)

	require.NoError(t, err)
	assert.Empty(t, rec.Header().Get("Set-Cookie"), "no trust cookie may be written when duration <= 0")
	assert.Empty(t, persister.created, "no phantom trusted-device row may be persisted when duration <= 0")
}

// Happy path: a positive lifetime writes the trust cookie (with a Max-Age) and persists exactly one
// trusted-device row for the stashed user.
func TestIssueTrustDeviceCookie_Execute_WritesCookieAndPersistsWhenActive(t *testing.T) {
	persister := &fakeTrustedDevicePersister{}
	deps, rec := trustDeps("always", 168*time.Hour, persister, "")
	ctx := newIssueCookieCtx(deps)
	uid := uuid.Must(uuid.NewV4())
	require.NoError(t, ctx.Stash().Set(shared.StashPathUserID, uid.String()))

	err := IssueTrustDeviceCookie{}.Execute(ctx)

	require.NoError(t, err)
	setCookie := rec.Header().Get("Set-Cookie")
	require.NotEmpty(t, setCookie, "a trust cookie must be written when duration > 0")
	assert.Contains(t, setCookie, testCookieName+"=")
	assert.Contains(t, setCookie, "Max-Age=")
	require.Len(t, persister.created, 1, "exactly one trusted-device row must be persisted")
	assert.Equal(t, uid.String(), persister.created[0].UserID.String())
}

// policy "never" short-circuits before any token generation.
func TestIssueTrustDeviceCookie_Execute_SkipsWhenPolicyNever(t *testing.T) {
	persister := &fakeTrustedDevicePersister{}
	deps, rec := trustDeps("never", 168*time.Hour, persister, "")
	ctx := newIssueCookieCtx(deps)
	require.NoError(t, ctx.Stash().Set(shared.StashPathUserID, uuid.Must(uuid.NewV4()).String()))

	err := IssueTrustDeviceCookie{}.Execute(ctx)

	require.NoError(t, err)
	assert.Empty(t, rec.Header().Get("Set-Cookie"))
	assert.Empty(t, persister.created)
}

// policy "prompt" without device_trust_granted in the stash short-circuits.
func TestIssueTrustDeviceCookie_Execute_SkipsWhenPromptNotGranted(t *testing.T) {
	persister := &fakeTrustedDevicePersister{}
	deps, rec := trustDeps("prompt", 168*time.Hour, persister, "")
	ctx := newIssueCookieCtx(deps)
	require.NoError(t, ctx.Stash().Set(shared.StashPathUserID, uuid.Must(uuid.NewV4()).String()))

	err := IssueTrustDeviceCookie{}.Execute(ctx)

	require.NoError(t, err)
	assert.Empty(t, rec.Header().Get("Set-Cookie"))
	assert.Empty(t, persister.created)
}

// policy "prompt" WITH device_trust_granted proceeds to write the cookie.
func TestIssueTrustDeviceCookie_Execute_WritesCookieWhenPromptGranted(t *testing.T) {
	persister := &fakeTrustedDevicePersister{}
	deps, rec := trustDeps("prompt", 168*time.Hour, persister, "")
	ctx := newIssueCookieCtx(deps)
	require.NoError(t, ctx.Stash().Set(shared.StashPathUserID, uuid.Must(uuid.NewV4()).String()))
	require.NoError(t, ctx.Stash().Set(shared.StashPathDeviceTrustGranted, true))

	err := IssueTrustDeviceCookie{}.Execute(ctx)

	require.NoError(t, err)
	assert.NotEmpty(t, rec.Header().Get("Set-Cookie"))
	require.Len(t, persister.created, 1)
}

// A pre-existing multi-user cookie is parsed and merged: the acting user is added, the other user
// retained.
func TestIssueTrustDeviceCookie_Execute_MergesExistingCookieEntries(t *testing.T) {
	persister := &fakeTrustedDevicePersister{}
	other := uuid.Must(uuid.NewV4())
	existing := other.String() + ":sometoken"
	deps, rec := trustDeps("always", 168*time.Hour, persister, existing)
	ctx := newIssueCookieCtx(deps)
	uid := uuid.Must(uuid.NewV4())
	require.NoError(t, ctx.Stash().Set(shared.StashPathUserID, uid.String()))

	err := IssueTrustDeviceCookie{}.Execute(ctx)

	require.NoError(t, err)
	setCookie := rec.Header().Get("Set-Cookie")
	require.NotEmpty(t, setCookie)
	assert.Contains(t, setCookie, uid.String(), "the acting user must be present in the merged cookie")
	assert.Contains(t, setCookie, other.String(), "the pre-existing user must be retained")
	require.Len(t, persister.created, 1)
}

// No user id in the stash is an error, and nothing is written.
func TestIssueTrustDeviceCookie_Execute_ErrorsWhenUserIDMissing(t *testing.T) {
	persister := &fakeTrustedDevicePersister{}
	deps, rec := trustDeps("always", 168*time.Hour, persister, "")
	ctx := newIssueCookieCtx(deps)

	err := IssueTrustDeviceCookie{}.Execute(ctx)

	require.Error(t, err)
	assert.Empty(t, rec.Header().Get("Set-Cookie"))
	assert.Empty(t, persister.created)
}

// A malformed user id in the stash is an error, and nothing is written.
func TestIssueTrustDeviceCookie_Execute_ErrorsWhenUserIDMalformed(t *testing.T) {
	persister := &fakeTrustedDevicePersister{}
	deps, rec := trustDeps("always", 168*time.Hour, persister, "")
	ctx := newIssueCookieCtx(deps)
	require.NoError(t, ctx.Stash().Set(shared.StashPathUserID, "not-a-uuid"))

	err := IssueTrustDeviceCookie{}.Execute(ctx)

	require.Error(t, err)
	assert.Empty(t, rec.Header().Get("Set-Cookie"))
	assert.Empty(t, persister.created)
}

// A persistence failure surfaces as an error and no cookie is written (the store is written before
// the cookie is set).
func TestIssueTrustDeviceCookie_Execute_ErrorsWhenPersistFails(t *testing.T) {
	persister := &fakeTrustedDevicePersister{createErr: errors.New("db down")}
	deps, rec := trustDeps("always", 168*time.Hour, persister, "")
	ctx := newIssueCookieCtx(deps)
	require.NoError(t, ctx.Stash().Set(shared.StashPathUserID, uuid.Must(uuid.NewV4()).String()))

	err := IssueTrustDeviceCookie{}.Execute(ctx)

	require.Error(t, err)
	assert.Empty(t, rec.Header().Get("Set-Cookie"), "no cookie may be written if the persist failed")
}
