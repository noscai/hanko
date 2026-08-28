package device_trust

import (
	"errors"
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

// These tests drive the real IssueTrustDeviceCookie.Execute through a fake flowpilot
// HookExecutionContext, with no Postgres. The hook's only context dependencies are c.Stash()
// (user id + device_trust_granted) and GetDeps(c) -> c.Get("deps"), so the fake embeds a real
// HookExecutionContext (flowpilot.NewMockHookExecutionContext, which owns the unexported stash)
// and overrides only Get to inject deps. Cookie writes are asserted against the echo response
// recorder; persistence against the fake trusted-device persister.

const (
	// testCookieName is the LEGACY (v1/v0) cookie. The hook must never write it again.
	testCookieName = "clinicos-2fa-device-token"
	// testDeviceCookieName is the v2 device-scoped cookie -- the only one the hook writes.
	testDeviceCookieName = "clinicos-2fa-device-id"
)

// A device token is 64 random bytes base64url-encoded -> 88 chars, and models.TrustedDevice
// validates the 64..128 length. Both fixtures are shaped like a real token so nothing passes or
// fails these tests for the wrong reason (a short "attacker" string would be rejected by model
// validation rather than by the reuse check under test).
var (
	knownDeviceToken   = strings.Repeat("A", 86) + "=="
	plantedDeviceToken = strings.Repeat("P", 86) + "=="
)

// fakeTrustedDevicePersister records writes and answers the two reads the device-trust code
// makes: FindByDeviceToken (the hook's reuse check) and FindValidTrust (CheckDeviceTrust's
// validation).
type fakeTrustedDevicePersister struct {
	created   []models.TrustedDevice
	createErr error
	// rowsByToken maps a device token to how many trusted_devices rows already exist for it --
	// i.e. how many users already trust this browser under that token.
	rowsByToken map[string]int
	findErr     error
	findCalls   []string
}

func (f *fakeTrustedDevicePersister) Create(td models.TrustedDevice) error {
	if f.createErr != nil {
		return f.createErr
	}
	f.created = append(f.created, td)
	return nil
}

func (f *fakeTrustedDevicePersister) FindByDeviceToken(token string) (*models.TrustedDevice, error) {
	f.findCalls = append(f.findCalls, token)
	if f.findErr != nil {
		return nil, f.findErr
	}
	if f.rowsByToken[token] > 0 {
		return &models.TrustedDevice{DeviceToken: token, UserID: uuid.Must(uuid.NewV4())}, nil
	}
	return nil, nil
}

// FindValidTrust answers from the rows this fake has actually stored, so a test can feed the
// cookie the hook emitted straight back into CheckDeviceTrust and see whether the write path and
// the read path agree.
func (f *fakeTrustedDevicePersister) FindValidTrust(token string, userID uuid.UUID, now time.Time) (*models.TrustedDevice, error) {
	if f.findErr != nil {
		return nil, f.findErr
	}
	for i := range f.created {
		row := f.created[i]
		if row.DeviceToken == token && row.UserID == userID && row.ExpiresAt.After(now) {
			return &row, nil
		}
	}
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

func trustDeps(policy string, duration time.Duration, persister persistence.TrustedDevicePersister, legacyCookie string) (*shared.Dependencies, *httptest.ResponseRecorder) {
	return trustDepsWithCookies(policy, duration, persister, legacyCookie, "")
}

// trustDepsWithCookies wires the Dependencies the hook reads. Either cookie, when non-empty, is
// placed on the request.
func trustDepsWithCookies(policy string, duration time.Duration, persister persistence.TrustedDevicePersister, legacyCookie, deviceCookie string) (*shared.Dependencies, *httptest.ResponseRecorder) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	if legacyCookie != "" {
		req.AddCookie(&http.Cookie{Name: testCookieName, Value: legacyCookie})
	}
	if deviceCookie != "" {
		req.AddCookie(&http.Cookie{Name: testDeviceCookieName, Value: deviceCookie})
	}
	rec := httptest.NewRecorder()
	httpCtx := e.NewContext(req, rec)

	cfg := config.Config{}
	cfg.MFA.DeviceTrustPolicy = policy
	cfg.MFA.DeviceTrustDuration = duration
	cfg.MFA.DeviceTrustCookieName = testCookieName
	cfg.MFA.DeviceTrustDeviceCookieName = testDeviceCookieName
	cfg.MFA.DeviceTrustMaxUsersPerDevice = 20

	deps := &shared.Dependencies{
		Cfg:         cfg,
		HttpContext: httpCtx,
		Persister:   &fakeTrustPersister{trusted: persister},
	}
	return deps, rec
}

// writtenCookies parses the recorder's Set-Cookie headers, so assertions are about cookie NAMES
// rather than substrings of a header (the legacy and device cookie names share a prefix in
// production).
func writtenCookies(rec *httptest.ResponseRecorder) []*http.Cookie {
	return (&http.Response{Header: rec.Header()}).Cookies()
}

// requireSingleDeviceCookie asserts the hook wrote exactly one cookie, that it is the v2
// device cookie, and returns the bare token it carries.
func requireSingleDeviceCookie(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	cookies := writtenCookies(rec)
	require.Len(t, cookies, 1, "the hook must write exactly one cookie: the v2 device cookie")
	require.Equal(t, testDeviceCookieName, cookies[0].Name)
	token, ok := services.ParseDeviceIDCookie(cookies[0].Value)
	require.True(t, ok, "the emitted value %q must parse as a v2 device cookie", cookies[0].Value)
	return token
}

// legacyMultiUserCookie builds a v1 composite cookie value carrying n users, the shape whose
// unbounded growth (and 20-entry truncation) was the original bug.
func legacyMultiUserCookie(n int) string {
	parts := make([]string, 0, n)
	for i := 0; i < n; i++ {
		parts = append(parts, uuid.Must(uuid.NewV4()).String()+":"+knownDeviceToken)
	}
	return strings.Join(parts, "|")
}

// archon#1667 OQ3: when the trust lifetime is not positive (a config set to 0), device trust is
// disabled for this login. The hook must write NO Set-Cookie header and persist NO trusted-device
// row -- writing here is the phantom entry that evicts a genuinely-trusted user while never
// validating itself.
//
// This is the guarded invariant. Deleting the maxAge guard in the source turns this test red.
func TestIssueTrustDeviceCookie_Execute_WritesNothingWhenDurationNonPositive(t *testing.T) {
	persister := &fakeTrustedDevicePersister{}
	deps, rec := trustDepsWithCookies("always", 0, persister, legacyMultiUserCookie(3), "d1."+knownDeviceToken)
	ctx := newIssueCookieCtx(deps)
	require.NoError(t, ctx.Stash().Set(shared.StashPathUserID, uuid.Must(uuid.NewV4()).String()))

	err := IssueTrustDeviceCookie{}.Execute(ctx)

	require.NoError(t, err)
	assert.Empty(t, writtenCookies(rec), "no cookie may be written when duration <= 0, so existing cookies stay untouched")
	assert.Empty(t, persister.created, "no phantom trusted-device row may be persisted when duration <= 0")
}

// Happy path with no v2 cookie on the request: the hook mints a fresh token, writes exactly one
// cookie (the v2 one), and persists exactly one row carrying that same token.
func TestIssueTrustDeviceCookie_Execute_MintsFreshTokenWhenNoDeviceCookie(t *testing.T) {
	persister := &fakeTrustedDevicePersister{}
	deps, rec := trustDeps("always", 168*time.Hour, persister, "")
	ctx := newIssueCookieCtx(deps)
	uid := uuid.Must(uuid.NewV4())
	require.NoError(t, ctx.Stash().Set(shared.StashPathUserID, uid.String()))

	err := IssueTrustDeviceCookie{}.Execute(ctx)

	require.NoError(t, err)
	token := requireSingleDeviceCookie(t, rec)
	assert.Len(t, token, 88, "a freshly minted token is 64 random bytes base64url-encoded")
	require.Len(t, persister.created, 1, "exactly one trusted-device row must be persisted")
	assert.Equal(t, uid.String(), persister.created[0].UserID.String())
	assert.Equal(t, token, persister.created[0].DeviceToken, "the persisted row must carry the token the browser was given")

	setCookie := rec.Header().Get("Set-Cookie")
	assert.Contains(t, setCookie, "Max-Age=")
	assert.Contains(t, setCookie, "Path=/")
	assert.Contains(t, setCookie, "HttpOnly")
	assert.Contains(t, setCookie, "Secure")
	assert.Contains(t, setCookie, "SameSite=None")
}

// A v2 cookie whose token already has at least one trusted_devices row is the browser's real
// device identity: reuse it, so every colleague who already trusts this browser keeps pointing at
// the same token.
func TestIssueTrustDeviceCookie_Execute_ReusesDeviceTokenBackedByExistingRow(t *testing.T) {
	persister := &fakeTrustedDevicePersister{rowsByToken: map[string]int{knownDeviceToken: 3}}
	deps, rec := trustDepsWithCookies("always", 168*time.Hour, persister, "", "d1."+knownDeviceToken)
	ctx := newIssueCookieCtx(deps)
	uid := uuid.Must(uuid.NewV4())
	require.NoError(t, ctx.Stash().Set(shared.StashPathUserID, uid.String()))

	err := IssueTrustDeviceCookie{}.Execute(ctx)

	require.NoError(t, err)
	assert.Equal(t, knownDeviceToken, requireSingleDeviceCookie(t, rec), "the browser must keep the device token it already had")
	require.Len(t, persister.created, 1)
	assert.Equal(t, knownDeviceToken, persister.created[0].DeviceToken, "the new row must hang off the reused device token")
	assert.Equal(t, uid.String(), persister.created[0].UserID.String())
}

// A device token the cookie merely CLAIMS is not a device identity. Anyone with devtools or a
// minute at a shared front desk can write d1.<token-they-chose>; if the hook reused it, every
// colleague who trusted that browser afterwards would get a row under a token the attacker
// already holds, and that one cookie would skip the second factor for all of them elsewhere.
// The token must already exist in trusted_devices to be reused.
func TestIssueTrustDeviceCookie_Execute_IgnoresPlantedDeviceTokenWithNoRow(t *testing.T) {
	persister := &fakeTrustedDevicePersister{}
	deps, rec := trustDepsWithCookies("always", 168*time.Hour, persister, "", "d1."+plantedDeviceToken)
	ctx := newIssueCookieCtx(deps)
	require.NoError(t, ctx.Stash().Set(shared.StashPathUserID, uuid.Must(uuid.NewV4()).String()))

	err := IssueTrustDeviceCookie{}.Execute(ctx)

	require.NoError(t, err)
	token := requireSingleDeviceCookie(t, rec)
	assert.NotEqual(t, plantedDeviceToken, token, "a planted token backed by no row must not become this browser's device identity")
	require.Len(t, persister.created, 1)
	assert.NotEqual(t, plantedDeviceToken, persister.created[0].DeviceToken, "the planted token must never reach CreateTrustedDevice")
	assert.Equal(t, token, persister.created[0].DeviceToken)
	assert.Contains(t, persister.findCalls, plantedDeviceToken, "the planted token must have been checked against the store")
}

// Anything that is not "d1.<non-empty>" carries no device token at all -- including the empty
// remainder "d1.", a bare v0 token, and a v1 composite value that landed in the wrong cookie.
func TestIssueTrustDeviceCookie_Execute_MintsFreshOnMalformedDeviceCookie(t *testing.T) {
	for name, value := range map[string]string{
		"empty remainder": "d1.",
		"bare token":      knownDeviceToken,
		"v1 composite":    uuid.Must(uuid.NewV4()).String() + ":" + knownDeviceToken,
		"wrong prefix":    "d2." + knownDeviceToken,
	} {
		t.Run(name, func(t *testing.T) {
			persister := &fakeTrustedDevicePersister{rowsByToken: map[string]int{knownDeviceToken: 1}}
			deps, rec := trustDepsWithCookies("always", 168*time.Hour, persister, "", value)
			ctx := newIssueCookieCtx(deps)
			require.NoError(t, ctx.Stash().Set(shared.StashPathUserID, uuid.Must(uuid.NewV4()).String()))

			err := IssueTrustDeviceCookie{}.Execute(ctx)

			require.NoError(t, err)
			token := requireSingleDeviceCookie(t, rec)
			assert.Len(t, token, 88, "a malformed v2 value means no token, so one is minted")
			assert.NotEqual(t, knownDeviceToken, token)
			require.Len(t, persister.created, 1)
			assert.Equal(t, token, persister.created[0].DeviceToken)
		})
	}
}

// The legacy cookie is read-only from here on: it still grants trust to pre-deploy users through
// CheckDeviceTrust's v1/v0 branches, and drains on its own within its own lifetime. Rewriting it
// would keep the per-headcount growth (and the 20-entry eviction) alive forever.
func TestIssueTrustDeviceCookie_Execute_NeverWritesLegacyCookie(t *testing.T) {
	persister := &fakeTrustedDevicePersister{}
	deps, rec := trustDepsWithCookies("always", 168*time.Hour, persister, legacyMultiUserCookie(5), "")
	ctx := newIssueCookieCtx(deps)
	require.NoError(t, ctx.Stash().Set(shared.StashPathUserID, uuid.Must(uuid.NewV4()).String()))

	err := IssueTrustDeviceCookie{}.Execute(ctx)

	require.NoError(t, err)
	for _, cookie := range writtenCookies(rec) {
		assert.NotEqual(t, testCookieName, cookie.Name, "the legacy cookie must never be written again")
	}
	requireSingleDeviceCookie(t, rec)
}

// The bug in one assertion: the emitted cookie must not grow with the number of users who
// already trust this browser. Under the old composite format the Set-Cookie grew by ~60 bytes per
// colleague until it hit the 20-user cap and started evicting people; here it is one token,
// byte-identical at 1, 21 and 50 existing users.
func TestIssueTrustDeviceCookie_Execute_CookieSizeIsIndependentOfUserCount(t *testing.T) {
	sizes := make(map[int]int)

	for _, existingUsers := range []int{1, 21, 50} {
		persister := &fakeTrustedDevicePersister{rowsByToken: map[string]int{knownDeviceToken: existingUsers}}
		deps, rec := trustDepsWithCookies("always", 168*time.Hour, persister,
			legacyMultiUserCookie(existingUsers), "d1."+knownDeviceToken)
		ctx := newIssueCookieCtx(deps)
		require.NoError(t, ctx.Stash().Set(shared.StashPathUserID, uuid.Must(uuid.NewV4()).String()))

		require.NoError(t, IssueTrustDeviceCookie{}.Execute(ctx))

		setCookie := rec.Header().Get("Set-Cookie")
		require.NotEmpty(t, setCookie)
		sizes[existingUsers] = len(setCookie)
	}

	assert.Equal(t, sizes[1], sizes[21], "cookie size must not depend on headcount (1 vs 21 users)")
	assert.Equal(t, sizes[1], sizes[50], "cookie size must not depend on headcount (1 vs 50 users)")
	assert.Less(t, sizes[1], 200, "one device token, not a per-user list: %d bytes", sizes[1])
}

// A read failure on the reuse check must not fail the login flow and must not reuse an
// unvalidated token: mint fresh and carry on.
func TestIssueTrustDeviceCookie_Execute_MintsFreshWhenReuseCheckErrors(t *testing.T) {
	persister := &fakeTrustedDevicePersister{
		rowsByToken: map[string]int{knownDeviceToken: 4},
		findErr:     errors.New("db read failed"),
	}
	deps, rec := trustDepsWithCookies("always", 168*time.Hour, persister, "", "d1."+knownDeviceToken)
	ctx := newIssueCookieCtx(deps)
	require.NoError(t, ctx.Stash().Set(shared.StashPathUserID, uuid.Must(uuid.NewV4()).String()))

	err := IssueTrustDeviceCookie{}.Execute(ctx)

	require.NoError(t, err, "a failed reuse check must not fail the hook")
	token := requireSingleDeviceCookie(t, rec)
	assert.NotEqual(t, knownDeviceToken, token, "an unverifiable token must not be reused")
	require.Len(t, persister.created, 1)
	assert.Equal(t, token, persister.created[0].DeviceToken)
}

// The write path and Task 5's read path must agree: feed the cookie the hook just emitted back in
// as a request cookie and CheckDeviceTrust's v2 branch must validate it for the same user -- and
// only for that user.
func TestIssueTrustDeviceCookie_Execute_EmittedCookieSatisfiesCheckDeviceTrust(t *testing.T) {
	persister := &fakeTrustedDevicePersister{}
	deps, rec := trustDeps("always", 168*time.Hour, persister, "")
	ctx := newIssueCookieCtx(deps)
	uid := uuid.Must(uuid.NewV4())
	require.NoError(t, ctx.Stash().Set(shared.StashPathUserID, uid.String()))

	require.NoError(t, IssueTrustDeviceCookie{}.Execute(ctx))
	cookies := writtenCookies(rec)
	require.Len(t, cookies, 1)

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookies[0])
	readCtx := e.NewContext(req, httptest.NewRecorder())

	// The legacy cookie name is blanked on the read side so CheckDeviceTrust's v1 and v0 branches
	// cannot fire: whatever validates here validated through the v2 branch, which is the one this
	// hook now feeds.
	readCfg := deps.Cfg
	readCfg.MFA.DeviceTrustCookieName = ""

	svc := services.DeviceTrustService{Persister: persister, Cfg: readCfg, HttpContext: readCtx}
	assert.True(t, svc.CheckDeviceTrust(uid), "the cookie the hook wrote must validate for the user it was issued to")
	assert.False(t, svc.CheckDeviceTrust(uuid.Must(uuid.NewV4())), "the same cookie must not validate for a colleague with no row")
}

// The cookie value the hook writes must be exactly what ParseDeviceIDCookie reads back, so the
// v2 writer and the v2 reader cannot drift apart about the format.
func TestFormatDeviceIDCookie_RoundTripsThroughParser(t *testing.T) {
	parsed, ok := services.ParseDeviceIDCookie(services.FormatDeviceIDCookie(knownDeviceToken))
	require.True(t, ok)
	assert.Equal(t, knownDeviceToken, parsed)
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
	requireSingleDeviceCookie(t, rec)
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
