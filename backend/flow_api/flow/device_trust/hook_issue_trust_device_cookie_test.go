package device_trust

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
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

	// v1/v0 cannot fire here regardless of this line: readCtx wraps a brand-new
	// httptest.NewRequest that only ever received cookies[0] (the v2 cookie the hook just wrote),
	// so there is no legacy-named cookie on the request for CheckDeviceTrust's v1/v0 branches to
	// find no matter what DeviceTrustCookieName is set to -- confirmed by removing this line and
	// seeing the test still pass identically. Blanking it anyway is belt-and-braces: it costs
	// nothing here and keeps this assertion (that validation happened through v2, not v1/v0) true
	// even if a future refactor starts reusing the write-side request/cookie jar on the read side.
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

// --- Task 8: the 4096-byte cookie guard ------------------------------------------------------
//
// The v2 cookie built above is one token at a constant ~164 bytes (Name + "d1." + 88-char token +
// attributes), regardless of how many people trust the browser -- see
// TestIssueTrustDeviceCookie_Execute_CookieSizeIsIndependentOfUserCount above and
// TestIssueTrustDeviceCookie_Execute_ByteGuardNeverFiresUnderV2Format below. That means the guard
// itself can never fire from anything the v2 format alone produces; the only legitimate way to
// drive it is a config-driven input that also feeds http.Cookie.String() -- the cookie's NAME
// (deps.Cfg.MFA.DeviceTrustDeviceCookieName), which is operator-controlled and unrelated to the
// token machinery. That is deliberately used below instead of adding any test-only seam to
// production code.

// captureWarnLogs redirects the process-wide zerolog logger (github.com/rs/zerolog/log) to a
// buffer for the duration of fn and returns what it wrote, then restores the original logger.
// The hook has no injected logger of its own -- shared.Dependencies only carries AuditLogger,
// which persists structured audit rows to the DB, a different concern -- so, like every other WARN
// this codebase emits outside a request handler (handler/passcode.go, session/template.go,
// thirdparty/provider_apple.go), the byte-cap guard logs through this same global package logger.
// Swapping its package-level Logger var for the call is the standard way to observe it in a test;
// nothing here touches production code or adds a logging dependency.
func captureWarnLogs(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	original := zlog.Logger
	zlog.Logger = zerolog.New(&buf)
	defer func() { zlog.Logger = original }()
	fn()
	return buf.String()
}

// cookieSerializationOverhead returns how many bytes http.Cookie.String() spends on everything
// except the cookie's Name, for the exact Value/Path/HttpOnly/Secure/MaxAge/SameSite
// IssueTrustDeviceCookie always builds. The Value length is fixed regardless of whether the token
// is reused or freshly minted: base64.URLEncoding always pads a 64-byte input to 88 characters.
// Used to pick a cookie NAME long enough to land the total serialized cookie at an exact target
// byte count.
func cookieSerializationOverhead(t *testing.T, maxAge int) int {
	t.Helper()
	probe := &http.Cookie{
		Name:     "n",
		Value:    services.FormatDeviceIDCookie(knownDeviceToken),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		MaxAge:   maxAge,
		SameSite: http.SameSiteNoneMode,
	}
	return len(probe.String()) - len(probe.Name)
}

// cookieNameForTargetBytes returns a cookie name (all valid HTTP token characters, so
// http.Cookie.String() never rejects it regardless of length) that makes the hook's emitted
// Set-Cookie serialize to exactly target bytes.
func cookieNameForTargetBytes(t *testing.T, maxAge, target int) string {
	t.Helper()
	overhead := cookieSerializationOverhead(t, maxAge)
	nameLen := target - overhead
	require.Positive(t, nameLen, "target %d bytes is smaller than the fixed cookie overhead %d", target, overhead)
	return strings.Repeat("n", nameLen)
}

// durationSeconds168h is the maxAge (seconds) every test below computes cookie overhead for,
// matching the 168*time.Hour duration each of them passes to trustDeps/trustDepsWithCookies.
const durationSeconds168h = int(168 * time.Hour / time.Second)

// A cookie whose serialized length would exceed the 4096-byte cap must not be written at all, and
// the hook must emit exactly one WARN naming the actual byte count. The row is still expected to
// have been persisted (CreateTrustedDevice runs before the cookie is built) -- see the comment on
// the guard in Execute for why that ordering is the deliberately chosen side: an orphaned row that
// nobody can ever present is inert, whereas checking size before persisting would mean
// restructuring the hook around a branch the current format cannot reach.
func TestIssueTrustDeviceCookie_Execute_RefusesOversizedCookie(t *testing.T) {
	const targetBytes = maxCookieBytes + 500 // comfortably over the cap, not a boundary probe

	persister := &fakeTrustedDevicePersister{}
	deps, rec := trustDeps("always", 168*time.Hour, persister, "")
	deps.Cfg.MFA.DeviceTrustDeviceCookieName = cookieNameForTargetBytes(t, durationSeconds168h, targetBytes)
	ctx := newIssueCookieCtx(deps)
	require.NoError(t, ctx.Stash().Set(shared.StashPathUserID, uuid.Must(uuid.NewV4()).String()))

	var err error
	logOutput := captureWarnLogs(t, func() {
		err = IssueTrustDeviceCookie{}.Execute(ctx)
	})

	require.NoError(t, err, "an oversized cookie must not fail the hook, only skip the write")
	assert.Empty(t, writtenCookies(rec), "a cookie over the 4096-byte cap must never be written")
	require.Equal(t, 1, strings.Count(logOutput, `"level":"warn"`), "exactly one WARN must be emitted:\n%s", logOutput)
	assert.Contains(t, logOutput, fmt.Sprintf("%d", targetBytes), "the WARN must name the actual byte count")
	assert.Len(t, persister.created, 1, "the trusted-device row is already persisted by the time the byte guard runs")
}

// The cap is exclusive: a cookie that serializes to exactly 4096 bytes is still under the
// browser's limit and must still be written (with no WARN), while one byte more must be refused.
// This is the off-by-one check -- ">" not ">=", and not "> 4096 - 1".
func TestIssueTrustDeviceCookie_Execute_ByteGuardBoundary(t *testing.T) {
	t.Run("exactly at the cap is written", func(t *testing.T) {
		persister := &fakeTrustedDevicePersister{}
		deps, rec := trustDeps("always", 168*time.Hour, persister, "")
		deps.Cfg.MFA.DeviceTrustDeviceCookieName = cookieNameForTargetBytes(t, durationSeconds168h, maxCookieBytes)
		ctx := newIssueCookieCtx(deps)
		require.NoError(t, ctx.Stash().Set(shared.StashPathUserID, uuid.Must(uuid.NewV4()).String()))

		var err error
		logOutput := captureWarnLogs(t, func() {
			err = IssueTrustDeviceCookie{}.Execute(ctx)
		})

		require.NoError(t, err)
		cookies := writtenCookies(rec)
		require.Len(t, cookies, 1, "a cookie of exactly %d bytes must still be written", maxCookieBytes)
		// Sanity on the probe itself, not a re-derived value: the Set-Cookie header IS
		// cookie.String() (what net/http's SetCookie writes verbatim), so its raw length -- not a
		// round trip through Cookies() re-parsing -- confirms the target was hit exactly.
		require.Equal(t, maxCookieBytes, len(rec.Header().Get("Set-Cookie")), "sanity: the probe must have landed exactly on the cap")
		assert.Empty(t, logOutput, "no WARN may be emitted for a cookie at the cap")
	})

	t.Run("one byte over the cap is refused", func(t *testing.T) {
		persister := &fakeTrustedDevicePersister{}
		deps, rec := trustDeps("always", 168*time.Hour, persister, "")
		deps.Cfg.MFA.DeviceTrustDeviceCookieName = cookieNameForTargetBytes(t, durationSeconds168h, maxCookieBytes+1)
		ctx := newIssueCookieCtx(deps)
		require.NoError(t, ctx.Stash().Set(shared.StashPathUserID, uuid.Must(uuid.NewV4()).String()))

		var err error
		logOutput := captureWarnLogs(t, func() {
			err = IssueTrustDeviceCookie{}.Execute(ctx)
		})

		require.NoError(t, err)
		assert.Empty(t, writtenCookies(rec), "a cookie of %d bytes (one over the cap) must not be written", maxCookieBytes+1)
		assert.Contains(t, logOutput, fmt.Sprintf("%d", maxCookieBytes+1))
	})
}

// The whole point of the v2 format is that this guard is unreachable at any headcount -- unlike
// the old per-user cookie, whose Set-Cookie grew ~60 bytes per colleague and would have crossed
// 4096 bytes well before its own 20-user truncation even engaged. Assert the guard stays silent
// (cookie written, no WARN) at 1, 21, 50 and 500 existing trusted_devices rows for the browser.
func TestIssueTrustDeviceCookie_Execute_ByteGuardNeverFiresUnderV2Format(t *testing.T) {
	for _, existingUsers := range []int{1, 21, 50, 500} {
		t.Run(fmt.Sprintf("%d existing users", existingUsers), func(t *testing.T) {
			persister := &fakeTrustedDevicePersister{rowsByToken: map[string]int{knownDeviceToken: existingUsers}}
			deps, rec := trustDepsWithCookies("always", 168*time.Hour, persister,
				legacyMultiUserCookie(existingUsers), "d1."+knownDeviceToken)
			ctx := newIssueCookieCtx(deps)
			require.NoError(t, ctx.Stash().Set(shared.StashPathUserID, uuid.Must(uuid.NewV4()).String()))

			var err error
			logOutput := captureWarnLogs(t, func() {
				err = IssueTrustDeviceCookie{}.Execute(ctx)
			})

			require.NoError(t, err)
			requireSingleDeviceCookie(t, rec)
			assert.Empty(t, logOutput, "the byte guard must not fire under the v2 format at %d existing users", existingUsers)
		})
	}
}
