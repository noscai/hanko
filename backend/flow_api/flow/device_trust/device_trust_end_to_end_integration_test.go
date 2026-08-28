package device_trust

// End-to-end device-trust properties: the REAL IssueTrustDeviceCookie hook grants trust and the
// REAL DeviceTrustService.CheckDeviceTrust verifies it, both against a real Postgres from
// test.Suite (dockertest).
//
// Every other device-trust test stubs one side of that loop. The hook tests
// (hook_issue_trust_device_cookie_test.go) drive the real hook but resolve trust through an
// in-memory fake persister; the service tests (flow_api/services/device_trust_test.go) exercise
// CheckDeviceTrust's v2/v1/v0 branches against the same kind of fake; the persister tests
// (persistence/trusted_device_persister_integration_test.go) hit real Postgres but call the
// persister directly, with no hook and no cookie. Nothing ran the write path and the read path
// together against the database -- which is exactly where the shipped bug lived: the row and the
// browser's pointer to it disagreed, and each half looked correct on its own.
//
// WHAT IS DELIBERATELY NOT HERE. The design listed four invariants; two are already asserted
// closer to the code that owns them, and duplicating them here would only add slow, redundant
// database round-trips:
//   - I-2, one row per (device_token, user_id) and lookups independent of row order ->
//     persistence/trusted_device_persister_integration_test.go, TestCreate_RetrustingSamePair...
//     and TestFindValidTrust_OrderIndependent / _ExpiresAtEqualsNow (the strict > boundary).
//   - I-3, cookie size constant in headcount -> hook_issue_trust_device_cookie_test.go,
//     ..._CookieSizeIsIndependentOfUserCount (N=1/21/50) and ..._ByteGuardNeverFiresUnderV2Format
//     (N=1/21/50/500).
// The one residue worth having here was that the upsert had only ever been driven by calling the
// persister directly, never through the hook against real Postgres; that is folded into I-1's
// row-count assertion rather than split into its own test.
//
// PLACEMENT. This is an INTERNAL test package (package device_trust, not device_trust_test),
// unlike the two persistence integration tests, which had to go external. Their constraint does
// not apply here: test.Suite lives in package "test", whose import closure is
// {config, persistence, persistence/models, audit_log, crypto, flowpilot, utils, ...} and
// contains no flow_api package at all (`go list -deps .../test`). So "test" -> "persistence" is
// a cycle for a test file inside package persistence, but "device_trust" -> "test" -> "persistence"
// is a straight line. Staying internal lets these tests reuse the harness the hook tests already
// built -- testDeviceCookieName, testCookieName, writtenCookies, newIssueCookieCtx -- rather than
// restating it, so the two files cannot drift about what the hook is wired to.
//
// COOKIE-FORMAT AGNOSTIC ON PURPOSE. sharedWorkstation below is a small cookie jar: it sends
// whatever cookies it holds and stores back whatever Set-Cookie headers come out, without
// asserting names or formats, and the read side is configured with BOTH cookie names so
// CheckDeviceTrust's v2, v1 and v0 branches are all live. Format assertions are the hook tests'
// job (they already pin "exactly one cookie, the v2 one, never the legacy one"). Here the
// assertions are only about the property -- who is still trusted -- so these tests keep their
// meaning against any cookie format the hook might be changed to write. That is what makes them
// usable as the regression guard: reintroducing the original composite-cookie write path leaves
// them compiling and running, and they fail on the property, not on a format mismatch.

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/suite"

	"github.com/teamhanko/hanko/backend/v2/config"
	"github.com/teamhanko/hanko/backend/v2/flow_api/flow/shared"
	"github.com/teamhanko/hanko/backend/v2/flow_api/services"
	"github.com/teamhanko/hanko/backend/v2/persistence/models"
	"github.com/teamhanko/hanko/backend/v2/test"
)

// trustDuration is the production lifetime (168h in every cluster). Nothing in these tests is
// meant to expire mid-run: the property under test is about rows that are STILL valid staying
// reachable. Expiry itself is pinned, boundary included, in
// persistence/trusted_device_persister_integration_test.go.
const trustDuration = 168 * time.Hour

func TestDeviceTrustEndToEndSuite(t *testing.T) {
	t.Parallel()
	suite.Run(t, new(deviceTrustEndToEndSuite))
}

type deviceTrustEndToEndSuite struct {
	test.Suite

	// maxUsersPerDeviceOverride, set only by
	// TestSetting_DeviceTrustMaxUsersPerDeviceIsInert, replaces cfg()'s
	// device_trust_max_users_per_device for the duration of one sub-case. nil means "use the
	// harness default (20)", matching every other test in this file.
	maxUsersPerDeviceOverride *int
}

func (s *deviceTrustEndToEndSuite) skipIfShort() {
	if testing.Short() {
		s.T().Skip("skipping test in short mode.")
	}
}

// TestRegression_TwentyFirstUserDoesNotEvictTheFirstFromTheBrowser is the end-to-end guard for
// the defect this branch fixes (CU-869eqrmjn).
//
// The shipped code recorded trust in a browser cookie that carried EVERY user's token
// ("<uuid>:<token>|..."), capped at 20 entries. On a shared clinic workstation the 21st person to
// trust the browser silently evicted the 1st: their trusted_devices row was untouched and
// unexpired, but the browser's only pointer to it was gone, so they were re-challenged for a full
// 2FA code -- and re-trusting displaced somebody else, so the condition never settled.
//
// The test that let this ship, TestMergeDeviceTrustEntries_ActingUserAlwaysSurvives, asserted
// that the user currently logging in survives truncation. That is trivially and permanently true
// -- the merge puts the acting user first -- so the suite stayed green through the whole
// incident. The assertion it never made, and could not make from a pure function with no
// database, is the one below: that an already-trusted, NON-acting user survives too. Here user 1
// never acts again after their own login, and twenty logins later they must still be trusted.
func (s *deviceTrustEndToEndSuite) TestRegression_TwentyFirstUserDoesNotEvictTheFirstFromTheBrowser() {
	s.skipIfShort()

	const totalUsers = 21
	users := s.createUsers(totalUsers)
	workstation := newSharedWorkstation()

	for i := 0; i < 20; i++ {
		s.trust(workstation, users[i])
	}

	s.Require().True(s.isTrusted(workstation, users[0]),
		"user 1 must be trusted after their own login -- if this fails the harness is broken, not the fix")

	// The 21st login: the exact event that used to push user 1 out of the cookie.
	s.trust(workstation, users[20])

	s.True(s.isTrusted(workstation, users[0]),
		"user 1 must still be trusted after user 21 trusts this browser -- this is the shipped bug")

	// Distinguish the two halves the bug pulled apart. Under the old cookie user 1's row was
	// present and unexpired all along; only the browser's pointer to it was lost. Asserting the
	// row separately makes a failure above unambiguous -- it is the reachability that broke, not
	// the record. Looked up by user_id alone, deliberately: going through the cookie's token
	// would make this assertion depend on the very mechanism under test.
	s.True(s.hasUnexpiredRow(users[0]),
		"user 1's trusted_devices row must still exist and be unexpired")

	for i, userID := range users {
		s.True(s.isTrusted(workstation, userID), "user %d must be trusted", i+1)
	}
}

// TestInvariant_EveryUnexpiredRowStaysReachableFromTheBrowserThatCreatedIt is invariant I-1:
// every trusted_devices row with expires_at > now stays reachable from the browser that created
// it, for its full lifetime.
//
// This is the invariant the bug violated -- and it violated it silently, because nothing about a
// single user's login looks wrong when a different user is dropped. So rather than a hand-picked
// sequence, this drives randomized (user, trust) sequences over a device shared by up to 200
// users, re-checking EVERY user who has ever trusted after EVERY event. Re-trusts are included
// (the sequence samples users with replacement), which is what a real workstation does.
//
// Two things keep the property from being vacuously true:
//   - a control user who never trusts must be reported NOT trusted throughout, so a
//     CheckDeviceTrust that answered "true" unconditionally would fail here;
//   - the row count at the end must equal the number of DISTINCT users who trusted, so re-trusts
//     upsert rather than accumulate (the hook-level counterpart to the persister's
//     TestCreate_RetrustingSamePairLeavesExactlyOneRowWithLatestExpiry).
//
// Keep the largest N. The two halves of this test bite at different sizes, verified by
// reintroducing the original defect: below the old 20-user cap nothing is ever evicted, so
// users=2 and users=25 fail only on the row-count assertion (the old code minted a token per
// trust, so re-trusts piled up rows), while the reachability assertion -- the eviction itself --
// only fires once the distinct-user count passes 20, which is why users=200 is here and why it is
// the case that actually reproduces the bug.
func (s *deviceTrustEndToEndSuite) TestInvariant_EveryUnexpiredRowStaysReachableFromTheBrowserThatCreatedIt() {
	s.skipIfShort()

	// Fixed seed: a randomized property test that cannot be replayed is not much of a guard. The
	// seed is reported in every failure message so a red run is reproducible verbatim.
	const seed = int64(0x5EED)

	for _, userCount := range []int{2, 25, 200} {
		s.Run(fmt.Sprintf("users=%d", userCount), func() {
			// testify runs SetupTest once per suite METHOD, not per s.Run, so these sub-runs
			// share one database. Clear the table so each N starts from a device nobody trusts
			// and the row-count assertion at the end counts only this sub-run's writes.
			s.Require().NoError(s.Storage.GetConnection().RawQuery("DELETE FROM trusted_devices").Exec())

			rng := rand.New(rand.NewSource(seed + int64(userCount)))

			users := s.createUsers(userCount + 1)
			// The last user never trusts: the negative control that keeps every True() below
			// meaningful.
			neverTrusts := users[userCount]
			users = users[:userCount]

			workstation := newSharedWorkstation()
			trusted := make(map[uuid.UUID]bool, userCount)

			// One event per user, sampled WITH replacement -- so some users trust several times
			// and others not at all, which is the point: it mixes first-trusts and re-trusts in
			// an order no hand-written case would pick.
			for event := 0; event < userCount; event++ {
				actor := users[rng.Intn(userCount)]
				s.trust(workstation, actor)
				trusted[actor] = true

				for userID := range trusted {
					s.Require().True(s.isTrusted(workstation, userID),
						"seed=%d users=%d event=%d: user %s trusted this browser and their row is unexpired, so the browser must still present it",
						seed, userCount, event, userID)
				}

				s.Require().False(s.isTrusted(workstation, neverTrusts),
					"seed=%d users=%d event=%d: a user who never trusted this browser must not be trusted",
					seed, userCount, event)
			}

			s.Equal(len(trusted), s.rowCount(),
				"one row per distinct user who trusted: re-trusting must refresh a row, not add one")
		})
	}
}

// TestInvariant_SharedDeviceTokenGrantsTrustOnlyToTheUsersWhoTrusted is invariant I-4: per-user
// isolation under a shared token.
//
// The fix deliberately gives one browser ONE device token that every user on it shares, moving
// identity out of the cookie and into trusted_devices(device_token, user_id). That trade is only
// safe while the user_id half is actually enforced -- a dropped predicate anywhere on the read
// path would not merely widen a lookup, it would hand a second-factor bypass to every colleague
// on the workstation the moment one of them trusted it. Too consequential to assume, so it is
// asserted here against the real database, with the shared token genuinely present in the jar.
func (s *deviceTrustEndToEndSuite) TestInvariant_SharedDeviceTokenGrantsTrustOnlyToTheUsersWhoTrusted() {
	s.skipIfShort()

	users := s.createUsers(6)
	workstation := newSharedWorkstation()

	// Only user A trusts. Everyone else is a colleague who has logged in on this machine but
	// never trusted it.
	userA := users[0]
	s.trust(workstation, userA)

	s.Require().True(s.isTrusted(workstation, userA))
	for _, userB := range users[1:] {
		s.False(s.isTrusted(workstation, userB),
			"user %s never trusted this browser and must not be trusted by A's token", userB)
	}

	// Now let three more users trust, so the token really is shared, and re-check that the
	// remaining two are still refused. Without the DISTINCT-token assertion below this would be
	// satisfiable by per-user tokens -- i.e. by not sharing at all -- which is not the property
	// being claimed.
	for _, userB := range users[1:4] {
		s.trust(workstation, userB)
	}

	s.Require().Equal(1, s.distinctDeviceTokenCount(),
		"all users must share one device token, otherwise this test proves nothing about isolation UNDER a shared token")

	for _, userB := range users[:4] {
		s.True(s.isTrusted(workstation, userB), "user %s trusted this browser and must be trusted", userB)
	}
	for _, userB := range users[4:] {
		s.False(s.isTrusted(workstation, userB),
			"user %s never trusted this browser and must stay untrusted even though the shared token is valid", userB)
	}
}

// TestSetting_DeviceTrustMaxUsersPerDeviceIsInert proves device_trust_max_users_per_device
// (CU-869eqrmjn Task 9) is now a documented no-op.
//
// The setting used to cap how many users could hold device trust on one browser: the trust cookie
// carried an entry per user, and once that list grew past the cap the oldest entries were
// truncated off -- silently evicting whoever had trusted the device longest, even though their
// trusted_devices row was still valid and unexpired. That eviction is exactly the bug
// TestRegression_TwentyFirstUserDoesNotEvictTheFirstFromTheBrowser guards, at the default cap of
// 20. This test guards the setting itself, at two configurations that would have evicted someone
// under the old truncating write path but must not under the current one:
//
//   - explicitly set BELOW the trusting headcount (5, with a 6th user trusting) -- proves a
//     tenant who deliberately tightens this key gets no truncation, not even at a threshold this
//     low;
//   - left at its Go zero value (0) -- NOT the same as "omitted from YAML": Load() seeds
//     DefaultConfig() (20) before merging the file, so an operator who omits the key gets 20, and
//     that path is covered by TestRegression_TwentyFirstUserDoesNotEvictTheFirstFromTheBrowser.
//     Zero is reachable from a bare config.Config{} or an operator writing 0 outright, and it
//     matters because it takes a different branch: the old capped-cookie write path
//     fell back to a default of 20 for a non-positive value (config_default.go still documents
//     that same default), so this sub-case drives past that threshold too (21 users, the same
//     headcount as the regression test above) rather than stopping short of it, so leaving the key
//     unset is proven inert and not merely untested.
//
// A setting that is inert only when explicitly configured is not actually retired -- hence both.
func (s *deviceTrustEndToEndSuite) TestSetting_DeviceTrustMaxUsersPerDeviceIsInert() {
	s.skipIfShort()

	s.Run("cap explicitly set below the trusting headcount", func() {
		s.assertCapDoesNotEvictTheFirstUser(5, 6)
	})

	s.Run("cap left at its zero value (bare struct, or explicitly set to 0)", func() {
		s.assertCapDoesNotEvictTheFirstUser(0, 21)
	})
}

// assertCapDoesNotEvictTheFirstUser configures device_trust_max_users_per_device as
// maxUsersPerDevice, has userCount users trust a shared browser in order, and asserts the first of
// them is still trusted afterward -- the exact property the old cookie truncation used to violate.
func (s *deviceTrustEndToEndSuite) assertCapDoesNotEvictTheFirstUser(maxUsersPerDevice, userCount int) {
	s.T().Helper()

	// Subtests share the suite's database (SetupTest runs once per suite METHOD, not per s.Run);
	// start each sub-case from a device nobody trusts, same pattern as
	// TestInvariant_EveryUnexpiredRowStaysReachableFromTheBrowserThatCreatedIt.
	s.Require().NoError(s.Storage.GetConnection().RawQuery("DELETE FROM trusted_devices").Exec())

	s.maxUsersPerDeviceOverride = &maxUsersPerDevice
	defer func() { s.maxUsersPerDeviceOverride = nil }()

	users := s.createUsers(userCount)
	workstation := newSharedWorkstation()

	for _, userID := range users {
		s.trust(workstation, userID)
	}

	s.True(s.isTrusted(workstation, users[0]),
		"user 1 must still be trusted after %d users trust this browser with "+
			"device_trust_max_users_per_device=%d -- the setting is retained only for "+
			"backward-compatible config loading and must not evict anyone",
		userCount, maxUsersPerDevice)
}

// sharedWorkstation is the browser half of the loop: a minimal cookie jar for one machine.
//
// It stores whatever the hook sets and replays it on the next request, keyed by cookie name, so a
// login can see what earlier logins left behind -- which is the only way the eviction bug is
// observable at all. It deliberately knows nothing about cookie formats or names; see the file
// header for why.
type sharedWorkstation struct {
	jar map[string]string
}

func newSharedWorkstation() *sharedWorkstation {
	return &sharedWorkstation{jar: map[string]string{}}
}

// send returns the cookies the browser would attach to the next request.
func (w *sharedWorkstation) send() []*http.Cookie {
	cookies := make([]*http.Cookie, 0, len(w.jar))
	for name, value := range w.jar {
		cookies = append(cookies, &http.Cookie{Name: name, Value: value})
	}
	return cookies
}

// receive applies a response's Set-Cookie headers, mirroring a browser: a cookie with MaxAge < 0
// is a deletion, anything else replaces the stored value under that name.
func (w *sharedWorkstation) receive(rec *httptest.ResponseRecorder) {
	for _, cookie := range writtenCookies(rec) {
		if cookie.MaxAge < 0 {
			delete(w.jar, cookie.Name)
			continue
		}
		w.jar[cookie.Name] = cookie.Value
	}
}

// trust drives the real IssueTrustDeviceCookie hook for one user, against real Postgres, with the
// workstation's current cookies on the request and its Set-Cookie response folded back into the
// jar -- one login on a shared machine.
func (s *deviceTrustEndToEndSuite) trust(workstation *sharedWorkstation, userID uuid.UUID) {
	s.T().Helper()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	for _, cookie := range workstation.send() {
		req.AddCookie(cookie)
	}

	deps := &shared.Dependencies{
		Cfg:         s.cfg(),
		HttpContext: echo.New().NewContext(req, rec),
		Persister:   s.Storage,
		// The hook resolves its persister via GetTrustedDevicePersisterWithConnection(deps.Tx);
		// a nil Tx would build a persister over a nil *pop.Connection and panic on first use.
		Tx: s.Storage.GetConnection(),
	}

	ctx := newIssueCookieCtx(deps)
	s.Require().NoError(ctx.Stash().Set(shared.StashPathUserID, userID.String()))
	s.Require().NoError(IssueTrustDeviceCookie{}.Execute(ctx))

	s.Require().NotEmpty(writtenCookies(rec), "a granted trust must hand the browser some cookie")
	workstation.receive(rec)
}

// isTrusted drives the real CheckDeviceTrust for one user, against real Postgres, with the
// workstation's cookies on the request -- the "may this user skip the second factor?" question
// asked exactly as the login flow asks it.
func (s *deviceTrustEndToEndSuite) isTrusted(workstation *sharedWorkstation, userID uuid.UUID) bool {
	s.T().Helper()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, cookie := range workstation.send() {
		req.AddCookie(cookie)
	}

	svc := services.DeviceTrustService{
		Persister:   s.Storage.GetTrustedDevicePersister(),
		Cfg:         s.cfg(),
		HttpContext: echo.New().NewContext(req, httptest.NewRecorder()),
	}
	return svc.CheckDeviceTrust(userID)
}

// cfg is the production-shaped device-trust config. Both cookie names are set, so all three of
// CheckDeviceTrust's branches are live and the read side accepts whichever format the write side
// chose -- see the file header on why these tests stay format-agnostic.
func (s *deviceTrustEndToEndSuite) cfg() config.Config {
	cfg := config.Config{}
	cfg.MFA.DeviceTrustPolicy = "always"
	cfg.MFA.DeviceTrustDuration = trustDuration
	cfg.MFA.DeviceTrustCookieName = testCookieName
	cfg.MFA.DeviceTrustDeviceCookieName = testDeviceCookieName
	cfg.MFA.DeviceTrustMaxUsersPerDevice = 20
	// Overridden only by TestSetting_DeviceTrustMaxUsersPerDeviceIsInert, to drive the setting at
	// values other than the harness default above while still going through the same trust/
	// isTrusted helpers every other test in this file uses.
	if s.maxUsersPerDeviceOverride != nil {
		cfg.MFA.DeviceTrustMaxUsersPerDevice = *s.maxUsersPerDeviceOverride
	}
	return cfg
}

// createUsers inserts n real users. trusted_devices.user_id carries a foreign key to users.id, so
// every actor in these tests has to exist for real; the fixture file only has one.
func (s *deviceTrustEndToEndSuite) createUsers(n int) []uuid.UUID {
	s.T().Helper()

	now := time.Now().UTC()
	users := make([]uuid.UUID, 0, n)
	for i := 0; i < n; i++ {
		id, err := uuid.NewV4()
		s.Require().NoError(err)
		s.Require().NoError(s.Storage.GetConnection().RawQuery(
			"INSERT INTO users (id, created_at, updated_at) VALUES (?, ?, ?)", id, now, now,
		).Exec())
		users = append(users, id)
	}
	return users
}

// hasUnexpiredRow answers whether the database still holds a live trust record for this user on
// ANY device token -- the "is the record there?" half of the question, asked without reference to
// the cookie, so it stays true independently of how the browser is told about it.
func (s *deviceTrustEndToEndSuite) hasUnexpiredRow(userID uuid.UUID) bool {
	s.T().Helper()

	exists, err := s.Storage.GetConnection().
		Where("user_id = ? AND expires_at > ?", userID, time.Now().UTC()).
		Exists(&models.TrustedDevice{})
	s.Require().NoError(err)
	return exists
}

func (s *deviceTrustEndToEndSuite) rowCount() int {
	s.T().Helper()

	count, err := s.Storage.GetConnection().Count(&models.TrustedDevice{})
	s.Require().NoError(err)
	return count
}

func (s *deviceTrustEndToEndSuite) distinctDeviceTokenCount() int {
	s.T().Helper()

	var rows []models.TrustedDevice
	s.Require().NoError(s.Storage.GetConnection().All(&rows))

	tokens := make(map[string]struct{}, len(rows))
	for _, row := range rows {
		tokens[row.DeviceToken] = struct{}{}
	}
	return len(tokens)
}
