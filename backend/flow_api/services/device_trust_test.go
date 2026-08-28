package services

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/teamhanko/hanko/backend/v2/config"
	"github.com/teamhanko/hanko/backend/v2/persistence/models"
)

const (
	// testCookieName is the legacy cookie: v0 bare tokens and v1 composite entries.
	testCookieName = "clinicos-2fa-device-token"
	// testDeviceCookieName is the v2 device-scoped cookie holding a single "d1.<token>" value.
	testDeviceCookieName = "clinicos-2fa-device-id"
)

// fakeTrustedDevicePersister is the whole persistence dependency of DeviceTrustService. The
// interface is three methods, which is what lets the entire service be tested with no Postgres.
//
// Rows are kept as a slice rather than a token-keyed map because one device_token is now shared
// by every user who trusted that browser (uq_trusted_devices_token_user is on the PAIR). A
// map[token] could not represent two users trusting the same device, which is precisely the
// state the cross-user isolation tests need to construct.
type fakeTrustedDevicePersister struct {
	rows      []*models.TrustedDevice
	byToken   map[string]*models.TrustedDevice
	created   []models.TrustedDevice
	createErr error
	findErr   error
	// errByToken fails lookups for one specific device_token, so a test can make a single branch
	// of CheckDeviceTrust's OR fail while the other branches still resolve normally.
	errByToken map[string]error
	// expiringExactlyAtNow maps a device_token to the user whose row expires at exactly the
	// instant of the lookup. It cannot be seeded as a fixed timestamp because CheckDeviceTrust
	// supplies its own now, so the row is materialised against the caller's clock instead.
	expiringExactlyAtNow map[string]uuid.UUID

	findValidTrustCalls    int
	findByDeviceTokenCalls int
}

func newFakePersister() *fakeTrustedDevicePersister {
	return &fakeTrustedDevicePersister{
		byToken:              map[string]*models.TrustedDevice{},
		errByToken:           map[string]error{},
		expiringExactlyAtNow: map[string]uuid.UUID{},
	}
}

func (f *fakeTrustedDevicePersister) Create(td models.TrustedDevice) error {
	if f.createErr != nil {
		return f.createErr
	}
	f.created = append(f.created, td)
	cp := td
	f.putRow(&cp)
	return nil
}

func (f *fakeTrustedDevicePersister) FindByDeviceToken(token string) (*models.TrustedDevice, error) {
	f.findByDeviceTokenCalls++
	if f.findErr != nil {
		return nil, f.findErr
	}
	if err := f.errByToken[token]; err != nil {
		return nil, err
	}
	return f.byToken[token], nil
}

// FindValidTrust mirrors the real persister's (device_token, user_id, expires_at > now) filter
// against this fake's in-memory rows, including the strict ">" on expiry.
func (f *fakeTrustedDevicePersister) FindValidTrust(deviceToken string, userID uuid.UUID, now time.Time) (*models.TrustedDevice, error) {
	f.findValidTrustCalls++
	if f.findErr != nil {
		return nil, f.findErr
	}
	if err := f.errByToken[deviceToken]; err != nil {
		return nil, err
	}
	for _, td := range f.rowsFor(deviceToken, now) {
		if td.UserID == userID && td.ExpiresAt.After(now) {
			return td, nil
		}
	}
	return nil, nil
}

func (f *fakeTrustedDevicePersister) rowsFor(deviceToken string, now time.Time) []*models.TrustedDevice {
	var rows []*models.TrustedDevice
	for _, td := range f.rows {
		if td.DeviceToken == deviceToken {
			rows = append(rows, td)
		}
	}
	if owner, ok := f.expiringExactlyAtNow[deviceToken]; ok {
		rows = append(rows, &models.TrustedDevice{
			ID:          uuid.Must(uuid.NewV4()),
			UserID:      owner,
			DeviceToken: deviceToken,
			ExpiresAt:   now,
		})
	}
	return rows
}

func (f *fakeTrustedDevicePersister) putRow(td *models.TrustedDevice) {
	f.rows = append(f.rows, td)
	// byToken backs FindByDeviceToken, the unscoped legacy lookup: first row seen for a token wins.
	if _, exists := f.byToken[td.DeviceToken]; !exists {
		f.byToken[td.DeviceToken] = td
	}
}

// store seeds a trusted device row for a user.
func (f *fakeTrustedDevicePersister) store(userID uuid.UUID, token string, expiresAt time.Time) {
	f.putRow(&models.TrustedDevice{
		ID:          uuid.Must(uuid.NewV4()),
		UserID:      userID,
		DeviceToken: token,
		ExpiresAt:   expiresAt,
	})
}

// storeExpiringExactlyAtNow seeds a row whose expires_at equals the instant it is looked up --
// the boundary the persister's "expires_at > now" must reject.
func (f *fakeTrustedDevicePersister) storeExpiringExactlyAtNow(userID uuid.UUID, token string) {
	f.expiringExactlyAtNow[token] = userID
}

// failFor makes every lookup of one device_token return an error, isolating a single branch of
// CheckDeviceTrust's OR.
func (f *fakeTrustedDevicePersister) failFor(token string, err error) {
	f.errByToken[token] = err
}

func newService(t *testing.T, persister *fakeTrustedDevicePersister, cookieValue string) DeviceTrustService {
	t.Helper()
	return newServiceWithCookies(t, persister, cookieValue, "")
}

// newServiceWithCookies sets the legacy (v0/v1) and v2 device cookies independently; "" models
// that cookie being absent. The combination that matters during the migration window -- both
// cookies present, disagreeing about this user -- cannot be expressed with a single-cookie
// helper, and is exactly the state that produces a mass re-challenge if CheckDeviceTrust
// dispatches on format instead of OR-ing results.
func newServiceWithCookies(t *testing.T, persister *fakeTrustedDevicePersister, legacyCookieValue, deviceCookieValue string) DeviceTrustService {
	t.Helper()

	cfg := config.Config{}
	cfg.MFA.DeviceTrustPolicy = "prompt"
	cfg.MFA.DeviceTrustCookieName = testCookieName
	cfg.MFA.DeviceTrustDeviceCookieName = testDeviceCookieName
	cfg.MFA.DeviceTrustDuration = time.Hour

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	if legacyCookieValue != "" {
		req.AddCookie(&http.Cookie{Name: testCookieName, Value: legacyCookieValue})
	}
	if deviceCookieValue != "" {
		req.AddCookie(&http.Cookie{Name: testDeviceCookieName, Value: deviceCookieValue})
	}
	c := e.NewContext(req, httptest.NewRecorder())

	return DeviceTrustService{Persister: persister, Cfg: cfg, HttpContext: c}
}

func randToken(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	_, err := rand.Read(b)
	require.NoError(t, err)
	// base64url uses [A-Za-z0-9-_=] -- none of which collide with the "|" and ":" separators.
	return base64.URLEncoding.EncodeToString(b)
}

// ---- Codec: the cookie has two readers (invariant I1) ----

// TestDeviceTrustCookie_RoundTrip is the I1 property: any composite cookie the serializer writes,
// the parser reads back identically, for 1..20 entries.
func TestDeviceTrustCookie_RoundTrip(t *testing.T) {
	svc := DeviceTrustService{}

	for n := 1; n <= 20; n++ {
		t.Run(fmt.Sprintf("%d_entries", n), func(t *testing.T) {
			want := make([]DeviceTrustEntry, n)
			for i := range want {
				want[i] = DeviceTrustEntry{UserID: uuid.Must(uuid.NewV4()), DeviceToken: randToken(t)}
			}

			got := svc.ParseDeviceTrustCookie(svc.SerializeDeviceTrustCookie(want))

			assert.Equal(t, want, got, "Parse(Serialize(x)) must be identity")
		})
	}
}

func TestSerializeDeviceTrustCookie_EmptyIsEmptyString(t *testing.T) {
	svc := DeviceTrustService{}
	assert.Equal(t, "", svc.SerializeDeviceTrustCookie(nil))
	assert.Equal(t, "", svc.SerializeDeviceTrustCookie([]DeviceTrustEntry{}))
}

func TestParseDeviceTrustCookie(t *testing.T) {
	svc := DeviceTrustService{}
	uid := uuid.Must(uuid.NewV4())

	t.Run("empty string parses to nil", func(t *testing.T) {
		assert.Nil(t, svc.ParseDeviceTrustCookie(""))
	})

	t.Run("legacy single token (no separators) parses to nil for the caller to migrate", func(t *testing.T) {
		assert.Nil(t, svc.ParseDeviceTrustCookie("a-single-legacy-token"))
	})

	t.Run("malformed entries are skipped, valid ones survive", func(t *testing.T) {
		good := uid.String() + ":goodtoken"
		value := "no-colon-here|" + good + "|not-a-uuid:tok"
		got := svc.ParseDeviceTrustCookie(value)
		require.Len(t, got, 1, "only the one well-formed, valid-uuid entry survives")
		assert.Equal(t, uid, got[0].UserID)
		assert.Equal(t, "goodtoken", got[0].DeviceToken)
	})

	t.Run("every entry malformed parses to empty", func(t *testing.T) {
		got := svc.ParseDeviceTrustCookie("not-a-uuid:tok|also-bad:tok2")
		assert.Empty(t, got)
	})
}

// ---- CheckDeviceTrust: expiry and cross-user isolation (invariant I2 / SEC-2) ----

func TestCheckDeviceTrust(t *testing.T) {
	userA := uuid.Must(uuid.NewV4())
	userB := uuid.Must(uuid.NewV4())
	future := time.Now().Add(time.Hour).UTC()
	past := time.Now().Add(-time.Hour).UTC()

	t.Run("nil user id is never trusted", func(t *testing.T) {
		svc := newService(t, newFakePersister(), "")
		assert.False(t, svc.CheckDeviceTrust(uuid.Nil))
	})

	t.Run("policy=never is never trusted even with a valid cookie", func(t *testing.T) {
		p := newFakePersister()
		tok := randToken(t)
		p.store(userA, tok, future)
		svc := newService(t, p, userA.String()+":"+tok)
		svc.Cfg.MFA.DeviceTrustPolicy = "never"
		assert.False(t, svc.CheckDeviceTrust(userA))
	})

	t.Run("no cookie is not trusted", func(t *testing.T) {
		svc := newService(t, newFakePersister(), "")
		assert.False(t, svc.CheckDeviceTrust(userA))
	})

	t.Run("valid composite cookie for the user is trusted", func(t *testing.T) {
		p := newFakePersister()
		tok := randToken(t)
		p.store(userA, tok, future)
		svc := newService(t, p, userA.String()+":"+tok)
		assert.True(t, svc.CheckDeviceTrust(userA))
	})

	// SEC-2: user B must not inherit user A's trust on a shared browser.
	t.Run("user B does not inherit user A's device trust", func(t *testing.T) {
		p := newFakePersister()
		tokA := randToken(t)
		p.store(userA, tokA, future)
		svc := newService(t, p, userA.String()+":"+tokA)
		assert.False(t, svc.CheckDeviceTrust(userB), "B must be challenged even though A trusted this browser")
	})

	// I2: an expired record is not honoured even with the cookie present.
	t.Run("expired trust record is rejected", func(t *testing.T) {
		p := newFakePersister()
		tok := randToken(t)
		p.store(userA, tok, past)
		svc := newService(t, p, userA.String()+":"+tok)
		assert.False(t, svc.CheckDeviceTrust(userA))
	})

	t.Run("cookie references a token with no DB record is not trusted", func(t *testing.T) {
		p := newFakePersister()
		svc := newService(t, p, userA.String()+":"+randToken(t))
		assert.False(t, svc.CheckDeviceTrust(userA))
	})

	// Legacy single-token format (invariant A3 / I1 second reader).
	t.Run("legacy single-token cookie still validates for its owner", func(t *testing.T) {
		p := newFakePersister()
		legacy := "legacytokennoseparators"
		p.store(userA, legacy, future)
		svc := newService(t, p, legacy)
		assert.True(t, svc.CheckDeviceTrust(userA))
	})

	t.Run("legacy single-token cookie does not validate for a different user", func(t *testing.T) {
		p := newFakePersister()
		legacy := "legacytokennoseparators"
		p.store(userA, legacy, future)
		svc := newService(t, p, legacy)
		assert.False(t, svc.CheckDeviceTrust(userB))
	})

	t.Run("expired legacy token is rejected", func(t *testing.T) {
		p := newFakePersister()
		legacy := "legacytokennoseparators"
		p.store(userA, legacy, past)
		svc := newService(t, p, legacy)
		assert.False(t, svc.CheckDeviceTrust(userA))
	})
}

// ---- CheckDeviceTrust across all three cookie formats (archon#2528) ----
//
// v2 (new)      "d1.<token>"                       in the device cookie   (DeviceTrustDeviceCookieName)
// v1 composite  "<uuid>:<tok>|<uuid>:<tok>|..."    in the legacy cookie   (DeviceTrustCookieName)
// v0 legacy     "<tok>" (bare, no separators)      in the legacy cookie
//
// All three coexist for the length of the migration window, so CheckDeviceTrust must be a
// logical OR over RESULTS: try v2, then v1, then v0, and answer false only once every applicable
// branch has been tried.

// TestCheckDeviceTrust_V2CookiePresentButOnlyV1TrustExists_StillTrusted is the deploy-day
// regression guard, and the single reason CheckDeviceTrust is an OR over results rather than a
// dispatch on cookie format.
//
// Picture a shared clinic workstation the morning after the deploy. Its legacy cookie still
// holds N colleagues' v1 entries. The first colleague to log in re-trusts the browser, and the
// browser now ALSO carries a v2 device cookie. Every other pre-deploy user on that machine still
// has only a v1 entry and no v2 row of their own: their trust rows are untouched and unexpired.
//
// An implementation that stops at the v2 branch because a v2 cookie merely exists and parses
// refuses all of them, and re-challenges an entire clinic for a full 2FA code -- the exact
// outcome this design exists to prevent. The v2 cookie here parses perfectly; its token simply
// has no row for THIS user, and the valid v1 entry underneath must still be honoured.
func TestCheckDeviceTrust_V2CookiePresentButOnlyV1TrustExists_StillTrusted(t *testing.T) {
	colleague := uuid.Must(uuid.NewV4())
	preDeployUser := uuid.Must(uuid.NewV4())
	future := time.Now().Add(time.Hour).UTC()

	p := newFakePersister()
	deviceToken := randToken(t)
	p.store(colleague, deviceToken, future) // the colleague who re-trusted after the deploy
	v1Token := randToken(t)
	p.store(preDeployUser, v1Token, future) // this user's pre-deploy trust: valid, and the only one they have

	svc := newServiceWithCookies(t, p,
		preDeployUser.String()+":"+v1Token,
		deviceTokenPrefix+deviceToken,
	)

	assert.True(t, svc.CheckDeviceTrust(preDeployUser),
		"a v2 cookie minted by someone else must not shadow this user's still-valid v1 trust")
}

func TestCheckDeviceTrust_CookieFormats(t *testing.T) {
	userA := uuid.Must(uuid.NewV4())
	userB := uuid.Must(uuid.NewV4())
	future := time.Now().Add(time.Hour).UTC()

	t.Run("v2 cookie with a matching valid row is trusted", func(t *testing.T) {
		p := newFakePersister()
		tok := randToken(t)
		p.store(userA, tok, future)
		svc := newServiceWithCookies(t, p, "", deviceTokenPrefix+tok)
		assert.True(t, svc.CheckDeviceTrust(userA))
	})

	// Guards the removal of the "no cookie -> return false" short-circuit: with two cookie names
	// in play, one absent cookie must not end the OR before the other branches are tried.
	t.Run("v2 cookie absent, valid v1 entry is still trusted", func(t *testing.T) {
		p := newFakePersister()
		tok := randToken(t)
		p.store(userA, tok, future)
		svc := newServiceWithCookies(t, p, userA.String()+":"+tok, "")
		assert.True(t, svc.CheckDeviceTrust(userA))
	})

	t.Run("v2 cookie absent, valid v0 bare token is still trusted", func(t *testing.T) {
		p := newFakePersister()
		legacy := "legacytokennoseparators"
		p.store(userA, legacy, future)
		svc := newServiceWithCookies(t, p, legacy, "")
		assert.True(t, svc.CheckDeviceTrust(userA))
	})

	t.Run("forged v2 cookie with no matching row is not trusted", func(t *testing.T) {
		p := newFakePersister()
		svc := newServiceWithCookies(t, p, "", deviceTokenPrefix+randToken(t))
		assert.NotPanics(t, func() {
			assert.False(t, svc.CheckDeviceTrust(userA))
		})
	})

	// The two cookies are read by name, never by shape: a v2-looking value that turns up under
	// the legacy name is a v0 bare token as far as the legacy branch is concerned, so the "d1."
	// prefix is NOT stripped and no row matches.
	t.Run("v2-shaped value under the legacy cookie name is not trusted", func(t *testing.T) {
		p := newFakePersister()
		tok := randToken(t)
		p.store(userA, tok, future)
		svc := newServiceWithCookies(t, p, deviceTokenPrefix+tok, "")
		assert.NotPanics(t, func() {
			assert.False(t, svc.CheckDeviceTrust(userA))
		})
	})

	// Fail closed, but fail closed for that branch only: a database error while checking v2 must
	// not deny a user whose v1 entry is perfectly valid.
	t.Run("a persister error on the v2 branch falls through to a valid v1 entry", func(t *testing.T) {
		p := newFakePersister()
		v2Token := randToken(t)
		v1Token := randToken(t)
		p.store(userA, v1Token, future)
		p.failFor(v2Token, fmt.Errorf("db down"))

		svc := newServiceWithCookies(t, p, userA.String()+":"+v1Token, deviceTokenPrefix+v2Token)
		assert.True(t, svc.CheckDeviceTrust(userA))
	})

	// SEC-2 under the v2 format: one device_token is now shared by every user who trusted the
	// browser, so the token alone can never be the trust decision -- the (device_token, user_id)
	// row is.
	t.Run("user B is not trusted by user A's v2 trust on the same device token", func(t *testing.T) {
		p := newFakePersister()
		tok := randToken(t)
		p.store(userA, tok, future)
		svc := newServiceWithCookies(t, p, "", deviceTokenPrefix+tok)
		assert.False(t, svc.CheckDeviceTrust(userB), "B must be challenged even though A trusted this browser")
	})

	t.Run("user B is trusted on the shared device token once B has a row of their own", func(t *testing.T) {
		p := newFakePersister()
		tok := randToken(t)
		p.store(userA, tok, future)
		p.store(userB, tok, future)
		svc := newServiceWithCookies(t, p, "", deviceTokenPrefix+tok)
		assert.True(t, svc.CheckDeviceTrust(userA))
		assert.True(t, svc.CheckDeviceTrust(userB))
	})

	// The persister filters expires_at > now, strictly. A row expiring at exactly the instant of
	// evaluation is expired.
	t.Run("expires_at exactly equal to now is not trusted", func(t *testing.T) {
		p := newFakePersister()
		tok := randToken(t)
		p.storeExpiringExactlyAtNow(userA, tok)
		svc := newServiceWithCookies(t, p, "", deviceTokenPrefix+tok)
		assert.False(t, svc.CheckDeviceTrust(userA))
	})

	t.Run("expired v2 row is not trusted", func(t *testing.T) {
		p := newFakePersister()
		tok := randToken(t)
		p.store(userA, tok, time.Now().Add(-time.Hour).UTC())
		svc := newServiceWithCookies(t, p, "", deviceTokenPrefix+tok)
		assert.False(t, svc.CheckDeviceTrust(userA))
	})

	t.Run("policy=never returns before any cookie or persister work", func(t *testing.T) {
		p := newFakePersister()
		tok := randToken(t)
		p.store(userA, tok, future)
		svc := newServiceWithCookies(t, p, userA.String()+":"+tok, deviceTokenPrefix+tok)
		svc.Cfg.MFA.DeviceTrustPolicy = "never"

		assert.False(t, svc.CheckDeviceTrust(userA))
		assert.Zero(t, p.findValidTrustCalls+p.findByDeviceTokenCalls,
			"policy=never must short-circuit before any lookup")
	})

	// ParseDeviceIDCookie rejects an empty remainder, so an empty device_token can never reach
	// the query -- asserted here at the call site rather than only at the parser.
	t.Run("an empty v2 token never reaches the persister", func(t *testing.T) {
		p := newFakePersister()
		svc := newServiceWithCookies(t, p, "", deviceTokenPrefix)
		assert.False(t, svc.CheckDeviceTrust(userA))
		assert.Zero(t, p.findValidTrustCalls, "\"d1.\" must not be queried as a device token")
	})

	// A cluster running the new binary against a config file written before
	// device_trust_device_cookie_name existed leaves the v2 name empty. The v2 branch must then
	// simply not match -- never look up a cookie named "" and never deny the v1/v0 branches.
	t.Run("an unconfigured v2 cookie name does not break the legacy branches", func(t *testing.T) {
		p := newFakePersister()
		tok := randToken(t)
		p.store(userA, tok, future)
		svc := newServiceWithCookies(t, p, userA.String()+":"+tok, deviceTokenPrefix+tok)
		svc.Cfg.MFA.DeviceTrustDeviceCookieName = ""

		assert.True(t, svc.CheckDeviceTrust(userA))
	})

	t.Run("both cookies absent is not trusted", func(t *testing.T) {
		p := newFakePersister()
		svc := newServiceWithCookies(t, p, "", "")
		assert.False(t, svc.CheckDeviceTrust(userA))
	})

	// The identity assertion is doubled on purpose (SQL predicate + Go re-check), but not the
	// query: one branch that validates costs exactly one lookup.
	t.Run("a validating branch costs a single lookup", func(t *testing.T) {
		p := newFakePersister()
		tok := randToken(t)
		p.store(userA, tok, future)
		svc := newServiceWithCookies(t, p, "", deviceTokenPrefix+tok)
		require.True(t, svc.CheckDeviceTrust(userA))
		assert.Equal(t, 1, p.findValidTrustCalls)
	})
}

// TestCheckDeviceTrust_RowForAnotherUserIsRejectedInGo pins requirement 3: the Go-side
// row.UserID == userID re-check on top of the SQL user_id predicate. It drives a persister that
// has "forgotten" to scope by user -- the shape a dropped predicate in the real query would take
// -- and asserts that CheckDeviceTrust still refuses. Without the re-check this is a total
// second-factor bypass: every user on a shared device inherits trust the moment one is trusted.
func TestCheckDeviceTrust_RowForAnotherUserIsRejectedInGo(t *testing.T) {
	userA := uuid.Must(uuid.NewV4())
	userB := uuid.Must(uuid.NewV4())
	tok := randToken(t)

	p := &unscopedPersister{row: &models.TrustedDevice{
		ID:          uuid.Must(uuid.NewV4()),
		UserID:      userA,
		DeviceToken: tok,
		ExpiresAt:   time.Now().Add(time.Hour).UTC(),
	}}
	svc := newServiceWithCookies(t, newFakePersister(), "", deviceTokenPrefix+tok)
	svc.Persister = p

	assert.False(t, svc.CheckDeviceTrust(userB),
		"a row belonging to another user must be rejected in Go even if the query returns it")
}

// unscopedPersister returns its one row for any (token, user) pair -- a persister whose user_id
// predicate has been lost.
type unscopedPersister struct {
	row *models.TrustedDevice
}

func (p *unscopedPersister) Create(models.TrustedDevice) error { return nil }
func (p *unscopedPersister) FindByDeviceToken(string) (*models.TrustedDevice, error) {
	return p.row, nil
}
func (p *unscopedPersister) FindValidTrust(string, uuid.UUID, time.Time) (*models.TrustedDevice, error) {
	return p.row, nil
}

// ---- CreateTrustedDevice: expiry derives from config (invariant I2 / A4) ----

func TestCreateTrustedDevice(t *testing.T) {
	userA := uuid.Must(uuid.NewV4())

	t.Run("stores a record whose expiry derives from config, not a constant", func(t *testing.T) {
		p := newFakePersister()
		svc := newService(t, p, "")
		svc.Cfg.MFA.DeviceTrustDuration = 48 * time.Hour

		before := time.Now().UTC()
		require.NoError(t, svc.CreateTrustedDevice(userA, "tok"))
		require.Len(t, p.created, 1)

		got := p.created[0]
		assert.Equal(t, userA, got.UserID)
		assert.Equal(t, "tok", got.DeviceToken)
		// Expiry ~ now + 48h; assert it tracks the configured duration, not a hardcoded 7d.
		assert.WithinDuration(t, before.Add(48*time.Hour), got.ExpiresAt, time.Minute)
	})

	t.Run("propagates a persister failure", func(t *testing.T) {
		p := newFakePersister()
		p.createErr = fmt.Errorf("db down")
		svc := newService(t, p, "")
		assert.Error(t, svc.CreateTrustedDevice(userA, "tok"))
	})
}

func TestGenerateRandomToken(t *testing.T) {
	svc := DeviceTrustService{}
	a, err := svc.GenerateRandomToken(64)
	require.NoError(t, err)
	b, err := svc.GenerateRandomToken(64)
	require.NoError(t, err)
	assert.NotEqual(t, a, b, "two tokens must differ")
	assert.NotEmpty(t, a)
}

// ---- MergeDeviceTrustEntries: the eviction boundary (invariant I3 / E1) ----

func makeEntries(t *testing.T, n int) []DeviceTrustEntry {
	t.Helper()
	out := make([]DeviceTrustEntry, n)
	for i := range out {
		out[i] = DeviceTrustEntry{UserID: uuid.Must(uuid.NewV4()), DeviceToken: fmt.Sprintf("tok-%d", i)}
	}
	return out
}

func TestMergeDeviceTrustEntries_ActingUserAlwaysSurvives(t *testing.T) {
	const maxUsers = 20

	for _, existingCount := range []int{0, 1, 19, 20, 21} {
		t.Run(fmt.Sprintf("%d_existing_users", existingCount), func(t *testing.T) {
			existing := makeEntries(t, existingCount)
			acting := DeviceTrustEntry{UserID: uuid.Must(uuid.NewV4()), DeviceToken: "acting-token"}

			merged := MergeDeviceTrustEntries(existing, acting, maxUsers)

			require.LessOrEqual(t, len(merged), maxUsers, "never exceeds the cap")
			assert.Equal(t, acting, merged[0], "the acting user is always first and therefore always survives truncation")

			if existingCount >= maxUsers {
				assert.Len(t, merged, maxUsers)
				// The oldest existing entry (last in the input) must have been evicted.
				oldest := existing[existingCount-1]
				for _, e := range merged {
					assert.NotEqual(t, oldest, e, "the oldest entry is the one evicted")
				}
			}
		})
	}
}

func TestMergeDeviceTrustEntries_ReTrustReplacesOwnEntry(t *testing.T) {
	uid := uuid.Must(uuid.NewV4())
	existing := []DeviceTrustEntry{
		{UserID: uid, DeviceToken: "old-token"},
		{UserID: uuid.Must(uuid.NewV4()), DeviceToken: "other"},
	}
	acting := DeviceTrustEntry{UserID: uid, DeviceToken: "new-token"}

	merged := MergeDeviceTrustEntries(existing, acting, 20)

	count := 0
	for _, e := range merged {
		if e.UserID == uid {
			count++
			assert.Equal(t, "new-token", e.DeviceToken, "the user's own entry is replaced, not duplicated")
		}
	}
	assert.Equal(t, 1, count, "re-trusting must not duplicate the user's entry")
	assert.Equal(t, acting, merged[0])
}

// ---- OQ3: device trust disabled for the login must write nothing (archon#1667) ----

func TestResolveTrustCookieEntries(t *testing.T) {
	existing := makeEntries(t, 20)
	acting := DeviceTrustEntry{UserID: uuid.Must(uuid.NewV4()), DeviceToken: "acting"}

	t.Run("positive lifetime is active and merges normally", func(t *testing.T) {
		entries, active := ResolveTrustCookieEntries(existing, acting, 20, 3600)
		require.True(t, active)
		assert.Equal(t, acting, entries[0])
		assert.Len(t, entries, 20)
	})

	// OQ3: the regression guard. Before the fix, a zero lifetime still wrote a phantom entry that
	// evicted a real user. It must now write nothing.
	t.Run("zero lifetime is inactive and writes nothing", func(t *testing.T) {
		entries, active := ResolveTrustCookieEntries(existing, acting, 20, 0)
		assert.False(t, active, "zero lifetime must not write a cookie -- archon#1667 OQ3")
		assert.Nil(t, entries, "no phantom entry may be produced")
	})

	t.Run("negative lifetime is inactive", func(t *testing.T) {
		_, active := ResolveTrustCookieEntries(existing, acting, 20, -1)
		assert.False(t, active)
	})
}

func TestMergeDeviceTrustEntries_NonPositiveMaxUsersFallsBackToDefault(t *testing.T) {
	existing := makeEntries(t, 25)
	acting := DeviceTrustEntry{UserID: uuid.Must(uuid.NewV4()), DeviceToken: "acting"}

	for _, maxUsers := range []int{0, -1} {
		merged := MergeDeviceTrustEntries(existing, acting, maxUsers)
		assert.Len(t, merged, DefaultMaxUsersPerDevice, "non-positive maxUsers falls back to the documented default of 20")
		assert.Equal(t, acting, merged[0])
	}
}

// ---- ParseDeviceIDCookie: v2 device-scoped cookie decode (archon#2528) ----

// TestParseDeviceIDCookie exercises the "d1." prefix that makes the v2 device-scoped cookie
// format unambiguous against v0 (bare token) and v1 (composite) values. Without the prefix,
// ParseDeviceTrustCookie's separator-based sniffing would misread a v2 value as v0 and route it
// to a single-row lookup, silently breaking trust for every other user on a shared device.
func TestParseDeviceIDCookie(t *testing.T) {
	uid := uuid.Must(uuid.NewV4())
	token := randToken(t)

	tests := []struct {
		name        string
		cookieValue string
		wantToken   string
		wantOK      bool
	}{
		{
			name:        "v2 device-scoped cookie decodes to its token",
			cookieValue: deviceTokenPrefix + token,
			wantToken:   token,
			wantOK:      true,
		},
		{
			name:        "prefix with empty remainder is rejected, never an empty token",
			cookieValue: deviceTokenPrefix,
			wantToken:   "",
			wantOK:      false,
		},
		{
			name:        "v0 legacy bare token has no prefix",
			cookieValue: token,
			wantToken:   "",
			wantOK:      false,
		},
		{
			name:        "v1 composite cookie is not a v2 value",
			cookieValue: uid.String() + fieldSeparator + token + entrySeparator + uid.String() + fieldSeparator + token,
			wantToken:   "",
			wantOK:      false,
		},
		{
			name:        "empty string",
			cookieValue: "",
			wantToken:   "",
			wantOK:      false,
		},
		{
			name:        "prefix appears mid-string but value does not start with it",
			cookieValue: "x" + deviceTokenPrefix + token,
			wantToken:   "",
			wantOK:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotToken, gotOK := ParseDeviceIDCookie(tt.cookieValue)
			assert.Equal(t, tt.wantOK, gotOK)
			assert.Equal(t, tt.wantToken, gotToken)
		})
	}
}
