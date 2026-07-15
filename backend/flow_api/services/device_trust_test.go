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

const testCookieName = "clinicos-2fa-device-token"

// fakeTrustedDevicePersister is the whole persistence dependency of DeviceTrustService. The
// interface is two methods, which is what lets the entire service be tested with no Postgres.
type fakeTrustedDevicePersister struct {
	byToken   map[string]*models.TrustedDevice
	created   []models.TrustedDevice
	createErr error
	findErr   error
}

func newFakePersister() *fakeTrustedDevicePersister {
	return &fakeTrustedDevicePersister{byToken: map[string]*models.TrustedDevice{}}
}

func (f *fakeTrustedDevicePersister) Create(td models.TrustedDevice) error {
	if f.createErr != nil {
		return f.createErr
	}
	f.created = append(f.created, td)
	cp := td
	f.byToken[td.DeviceToken] = &cp
	return nil
}

func (f *fakeTrustedDevicePersister) FindByDeviceToken(token string) (*models.TrustedDevice, error) {
	if f.findErr != nil {
		return nil, f.findErr
	}
	return f.byToken[token], nil
}

// store seeds a live (unexpired) trusted device for a user.
func (f *fakeTrustedDevicePersister) store(userID uuid.UUID, token string, expiresAt time.Time) {
	f.byToken[token] = &models.TrustedDevice{
		ID:          uuid.Must(uuid.NewV4()),
		UserID:      userID,
		DeviceToken: token,
		ExpiresAt:   expiresAt,
	}
}

func newService(t *testing.T, persister *fakeTrustedDevicePersister, cookieValue string) DeviceTrustService {
	t.Helper()

	cfg := config.Config{}
	cfg.MFA.DeviceTrustPolicy = "prompt"
	cfg.MFA.DeviceTrustCookieName = testCookieName
	cfg.MFA.DeviceTrustDuration = time.Hour

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	if cookieValue != "" {
		req.AddCookie(&http.Cookie{Name: testCookieName, Value: cookieValue})
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
