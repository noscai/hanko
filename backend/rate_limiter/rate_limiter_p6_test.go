package rate_limiter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sethvargo/go-limiter"
	"github.com/sethvargo/go-limiter/httplimit"
	"github.com/sethvargo/go-limiter/memorystore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/teamhanko/hanko/backend/v2/config"
)

func newMemStore(t *testing.T, tokens uint64, interval time.Duration) limiter.Store {
	t.Helper()
	store, err := memorystore.New(&memorystore.Config{Tokens: tokens, Interval: interval})
	require.NoError(t, err)
	return store
}

// NewRateLimiter returns a redis-backed store when configured for redis. redisstore.New is lazy --
// it never dials until Take -- so constructing it without a live redis is safe as long as we never
// draw from it here.
func TestNewRateLimiter_Redis(t *testing.T) {
	store := NewRateLimiter(
		config.RateLimiter{
			Store: config.RATE_LIMITER_STORE_REDIS,
			Redis: &config.RedisConfig{Address: "localhost:6379"},
		},
		config.RateLimits{Tokens: 5, Interval: time.Minute},
	)
	require.NotNil(t, store, "redis store must be constructed without dialing")
}

func newEchoContext() echo.Context {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rec := httptest.NewRecorder()
	return e.NewContext(req, rec)
}

// Limit sets the rate-limit headers and permits the request while tokens remain.
func TestLimit_Allows_SetsHeaders(t *testing.T) {
	store := newMemStore(t, 5, time.Minute)
	c := newEchoContext()
	userID := uuid.Must(uuid.NewV4())

	err := Limit(store, userID, c)

	require.NoError(t, err)
	assert.Equal(t, "5", c.Response().Header().Get(httplimit.HeaderRateLimitLimit))
	assert.NotEmpty(t, c.Response().Header().Get(httplimit.HeaderRateLimitRemaining))
	assert.Empty(t, c.Response().Header().Get(httplimit.HeaderRetryAfter), "retry-after only set when denied")
}

// Limit returns 429 and a Retry-After header once the bucket is exhausted.
func TestLimit_Denies_WhenExhausted(t *testing.T) {
	store := newMemStore(t, 1, time.Minute)
	userID := uuid.Must(uuid.NewV4())

	require.NoError(t, Limit(store, userID, newEchoContext()))

	c := newEchoContext()
	err := Limit(store, userID, c)

	require.Error(t, err)
	he, ok := err.(*echo.HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusTooManyRequests, he.Code)
	assert.NotEmpty(t, c.Response().Header().Get(httplimit.HeaderRetryAfter))
}

// A stopped store makes store.Take fail -- Limit propagates that backend error.
func TestLimit_StoreError_Propagates(t *testing.T) {
	store := newMemStore(t, 5, time.Minute)
	require.NoError(t, store.Close(context.Background()))

	err := Limit(store, uuid.Must(uuid.NewV4()), newEchoContext())
	require.Error(t, err)
	assert.Equal(t, limiter.ErrStopped, err)
}

// Limit2 permits and reports a retry-after seconds figure while tokens remain.
func TestLimit2_Allows(t *testing.T) {
	store := newMemStore(t, 5, time.Minute)

	retryAfter, ok, err := Limit2(store, "k1")

	require.NoError(t, err)
	assert.True(t, ok)
	assert.GreaterOrEqual(t, retryAfter, 0)
}

// Limit2 denies once the single token is consumed.
func TestLimit2_Denies_WhenExhausted(t *testing.T) {
	store := newMemStore(t, 1, time.Minute)

	_, ok, err := Limit2(store, "same-key")
	require.NoError(t, err)
	require.True(t, ok)

	_, ok, err = Limit2(store, "same-key")
	require.NoError(t, err)
	assert.False(t, ok, "second take on a 1-token bucket must be denied")
}

// A stopped store makes Limit2 return -1 and a wrapped backend error.
func TestLimit2_StoreError(t *testing.T) {
	store := newMemStore(t, 5, time.Minute)
	require.NoError(t, store.Close(context.Background()))

	retryAfter, ok, err := Limit2(store, "boom")
	require.Error(t, err)
	assert.False(t, ok)
	assert.Equal(t, -1, retryAfter)
	assert.Contains(t, err.Error(), "boom")
}

func TestRateLimitKeyBuilders(t *testing.T) {
	assert.Equal(t, "passcode/1.2.3.4/a@b.de", CreateRateLimitPasscodeKey("1.2.3.4", "a@b.de"))
	assert.Equal(t, "password/1.2.3.4/uid", CreateRateLimitPasswordKey("1.2.3.4", "uid"))
	assert.Equal(t, "otp/1.2.3.4/uid", CreateRateLimitOTPKey("1.2.3.4", "uid"))
	assert.Equal(t, "token_exchange/1.2.3.4", CreateRateLimitTokenExchangeKey("1.2.3.4"))
	assert.Equal(t, "service_token/1.2.3.4", CreateRateLimitServiceTokenKey("1.2.3.4"))
}
