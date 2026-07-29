package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/teamhanko/hanko/backend/v2/config"
	"github.com/teamhanko/hanko/backend/v2/persistence"
	"github.com/teamhanko/hanko/backend/v2/persistence/models"
)

// These tests drive the multi-tenant resolution middleware -- the code that populates the tenant
// context every authenticated flow action later reads through deps.TenantID (archon#1668/#1874).
// The header -> lookup -> auto-provision -> enabled decision tree is exercised without a database
// by faking the tenant persister.

// fakeTenantPersister satisfies persistence.TenantPersister via embedding; only Get and Create --
// the two methods the middleware calls -- are real.
type fakeTenantPersister struct {
	persistence.TenantPersister
	tenant    *models.Tenant
	getErr    error
	createErr error
	created   *models.Tenant
}

func (f *fakeTenantPersister) Get(id uuid.UUID) (*models.Tenant, error) {
	return f.tenant, f.getErr
}

func (f *fakeTenantPersister) Create(tenant models.Tenant) error {
	if f.createErr != nil {
		return f.createErr
	}
	f.created = &tenant
	return nil
}

// fakePersister satisfies persistence.Persister via embedding; only GetTenantPersister is real.
type fakePersister struct {
	persistence.Persister
	tp *fakeTenantPersister
}

func (f *fakePersister) GetTenantPersister() persistence.TenantPersister {
	return f.tp
}

const testTenantHeader = "X-Tenant-ID"

var testTenantID = uuid.Must(uuid.FromString("aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"))

func runTenantMW(t *testing.T, cfg config.MultiTenant, p persistence.Persister, headerVal string) (bool, echo.Context, error) {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if headerVal != "" {
		hn := cfg.TenantHeader
		if hn == "" {
			hn = testTenantHeader
		}
		req.Header.Set(hn, headerVal)
	}
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	nextCalled := false
	handler := Tenant(cfg, p)(func(ec echo.Context) error {
		nextCalled = true
		return nil
	})
	err := handler(c)
	return nextCalled, c, err
}

func httpErrCode(t *testing.T, err error) int {
	t.Helper()
	require.Error(t, err)
	var he *echo.HTTPError
	require.True(t, errors.As(err, &he), "expected an *echo.HTTPError, got %T", err)
	return he.Code
}

// When multi-tenant mode is off the middleware is a pass-through: no header is read, no tenant is
// set, next always runs.
func TestTenant_Disabled_IsNoOp(t *testing.T) {
	cfg := config.MultiTenant{Enabled: false}
	next, c, err := runTenantMW(t, cfg, &fakePersister{tp: &fakeTenantPersister{}}, "")

	require.NoError(t, err)
	assert.True(t, next, "disabled middleware must call next")
	assert.Nil(t, GetTenantID(c), "no tenant id may be set when disabled")
	assert.Nil(t, GetTenant(c))
}

// A valid header resolving to an enabled tenant sets both context keys and continues.
func TestTenant_ExistingEnabledTenant_SetsContext(t *testing.T) {
	cfg := config.MultiTenant{Enabled: true, TenantHeader: testTenantHeader}
	tenant := &models.Tenant{ID: testTenantID, Name: "Acme", Enabled: true}
	tp := &fakeTenantPersister{tenant: tenant}

	next, c, err := runTenantMW(t, cfg, &fakePersister{tp: tp}, testTenantID.String())

	require.NoError(t, err)
	assert.True(t, next)
	require.NotNil(t, GetTenantID(c))
	assert.Equal(t, testTenantID, *GetTenantID(c))
	assert.Equal(t, tenant, GetTenant(c))
}

// A disabled tenant is rejected with 403 even though it exists.
func TestTenant_DisabledTenant_Forbidden(t *testing.T) {
	cfg := config.MultiTenant{Enabled: true, TenantHeader: testTenantHeader}
	tp := &fakeTenantPersister{tenant: &models.Tenant{ID: testTenantID, Enabled: false}}

	next, _, err := runTenantMW(t, cfg, &fakePersister{tp: tp}, testTenantID.String())

	assert.False(t, next, "a disabled tenant must not reach next")
	assert.Equal(t, http.StatusForbidden, httpErrCode(t, err))
}

// A malformed (non-UUID) header value is a 400 before any lookup.
func TestTenant_InvalidUUIDHeader_BadRequest(t *testing.T) {
	cfg := config.MultiTenant{Enabled: true, TenantHeader: testTenantHeader}
	next, _, err := runTenantMW(t, cfg, &fakePersister{tp: &fakeTenantPersister{}}, "not-a-uuid")

	assert.False(t, next)
	assert.Equal(t, http.StatusBadRequest, httpErrCode(t, err))
}

// A persister failure during lookup surfaces as 500.
func TestTenant_LookupError_InternalServerError(t *testing.T) {
	cfg := config.MultiTenant{Enabled: true, TenantHeader: testTenantHeader}
	tp := &fakeTenantPersister{getErr: errors.New("db down")}

	next, _, err := runTenantMW(t, cfg, &fakePersister{tp: tp}, testTenantID.String())

	assert.False(t, next)
	assert.Equal(t, http.StatusInternalServerError, httpErrCode(t, err))
}

// Unknown tenant + auto-provision disabled -> 404.
func TestTenant_UnknownTenant_NoAutoProvision_NotFound(t *testing.T) {
	cfg := config.MultiTenant{Enabled: true, TenantHeader: testTenantHeader, AutoProvision: false}
	tp := &fakeTenantPersister{tenant: nil}

	next, _, err := runTenantMW(t, cfg, &fakePersister{tp: tp}, testTenantID.String())

	assert.False(t, next)
	assert.Equal(t, http.StatusNotFound, httpErrCode(t, err))
}

// Unknown tenant + auto-provision enabled -> a new enabled tenant is created and the context is set.
func TestTenant_UnknownTenant_AutoProvision_CreatesTenant(t *testing.T) {
	cfg := config.MultiTenant{Enabled: true, TenantHeader: testTenantHeader, AutoProvision: true}
	tp := &fakeTenantPersister{tenant: nil}

	next, c, err := runTenantMW(t, cfg, &fakePersister{tp: tp}, testTenantID.String())

	require.NoError(t, err)
	assert.True(t, next)
	require.NotNil(t, tp.created, "auto-provision must create a tenant")
	assert.Equal(t, testTenantID, tp.created.ID)
	assert.True(t, tp.created.Enabled, "auto-provisioned tenant must be enabled")
	require.NotNil(t, GetTenantID(c))
	assert.Equal(t, testTenantID, *GetTenantID(c))
	// The middleware stores the FULL tenant object after auto-provision
	// (tenant.go: c.Set(TenantContextKey, tenant)), not just its id. Assert
	// GetTenant(c) too, so a regression that stops storing the object — leaving
	// downstream handlers with a nil tenant — is caught (cubic P3).
	provisioned := GetTenant(c)
	require.NotNil(t, provisioned, "auto-provision must store the full tenant object in context")
	assert.Equal(t, testTenantID, provisioned.ID)
	assert.True(t, provisioned.Enabled, "the stored tenant must be enabled")
}

// Unknown tenant + auto-provision enabled but Create fails -> 500.
func TestTenant_AutoProvisionCreateError_InternalServerError(t *testing.T) {
	cfg := config.MultiTenant{Enabled: true, TenantHeader: testTenantHeader, AutoProvision: true}
	tp := &fakeTenantPersister{tenant: nil, createErr: errors.New("insert failed")}

	next, _, err := runTenantMW(t, cfg, &fakePersister{tp: tp}, testTenantID.String())

	assert.False(t, next)
	assert.Equal(t, http.StatusInternalServerError, httpErrCode(t, err))
}

// No header + global users allowed -> pass through, no tenant set.
func TestTenant_NoHeader_GlobalUsersAllowed_PassesThrough(t *testing.T) {
	cfg := config.MultiTenant{Enabled: true, TenantHeader: testTenantHeader, AllowGlobalUsers: true}
	next, c, err := runTenantMW(t, cfg, &fakePersister{tp: &fakeTenantPersister{}}, "")

	require.NoError(t, err)
	assert.True(t, next)
	assert.Nil(t, GetTenantID(c), "global-user request must leave tenant id unset")
}

// No header + global users disallowed -> 400, the header is mandatory.
func TestTenant_NoHeader_GlobalUsersDisallowed_BadRequest(t *testing.T) {
	cfg := config.MultiTenant{Enabled: true, TenantHeader: testTenantHeader, AllowGlobalUsers: false}
	next, _, err := runTenantMW(t, cfg, &fakePersister{tp: &fakeTenantPersister{}}, "")

	assert.False(t, next)
	assert.Equal(t, http.StatusBadRequest, httpErrCode(t, err))
}

// GetTenantID / GetTenant return nil when the context carries nothing (or the wrong type).
func TestGetTenantHelpers_Unset(t *testing.T) {
	e := echo.New()
	c := e.NewContext(httptest.NewRequest(http.MethodGet, "/", nil), httptest.NewRecorder())

	assert.Nil(t, GetTenantID(c))
	assert.Nil(t, GetTenant(c))

	// Wrong type stored under the keys is treated as unset, never a panic.
	c.Set(TenantIDContextKey, "not-a-uuid-pointer")
	c.Set(TenantContextKey, 42)
	assert.Nil(t, GetTenantID(c))
	assert.Nil(t, GetTenant(c))
}
