package persistence

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/teamhanko/hanko/backend/v2/persistence/models"
)

// These tests cover the order in which TrustedDevicePersister.Create runs its three statements
// (upsertTrustedDevice), against an in-memory table that applies the same unique indexes Postgres
// does: no database. Whether each statement's SQL does what its name says is covered against
// Postgres in trusted_device_persister_integration_test.go.
//
// The table is modelled in both shapes Create must serve without a code change: with
// trusted_devices_token_user_idx on (device_token, user_id) still in place, as this release ships,
// and after archon#1085 task 34 drops it, leaving only the per-tenant partial indexes.

var (
	upsertTenantA = uuid.FromStringOrNil("aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa")
	upsertTenantB = uuid.FromStringOrNil("bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb")
	upsertUserID  = uuid.FromStringOrNil("cccccccc-3333-4333-8333-cccccccccccc")
	upsertToken   = strings.Repeat("u", 64)
	upsertNow     = time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)
)

type fakeTrustTable struct {
	rows []models.TrustedDevice
	// pairIndex models trusted_devices_token_user_idx: one row per (device_token, user_id).
	pairIndex bool
	// concurrent is a row another transaction commits just before this one inserts.
	concurrent *models.TrustedDevice
	failOn     string
	calls      []string
}

func (f *fakeTrustTable) samePair(row, td models.TrustedDevice) bool {
	return row.DeviceToken == td.DeviceToken && row.UserID == td.UserID
}

func (f *fakeTrustTable) refresh(td models.TrustedDevice) (int, error) {
	f.calls = append(f.calls, "refresh")
	if f.failOn == "refresh" {
		return 0, errors.New("refresh failed")
	}
	n := 0
	for i := range f.rows {
		if f.samePair(f.rows[i], td) && f.rows[i].MatchesTenant(td.TenantID) {
			f.rows[i].ExpiresAt = td.ExpiresAt
			f.rows[i].UpdatedAt = td.UpdatedAt
			n++
		}
	}
	return n, nil
}

func (f *fakeTrustTable) insertIfAbsent(td models.TrustedDevice) (int, error) {
	f.calls = append(f.calls, "insert")
	if f.failOn == "insert" {
		return 0, errors.New("insert failed")
	}
	if f.concurrent != nil {
		f.rows = append(f.rows, *f.concurrent)
		f.concurrent = nil
	}
	for _, row := range f.rows {
		// The per-tenant partial indexes key (device_token, user_id, tenant_id), NULL tenants
		// together; the pair index keys (device_token, user_id) alone.
		if f.samePair(row, td) && (f.pairIndex || row.MatchesTenant(td.TenantID)) {
			return 0, nil
		}
	}
	f.rows = append(f.rows, td)
	return 1, nil
}

func (f *fakeTrustTable) moveToTenant(td models.TrustedDevice) (int, error) {
	f.calls = append(f.calls, "move")
	latest := -1
	for i := range f.rows {
		if f.samePair(f.rows[i], td) && (latest < 0 || f.rows[i].ExpiresAt.After(f.rows[latest].ExpiresAt)) {
			latest = i
		}
	}
	if latest < 0 {
		return 0, nil
	}
	f.rows[latest].TenantID = td.TenantID
	f.rows[latest].ExpiresAt = td.ExpiresAt
	f.rows[latest].UpdatedAt = td.UpdatedAt
	return 1, nil
}

func trustRow(tenantID *uuid.UUID, expiresIn time.Duration) models.TrustedDevice {
	return models.TrustedDevice{
		ID:          uuid.Must(uuid.NewV4()),
		UserID:      upsertUserID,
		TenantID:    tenantID,
		DeviceToken: upsertToken,
		ExpiresAt:   upsertNow.Add(expiresIn),
		CreatedAt:   upsertNow,
		UpdatedAt:   upsertNow,
	}
}

func TestUpsertTrustedDevice_FirstTrustInserts(t *testing.T) {
	table := &fakeTrustTable{pairIndex: true}

	require.NoError(t, upsertTrustedDevice(table, trustRow(&upsertTenantA, time.Hour)))

	require.Len(t, table.rows, 1)
	assert.Equal(t, &upsertTenantA, table.rows[0].TenantID)
	assert.Equal(t, []string{"refresh", "insert"}, table.calls)
}

func TestUpsertTrustedDevice_ReTrustUnderTheSameTenantRefreshesTheRow(t *testing.T) {
	for _, tenantID := range []*uuid.UUID{&upsertTenantA, nil} {
		existing := trustRow(tenantID, time.Hour)
		table := &fakeTrustTable{pairIndex: true, rows: []models.TrustedDevice{existing}}

		require.NoError(t, upsertTrustedDevice(table, trustRow(tenantID, 7*time.Hour)))

		require.Len(t, table.rows, 1)
		assert.Equal(t, existing.ID, table.rows[0].ID, "the row is refreshed in place, not replaced")
		assert.Equal(t, upsertNow.Add(7*time.Hour), table.rows[0].ExpiresAt)
		assert.Equal(t, []string{"refresh"}, table.calls)
	}
}

// While trusted_devices_token_user_idx stands, one browser holds one trust row per user. Before
// keep_users_global is on (archon#1085 task 34) a user belongs to one tenant, so this is reached
// only between a flow with that tenant and one without; trust follows the flow that trusted last.
func TestUpsertTrustedDevice_WhileThePairIndexStandsTrustFollowsTheLatestTenant(t *testing.T) {
	cases := []struct {
		name   string
		from   *uuid.UUID
		to     *uuid.UUID
		wantTo *uuid.UUID
	}{
		{"from a tenant to another", &upsertTenantA, &upsertTenantB, &upsertTenantB},
		{"from no tenant to a tenant", nil, &upsertTenantA, &upsertTenantA},
		{"from a tenant to no tenant", &upsertTenantA, nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			existing := trustRow(tc.from, time.Hour)
			table := &fakeTrustTable{pairIndex: true, rows: []models.TrustedDevice{existing}}

			require.NoError(t, upsertTrustedDevice(table, trustRow(tc.to, 7*time.Hour)))

			require.Len(t, table.rows, 1, "the pair index allows one row per browser and user")
			assert.Equal(t, existing.ID, table.rows[0].ID)
			assert.Equal(t, tc.wantTo, table.rows[0].TenantID, "trust must follow the latest tenant")
			assert.Equal(t, upsertNow.Add(7*time.Hour), table.rows[0].ExpiresAt)
			assert.Equal(t, []string{"refresh", "insert", "refresh", "move"}, table.calls)
		})
	}
}

// Once task 34 drops the pair index, the same code keeps one row per tenant side by side.
func TestUpsertTrustedDevice_WithoutThePairIndexTenantsCoexist(t *testing.T) {
	existing := trustRow(&upsertTenantA, time.Hour)
	table := &fakeTrustTable{pairIndex: false, rows: []models.TrustedDevice{existing}}

	require.NoError(t, upsertTrustedDevice(table, trustRow(&upsertTenantB, 7*time.Hour)))

	require.Len(t, table.rows, 2)
	assert.Equal(t, existing, table.rows[0], "A's trust must be left alone")
	assert.Equal(t, &upsertTenantB, table.rows[1].TenantID)
	assert.Equal(t, []string{"refresh", "insert"}, table.calls)
}

// Two logins of the same user on the same browser and tenant race: the other one inserts first.
// Ours must refresh that row, and must not touch another tenant's row of the same browser.
func TestUpsertTrustedDevice_ConcurrentTrustOfTheSameTenantIsRefreshed(t *testing.T) {
	other := trustRow(&upsertTenantB, 9*time.Hour)
	racer := trustRow(&upsertTenantA, time.Hour)
	table := &fakeTrustTable{pairIndex: false, rows: []models.TrustedDevice{other}, concurrent: &racer}

	require.NoError(t, upsertTrustedDevice(table, trustRow(&upsertTenantA, 7*time.Hour)))

	require.Len(t, table.rows, 2)
	assert.Equal(t, other, table.rows[0], "another tenant's trust must be left alone")
	assert.Equal(t, racer.ID, table.rows[1].ID)
	assert.Equal(t, upsertNow.Add(7*time.Hour), table.rows[1].ExpiresAt)
	assert.Equal(t, []string{"refresh", "insert", "refresh"}, table.calls)
}

func TestUpsertTrustedDevice_StopsAtTheFirstFailure(t *testing.T) {
	for _, step := range []string{"refresh", "insert"} {
		table := &fakeTrustTable{pairIndex: true, failOn: step}

		err := upsertTrustedDevice(table, trustRow(&upsertTenantA, time.Hour))

		require.Error(t, err)
		assert.Equal(t, step, table.calls[len(table.calls)-1], "no statement may run after a failed one")
	}
}
