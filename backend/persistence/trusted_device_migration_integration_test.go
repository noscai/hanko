package persistence_test

// This file uses the external "persistence_test" package (not "persistence")
// because test.Suite (in package "test") imports package "persistence" for
// its Storage type -- an internal test file here (package "persistence")
// importing "test" would create an import cycle (persistence -> test ->
// persistence), which `go vet` rejects. None of the exported symbols this
// test needs are unexported, so the external package works without issue.

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/suite"
	"github.com/teamhanko/hanko/backend/v2/config"
	"github.com/teamhanko/hanko/backend/v2/persistence"
	"github.com/teamhanko/hanko/backend/v2/persistence/models"
	"github.com/teamhanko/hanko/backend/v2/test"
)

// TestTrustedDeviceMigrationSuite exercises the migration that adds a unique
// index on trusted_devices (device_token, user_id) -- see
// 20260828085758_add_trusted_devices_token_user_unique.{up,down}.fizz.
//
// This is the highest-risk migration in the device-trust-cookie-cap plan:
// hanko's Kubernetes deployment runs `hanko migrate up` as an initContainer,
// so a CREATE UNIQUE INDEX that hits a duplicate would fail the migration and
// take down login for every user, not just 2FA users. Analysis says
// duplicate (device_token, user_id) pairs cannot exist because every
// revision of the write path mints a fresh random token, but that only
// covers rows hanko's own code wrote -- not manual edits, imports, or a
// partial restore. This test proves the migration's defensive dedupe step
// makes the index-creation safe even if that assumption is ever wrong.
func TestTrustedDeviceMigrationSuite(t *testing.T) {
	t.Parallel()
	suite.Run(t, new(trustedDeviceMigrationSuite))
}

type trustedDeviceMigrationSuite struct {
	test.Suite
}

func (s *trustedDeviceMigrationSuite) connectWithOptions(options string) persistence.Storage {
	u, err := url.Parse(s.DB.DatabaseUrl)
	s.Require().NoError(err)
	q := u.Query()
	q.Set("options", options)
	u.RawQuery = q.Encode()
	storage, err := persistence.New(config.Database{Url: u.String()})
	s.Require().NoError(err)
	return storage
}

// fixtureUserID matches test/fixtures/user/users.yaml, loaded below to
// satisfy trusted_devices.user_id's FK to users.id.
const fixtureUserID = "b5dd5267-b462-48be-b70d-bcd6f1bbe7a5"

func (s *trustedDeviceMigrationSuite) TestTenantMigration_RunsUnderLiveTrafficBelowTheSizeGate() {
	if testing.Short() {
		s.T().Skip("requires disposable PostgreSQL")
	}
	s.Require().NoError(s.Storage.MigrateDown(3))
	s.Require().NoError(s.LoadFixtures("../test/fixtures/user"))
	_, err := s.insertTrustedDevice(strings.Repeat("m", 64), uuid.FromStringOrNil(fixtureUserID), time.Now().UTC().Add(time.Hour))
	s.Require().NoError(err)
	s.Require().NoError(s.Storage.MigrateUp(), "a cluster below the size gate migrates without a drain")
}

func (s *trustedDeviceMigrationSuite) TestTenantMigration_RefusesAboveTheSizeGateWithoutMaintenanceAcknowledgement() {
	if testing.Short() {
		s.T().Skip("requires disposable PostgreSQL")
	}
	s.Require().NoError(s.Storage.MigrateDown(3))
	s.Require().NoError(s.LoadFixtures("../test/fixtures/user"))
	_, err := s.insertTrustedDevice(strings.Repeat("m", 64), uuid.FromStringOrNil(fixtureUserID), time.Now().UTC().Add(time.Hour))
	s.Require().NoError(err)
	overGate := s.connectWithOptions("-c hanko.trust_migration_max_live_rows=0")
	defer overGate.GetConnection().Close()
	s.Require().ErrorContains(overGate.MigrateUp(), "too large to migrate under live login traffic")
	acknowledged := s.connectWithOptions("-c hanko.trust_migration_max_live_rows=0 -c hanko.trusted_device_maintenance=on")
	defer acknowledged.GetConnection().Close()
	s.Require().NoError(acknowledged.MigrateUp(), "explicit maintenance acknowledgement permits the same migration")
}

func (s *trustedDeviceMigrationSuite) TestTenantMigration_SizeGateCountsOnlyLiveTrust() {
	if testing.Short() {
		s.T().Skip("requires disposable PostgreSQL")
	}
	s.Require().NoError(s.Storage.MigrateDown(3))
	s.Require().NoError(s.LoadFixtures("../test/fixtures/user"))
	_, err := s.insertTrustedDevice(strings.Repeat("e", 64), uuid.FromStringOrNil(fixtureUserID), time.Now().UTC().Add(-time.Hour))
	s.Require().NoError(err)
	overGate := s.connectWithOptions("-c hanko.trust_migration_max_live_rows=0")
	defer overGate.GetConnection().Close()
	s.Require().NoError(overGate.MigrateUp(), "expired rows are pruned, not counted")
}

func (s *trustedDeviceMigrationSuite) TestTenantMigration_PrunesOnlyExpiredUTCTrustInAnotherTimeZone() {
	if testing.Short() {
		s.T().Skip("requires disposable PostgreSQL")
	}
	s.Require().NoError(s.Storage.MigrateDown(3))
	s.Require().NoError(s.LoadFixtures("../test/fixtures/user"))
	userID := uuid.FromStringOrNil(fixtureUserID)
	live, err := s.insertTrustedDevice(strings.Repeat("z", 64), userID, time.Now().UTC().Add(time.Hour))
	s.Require().NoError(err)
	_, err = s.insertTrustedDevice(strings.Repeat("y", 64), userID, time.Now().UTC().Add(-time.Hour))
	s.Require().NoError(err)
	zoned := s.connectWithOptions("-c TimeZone=Asia/Tokyo")
	defer zoned.GetConnection().Close()
	s.Require().NoError(zoned.MigrateUp())
	var ids []struct {
		ID uuid.UUID `db:"id"`
	}
	s.Require().NoError(zoned.GetConnection().RawQuery("SELECT id FROM trusted_devices WHERE user_id = ?", userID).All(&ids))
	s.Require().Len(ids, 1)
	s.Equal(live, ids[0].ID)
}

func (s *trustedDeviceMigrationSuite) TestMigration_DedupesTrustedDevicesBeforeCreatingUniqueIndex() {
	if testing.Short() {
		s.T().Skip("skipping test in short mode.")
	}

	// SetupTest() already ran MigrateUp(), which means the migration under
	// test has already run and its unique index already exists -- so we
	// can't insert duplicate (device_token, user_id) rows yet. Roll back
	// that migration so duplicates can be inserted with raw SQL, then
	// re-apply it and assert on the outcome. Four steps, because the
	// tenant-id, revocation and pair-index-drop migrations run after it
	// (the last one's down recreates this index); rolling back all four
	// returns the table to the schema this migration first ran against.
	s.Require().NoError(s.Storage.MigrateDown(4))

	s.Require().NoError(s.LoadFixtures("../test/fixtures/user"))

	userID := uuid.FromStringOrNil(fixtureUserID)
	s.Require().False(userID.IsNil())

	now := time.Now().UTC().Truncate(time.Second)

	dupToken := strings.Repeat("a", 64)
	tieToken := strings.Repeat("b", 64)
	uniqueToken := strings.Repeat("c", 64)

	// Group 1: two rows for the same (device_token, user_id) pair with
	// different expires_at -- the later expiry must be the survivor.
	olderID, err := s.insertTrustedDevice(dupToken, userID, now.Add(1*time.Hour))
	s.Require().NoError(err)
	newerID, err := s.insertTrustedDevice(dupToken, userID, now.Add(7*24*time.Hour))
	s.Require().NoError(err)

	// Group 2: two rows with an identical expires_at, to exercise the
	// `id DESC` tiebreak (otherwise the survivor would be arbitrary).
	var tieLowID, tieHighID uuid.UUID
	tieA, err := s.insertTrustedDevice(tieToken, userID, now.Add(2*time.Hour))
	s.Require().NoError(err)
	tieB, err := s.insertTrustedDevice(tieToken, userID, now.Add(2*time.Hour))
	s.Require().NoError(err)
	if tieA.String() > tieB.String() {
		tieHighID, tieLowID = tieA, tieB
	} else {
		tieHighID, tieLowID = tieB, tieA
	}
	_ = tieLowID

	// A pair that is already unique -- must be left completely untouched.
	untouchedID, err := s.insertTrustedDevice(uniqueToken, userID, now.Add(24*time.Hour))
	s.Require().NoError(err)

	// Sanity check: 5 rows exist before the migration runs.
	preRows, err := s.rowsWithoutTenant("")
	s.Require().NoError(err)
	s.Require().Len(preRows, 5)

	// This is the assertion that proves the outage path is unreachable:
	// the migration must succeed even with duplicate (device_token,
	// user_id) rows present.
	err = s.Storage.MigrateUp()
	s.Require().NoError(err, "migration must succeed even with duplicate (device_token, user_id) rows present")

	var dupSurvivors []models.TrustedDevice
	s.Require().NoError(s.Storage.GetConnection().
		Where("device_token = ? AND user_id = ?", dupToken, userID).
		All(&dupSurvivors))
	s.Require().Len(dupSurvivors, 1, "exactly one row must survive per (device_token, user_id) pair")
	s.Equal(newerID, dupSurvivors[0].ID, "the survivor must be the row with the latest expires_at")

	var tieSurvivors []models.TrustedDevice
	s.Require().NoError(s.Storage.GetConnection().
		Where("device_token = ? AND user_id = ?", tieToken, userID).
		All(&tieSurvivors))
	s.Require().Len(tieSurvivors, 1, "exactly one row must survive a tied-expires_at duplicate pair")
	s.Equal(tieHighID, tieSurvivors[0].ID, "a tied expires_at must be broken deterministically by the higher id")

	var untouchedRows []models.TrustedDevice
	s.Require().NoError(s.Storage.GetConnection().
		Where("device_token = ? AND user_id = ?", uniqueToken, userID).
		All(&untouchedRows))
	s.Require().Len(untouchedRows, 1, "a pair that was already unique must be left untouched")
	s.Equal(untouchedID, untouchedRows[0].ID)
	s.WithinDuration(now.Add(24*time.Hour), untouchedRows[0].ExpiresAt, time.Second)

	_, err = s.insertTrustedDevice(dupToken, userID, now.Add(48*time.Hour))
	s.Error(err, "the unique index must reject a new duplicate (device_token, user_id) row going forward")

	olderExists, err := s.Storage.GetConnection().Where("id = ?", olderID).Exists(&models.TrustedDevice{})
	s.Require().NoError(err)
	s.False(olderExists, "the losing duplicate (earlier expires_at) must have been deleted")

	tieLowExists, err := s.Storage.GetConnection().Where("id = ?", tieLowID).Exists(&models.TrustedDevice{})
	s.Require().NoError(err)
	s.False(tieLowExists, "the losing tied-expires_at duplicate (lower id) must have been deleted")
}

// TestTenantMigration_BackfillsTenantBoundUsersAndKeepsGlobalRowsLegacy covers
// 20261101235835_add_trusted_devices_tenant_id. Login flows send X-Tenant-ID, and after this
// migration a NULL row no longer answers them, so without the backfill every trusted browser would
// be asked for a code once after deploy. A tenant-bound user can only be signed in under their own
// tenant, so their rows take that tenant; a global user's rows stay NULL.
func (s *trustedDeviceMigrationSuite) TestTenantMigration_BackfillsTenantBoundUsersAndKeepsGlobalRowsLegacy() {
	if testing.Short() {
		s.T().Skip("skipping test in short mode.")
	}

	s.Require().NoError(s.Storage.MigrateDown(3))
	s.Require().NoError(s.LoadFixtures("../test/fixtures/user"))

	tenantID := uuid.FromStringOrNil("aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa")
	boundUserID := uuid.FromStringOrNil("dddddddd-4444-4444-8444-dddddddddddd")
	globalUserID := uuid.FromStringOrNil(fixtureUserID)
	now := time.Now().UTC().Truncate(time.Second)

	s.Require().NoError(s.Storage.GetConnection().RawQuery(
		"INSERT INTO tenants (id, name, slug, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
		tenantID, "Tenant A", "tenant-a", true, now, now,
	).Exec())
	s.Require().NoError(s.Storage.GetConnection().RawQuery(
		"INSERT INTO users (id, tenant_id, created_at, updated_at) VALUES (?, ?, ?, ?)",
		boundUserID, tenantID, now, now,
	).Exec())

	boundRowID, err := s.insertTrustedDevice(strings.Repeat("d", 64), boundUserID, now.Add(time.Hour))
	s.Require().NoError(err)
	globalRowID, err := s.insertTrustedDevice(strings.Repeat("e", 64), globalUserID, now.Add(time.Hour))
	s.Require().NoError(err)

	s.Require().NoError(s.Storage.MigrateUp())

	var boundRow models.TrustedDevice
	s.Require().NoError(s.Storage.GetConnection().Find(&boundRow, boundRowID))
	s.Require().NotNil(boundRow.TenantID, "a tenant-bound user's row must take the user's tenant")
	s.Equal(tenantID, *boundRow.TenantID)

	var globalRow models.TrustedDevice
	s.Require().NoError(s.Storage.GetConnection().Find(&globalRow, globalRowID))
	s.Nil(globalRow.TenantID, "a global user's row must stay a legacy row")
}

// 20261101235835 is additive: trusted_devices_token_user_idx, the previous image's ON CONFLICT
// arbiter, survives it, so one browser still holds one row per user across tenants; and its down
// drops only what it added, leaving that index in place. Run below 20261106065051, which drops the
// pair index.
func (s *trustedDeviceMigrationSuite) TestTenantMigration_KeepsThePairIndexAndDownDropsOnlyTheTenant() {
	if testing.Short() {
		s.T().Skip("skipping test in short mode.")
	}

	s.Require().NoError(s.Storage.MigrateDown(1))
	s.Require().NoError(s.LoadFixtures("../test/fixtures/user"))

	userID := uuid.FromStringOrNil(fixtureUserID)
	token := strings.Repeat("f", 64)
	now := time.Now().UTC().Truncate(time.Second)

	s.Require().NoError(s.insertUnderTenant(token, userID, "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa", now.Add(time.Hour)))
	s.Error(s.insertUnderTenant(token, userID, "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb", now.Add(time.Hour)),
		"trusted_devices_token_user_idx must still allow one row per (device_token, user_id)")

	s.Require().NoError(s.Storage.MigrateDown(2))

	_, err := s.insertTrustedDevice(token, userID, now.Add(48*time.Hour))
	s.Error(err, "after the down, trusted_devices_token_user_idx must still reject a duplicate")

	rows, err := s.rowsWithoutTenant("WHERE device_token = ?", token)
	s.Require().NoError(err)
	s.Len(rows, 1, "the down keeps the rows; it drops only the tenant")

	s.Require().NoError(s.Storage.MigrateUp())
}

// 20261106065051 (archon#1085 task 34) drops trusted_devices_token_user_idx, so one browser holds
// the same person's trust for two clinics and for a flow without a tenant side by side; the
// per-tenant partial indexes still allow one row per (device_token, user_id, tenant). Its down keeps
// the latest-expiring row of each pair and recreates the index, so an older image's ON CONFLICT has
// its arbiter again.
func (s *trustedDeviceMigrationSuite) TestPairIndexDrop_AllowsTrustPerTenantAndDownKeepsTheLatestRow() {
	if testing.Short() {
		s.T().Skip("skipping test in short mode.")
	}

	s.Require().NoError(s.LoadFixtures("../test/fixtures/user"))

	userID := uuid.FromStringOrNil(fixtureUserID)
	token := strings.Repeat("d", 64)
	now := time.Now().UTC().Truncate(time.Second)
	tenantA := "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"
	tenantB := "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb"

	s.Require().NoError(s.insertUnderTenant(token, userID, tenantA, now.Add(time.Hour)))
	s.Require().NoError(s.insertUnderTenant(token, userID, tenantB, now.Add(3*time.Hour)),
		"without the pair index one browser holds trust for a second clinic")
	s.Require().NoError(s.insertUnderTenant(token, userID, "", now.Add(2*time.Hour)),
		"and for a flow without a tenant")
	s.Error(s.insertUnderTenant(token, userID, tenantA, now.Add(4*time.Hour)),
		"trusted_devices_token_user_tenant_idx still allows one row per clinic")
	s.Error(s.insertUnderTenant(token, userID, "", now.Add(4*time.Hour)),
		"trusted_devices_token_user_global_idx still allows one row without a tenant")

	s.Require().NoError(s.Storage.MigrateDown(1))

	var rows []models.TrustedDevice
	s.Require().NoError(s.Storage.GetConnection().Where("device_token = ?", token).All(&rows))
	s.Require().Len(rows, 1, "the down keeps one row per (device_token, user_id)")
	s.Require().NotNil(rows[0].TenantID)
	s.Equal(tenantB, rows[0].TenantID.String(), "the down keeps the latest-expiring row")
	s.Error(s.insertUnderTenant(token, userID, tenantA, now.Add(time.Hour)),
		"after the down, trusted_devices_token_user_idx rejects a second row for the pair")

	s.Require().NoError(s.Storage.MigrateUp())
}

// 20261106065051's up gives a tenant-bound user's leftover tenantless row the user's tenant before it
// drops the pair index, while at most one row per (device_token, user_id) exists and the UPDATE
// cannot collide with trusted_devices_token_user_tenant_idx. A global user's row stays without one.
func (s *trustedDeviceMigrationSuite) TestPairIndexDrop_UpBackfillsBoundUsersTenantlessRowsBeforeTheDrop() {
	if testing.Short() {
		s.T().Skip("skipping test in short mode.")
	}

	s.Require().NoError(s.Storage.MigrateDown(1))
	s.Require().NoError(s.LoadFixtures("../test/fixtures/user"))

	tenantID := uuid.FromStringOrNil("aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa")
	boundUserID := uuid.FromStringOrNil("dddddddd-4444-4444-8444-dddddddddddd")
	now := time.Now().UTC().Truncate(time.Second)
	s.Require().NoError(s.Storage.GetConnection().RawQuery(
		"INSERT INTO tenants (id, name, slug, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
		tenantID, "Tenant A", "tenant-a", true, now, now,
	).Exec())
	s.Require().NoError(s.Storage.GetConnection().RawQuery(
		"INSERT INTO users (id, tenant_id, created_at, updated_at) VALUES (?, ?, ?, ?)",
		boundUserID, tenantID, now, now,
	).Exec())

	boundToken := strings.Repeat("h", 64)
	globalToken := strings.Repeat("i", 64)
	s.Require().NoError(s.insertUnderTenant(boundToken, boundUserID, "", now.Add(time.Hour)))
	s.Require().NoError(s.insertUnderTenant(globalToken, uuid.FromStringOrNil(fixtureUserID), "", now.Add(time.Hour)))

	s.Require().NoError(s.Storage.MigrateUp())

	var bound models.TrustedDevice
	s.Require().NoError(s.Storage.GetConnection().Where("device_token = ?", boundToken).First(&bound))
	s.Require().NotNil(bound.TenantID, "the up gives a tenant-bound user's tenantless row the user's tenant")
	s.Equal(tenantID, *bound.TenantID)

	var global models.TrustedDevice
	s.Require().NoError(s.Storage.GetConnection().Where("device_token = ?", globalToken).First(&global))
	s.Nil(global.TenantID, "a global user's row stays without a tenant")
}

func (s *trustedDeviceMigrationSuite) TestPairIndexDrop_DownRefusesAboveTheSizeGateWithoutMaintenanceAcknowledgement() {
	if testing.Short() {
		s.T().Skip("requires disposable PostgreSQL")
	}
	s.Require().NoError(s.LoadFixtures("../test/fixtures/user"))
	s.Require().NoError(s.insertUnderTenant(strings.Repeat("g", 64), uuid.FromStringOrNil(fixtureUserID), "", time.Now().UTC().Add(time.Hour)))

	overGate := s.connectWithOptions("-c hanko.trust_migration_max_live_rows=0")
	defer overGate.GetConnection().Close()
	s.Require().ErrorContains(overGate.MigrateDown(1), "too large to roll back under live login traffic")
	acknowledged := s.connectWithOptions("-c hanko.trust_migration_max_live_rows=0 -c hanko.trusted_device_maintenance=on")
	defer acknowledged.GetConnection().Close()
	s.Require().NoError(acknowledged.MigrateDown(1), "explicit maintenance acknowledgement permits the same rollback")

	s.Require().NoError(s.Storage.MigrateUp())
}

// insertUnderTenant writes a trust row with raw SQL under a tenant, or without one for "".
func (s *trustedDeviceMigrationSuite) insertUnderTenant(token string, userID uuid.UUID, tenant string, expiresAt time.Time) error {
	var tenantID interface{}
	if tenant != "" {
		tenantID = uuid.FromStringOrNil(tenant)
	}
	now := time.Now().UTC().Truncate(time.Second)
	return s.Storage.GetConnection().RawQuery(
		"INSERT INTO trusted_devices (id, user_id, tenant_id, device_token, expires_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		uuid.Must(uuid.NewV4()), userID, tenantID, token, expiresAt, now, now,
	).Exec()
}

// rowsWithoutTenant reads trusted_devices naming its columns, for a schema rolled back below
// 20261101235835: pop's Count and All select every column of models.TrustedDevice, tenant_id
// included, which does not exist there.
func (s *trustedDeviceMigrationSuite) rowsWithoutTenant(where string, args ...interface{}) ([]models.TrustedDevice, error) {
	var rows []models.TrustedDevice
	err := s.Storage.GetConnection().RawQuery(
		"SELECT id, user_id, device_token, expires_at, created_at, updated_at FROM trusted_devices "+where,
		args...,
	).All(&rows)
	return rows, err
}

func (s *trustedDeviceMigrationSuite) insertTrustedDevice(deviceToken string, userID uuid.UUID, expiresAt time.Time) (uuid.UUID, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return uuid.Nil, err
	}

	now := time.Now().UTC()
	err = s.Storage.GetConnection().RawQuery(
		"INSERT INTO trusted_devices (id, user_id, device_token, expires_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
		id, userID, deviceToken, expiresAt, now, now,
	).Exec()

	return id, err
}
