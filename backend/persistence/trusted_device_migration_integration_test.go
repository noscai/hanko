package persistence_test

// This file uses the external "persistence_test" package (not "persistence")
// because test.Suite (in package "test") imports package "persistence" for
// its Storage type -- an internal test file here (package "persistence")
// importing "test" would create an import cycle (persistence -> test ->
// persistence), which `go vet` rejects. None of the exported symbols this
// test needs are unexported, so the external package works without issue.

import (
	"strings"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/suite"
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

// fixtureUserID matches test/fixtures/user/users.yaml, loaded below to
// satisfy trusted_devices.user_id's FK to users.id.
const fixtureUserID = "b5dd5267-b462-48be-b70d-bcd6f1bbe7a5"

func (s *trustedDeviceMigrationSuite) TestMigration_DedupesTrustedDevicesBeforeCreatingUniqueIndex() {
	if testing.Short() {
		s.T().Skip("skipping test in short mode.")
	}

	// SetupTest() already ran MigrateUp(), which means the migration under
	// test has already run and its unique index already exists -- so we
	// can't insert duplicate (device_token, user_id) rows yet. Roll back
	// just that one migration so duplicates can be inserted with raw SQL,
	// then re-apply it and assert on the outcome.
	s.Require().NoError(s.Storage.MigrateDown(1))

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
	preCount, err := s.Storage.GetConnection().Count(&models.TrustedDevice{})
	s.Require().NoError(err)
	s.Require().Equal(5, preCount)

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
