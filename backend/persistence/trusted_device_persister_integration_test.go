package persistence_test

// This file uses the external "persistence_test" package (not "persistence") for the same
// reason as trusted_device_migration_integration_test.go in this directory: test.Suite (in
// package "test") imports package "persistence", so an internal test file here would create an
// import cycle. See that file's header comment for the full explanation. It also already
// declares fixtureUserID for test/fixtures/user/users.yaml -- since both files share the
// "persistence_test" package, that constant is reused here rather than redeclared.

import (
	"strings"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/suite"
	"github.com/teamhanko/hanko/backend/v2/persistence/models"
	"github.com/teamhanko/hanko/backend/v2/test"
)

// TestTrustedDevicePersisterSuite exercises FindValidTrust and the Create upsert added to
// support one shared browser device_token trusting many users, keyed by the
// trusted_devices_token_user_idx unique index (20260828085758). The single riskiest property
// here is identity isolation: FindValidTrust must never return a row for the wrong user just
// because the device_token matches -- that would turn a shared clinic workstation into a
// total second-factor bypass the moment any one user trusts it.
func TestTrustedDevicePersisterSuite(t *testing.T) {
	t.Parallel()
	suite.Run(t, new(trustedDevicePersisterSuite))
}

type trustedDevicePersisterSuite struct {
	test.Suite
}

// secondUserID is a second user, distinct from fixtureUserID, inserted directly (see insertUser
// below) rather than added to test/fixtures/user/users.yaml -- that fixture is also loaded by
// handler/user_test.go, which is out of scope for this change, so it is left untouched.
const secondUserID = "6f6e0f8b-8f3f-4a3e-9f0a-2b7a6f1c9d40"

func (s *trustedDevicePersisterSuite) SetupTest() {
	s.Suite.SetupTest()
	if testing.Short() {
		return
	}
	s.Require().NoError(s.LoadFixtures("../test/fixtures/user"))
	s.Require().NoError(s.insertUser(uuid.FromStringOrNil(secondUserID)))
}

func (s *trustedDevicePersisterSuite) TestFindValidTrust_ReturnsRowForCorrectTokenAndUser() {
	if testing.Short() {
		s.T().Skip("skipping test in short mode.")
	}

	userID := uuid.FromStringOrNil(fixtureUserID)
	token := strings.Repeat("a", 64)
	now := time.Now().UTC().Truncate(time.Millisecond)

	persister := s.Storage.GetTrustedDevicePersister()
	s.Require().NoError(persister.Create(models.TrustedDevice{
		ID:          s.mustNewUUID(),
		UserID:      userID,
		DeviceToken: token,
		ExpiresAt:   now.Add(1 * time.Hour),
		CreatedAt:   now,
		UpdatedAt:   now,
	}))

	found, err := persister.FindValidTrust(token, userID, now)
	s.Require().NoError(err)
	s.Require().NotNil(found)
	s.Equal(token, found.DeviceToken)
	s.Equal(userID, found.UserID)
}

// TestFindValidTrust_WrongUser_ReturnsNilNil is the isolation property the whole redesign rests
// on: two rows can now legitimately share a device_token, and FindValidTrust must only ever
// match the row whose user_id equals the one asked for.
func (s *trustedDevicePersisterSuite) TestFindValidTrust_WrongUser_ReturnsNilNil() {
	if testing.Short() {
		s.T().Skip("skipping test in short mode.")
	}

	trustedUserID := uuid.FromStringOrNil(fixtureUserID)
	otherUserID := uuid.FromStringOrNil(secondUserID)
	token := strings.Repeat("b", 64)
	now := time.Now().UTC().Truncate(time.Millisecond)

	persister := s.Storage.GetTrustedDevicePersister()
	s.Require().NoError(persister.Create(models.TrustedDevice{
		ID:          s.mustNewUUID(),
		UserID:      trustedUserID,
		DeviceToken: token,
		ExpiresAt:   now.Add(1 * time.Hour),
		CreatedAt:   now,
		UpdatedAt:   now,
	}))

	found, err := persister.FindValidTrust(token, otherUserID, now)
	s.Require().NoError(err)
	s.Nil(found, "a device_token trusted by one user must not be reported as trusted for another")
}

func (s *trustedDevicePersisterSuite) TestFindValidTrust_ExpiredInPast_ReturnsNilNil() {
	if testing.Short() {
		s.T().Skip("skipping test in short mode.")
	}

	userID := uuid.FromStringOrNil(fixtureUserID)
	token := strings.Repeat("c", 64)
	now := time.Now().UTC().Truncate(time.Millisecond)

	_, err := s.insertTrustedDevice(token, userID, now.Add(-1*time.Minute))
	s.Require().NoError(err)

	found, err := s.Storage.GetTrustedDevicePersister().FindValidTrust(token, userID, now)
	s.Require().NoError(err)
	s.Nil(found)
}

// TestFindValidTrust_ExpiresAtEqualsNow_ReturnsNilNil pins the boundary explicitly: the
// comparison is expires_at > now, strictly greater, so a row expiring at exactly `now` must be
// treated as already expired, not as still valid.
func (s *trustedDevicePersisterSuite) TestFindValidTrust_ExpiresAtEqualsNow_ReturnsNilNil() {
	if testing.Short() {
		s.T().Skip("skipping test in short mode.")
	}

	userID := uuid.FromStringOrNil(fixtureUserID)
	token := strings.Repeat("d", 64)
	now := time.Now().UTC().Truncate(time.Millisecond)

	_, err := s.insertTrustedDevice(token, userID, now)
	s.Require().NoError(err)

	found, err := s.Storage.GetTrustedDevicePersister().FindValidTrust(token, userID, now)
	s.Require().NoError(err)
	s.Nil(found, "expires_at == now must not count as valid -- the comparison is strictly greater")

	// Complement the boundary: one millisecond past `now` must count as valid, proving the
	// nil result above is really about the boundary and not some other bug in the query.
	found, err = s.Storage.GetTrustedDevicePersister().FindValidTrust(token, userID, now.Add(-1*time.Millisecond))
	s.Require().NoError(err)
	s.Require().NotNil(found, "a row expiring strictly after `now` must be reported valid")
}

// TestFindValidTrust_OrderIndependent writes several rows directly, interleaving tokens, users
// and past/future expiries so the physically last-inserted row is never the expected match.
// FindValidTrust must still return the correct row for each (token, user) pair regardless of
// insertion order -- guarding against a query that accidentally relies on row order (e.g. an
// unscoped `.First()`) instead of filtering on all three conditions.
func (s *trustedDevicePersisterSuite) TestFindValidTrust_OrderIndependent() {
	if testing.Short() {
		s.T().Skip("skipping test in short mode.")
	}

	userA := uuid.FromStringOrNil(fixtureUserID)
	userB := uuid.FromStringOrNil(secondUserID)
	tokenX := strings.Repeat("e", 64)
	tokenY := strings.Repeat("f", 64)
	now := time.Now().UTC().Truncate(time.Millisecond)

	// Insertion order deliberately does not match query order: the row that answers the
	// first assertion below (tokenX/userA) is written first, but three more rows -- two of
	// them expired, one of them a different user on the same tokenX -- are written after it.
	_, err := s.insertTrustedDevice(tokenX, userA, now.Add(2*time.Hour)) // valid, queried first
	s.Require().NoError(err)
	_, err = s.insertTrustedDevice(tokenX, userB, now.Add(-2*time.Hour)) // expired, same token
	s.Require().NoError(err)
	_, err = s.insertTrustedDevice(tokenY, userB, now.Add(3*time.Hour)) // valid, different token
	s.Require().NoError(err)
	_, err = s.insertTrustedDevice(tokenY, userA, now.Add(-3*time.Hour)) // expired, written last
	s.Require().NoError(err)

	persister := s.Storage.GetTrustedDevicePersister()

	found, err := persister.FindValidTrust(tokenX, userA, now)
	s.Require().NoError(err)
	s.Require().NotNil(found)
	s.WithinDuration(now.Add(2*time.Hour), found.ExpiresAt, time.Second)

	found, err = persister.FindValidTrust(tokenX, userB, now)
	s.Require().NoError(err)
	s.Nil(found, "userB's row on tokenX is expired")

	found, err = persister.FindValidTrust(tokenY, userB, now)
	s.Require().NoError(err)
	s.Require().NotNil(found)
	s.WithinDuration(now.Add(3*time.Hour), found.ExpiresAt, time.Second)

	found, err = persister.FindValidTrust(tokenY, userA, now)
	s.Require().NoError(err)
	s.Nil(found, "userA's row on tokenY is expired")
}

// TestCreate_RetrustingSamePairLeavesExactlyOneRowWithLatestExpiry proves the upsert: with a
// device_token now shared across users, re-trusting the same (device_token, user_id) pair must
// refresh the one row's expires_at, never pile up duplicates that a naive .First() could return
// out of order.
func (s *trustedDevicePersisterSuite) TestCreate_RetrustingSamePairLeavesExactlyOneRowWithLatestExpiry() {
	if testing.Short() {
		s.T().Skip("skipping test in short mode.")
	}

	userID := uuid.FromStringOrNil(fixtureUserID)
	token := strings.Repeat("g", 64)
	base := time.Now().UTC().Truncate(time.Millisecond)

	persister := s.Storage.GetTrustedDevicePersister()
	var firstID uuid.UUID
	var firstCreatedAt, lastExpiresAt, lastUpdatedAt time.Time
	for i := 0; i < 10; i++ {
		// Every real call generates a fresh row ID (see DeviceTrustService.CreateTrustedDevice
		// in flow_api/services/device_trust.go), so this must not depend on ID reuse -- only
		// the (device_token, user_id) pair can dedupe it.
		id := s.mustNewUUID()
		// created_at and updated_at are deliberately distinct per iteration (not a shared
		// `base`, as an earlier version of this test used) -- otherwise "created_at was
		// preserved from the first insert" and "created_at happened to be overwritten with a
		// coincidentally identical value" would be indistinguishable, and the assertion below
		// would not notice a DO UPDATE SET that started touching created_at.
		createdAt := base.Add(time.Duration(i) * time.Minute)
		updatedAt := base.Add(time.Duration(i)*time.Minute + 30*time.Second)
		lastExpiresAt = base.Add(time.Duration(i+1) * time.Hour)
		lastUpdatedAt = updatedAt
		if i == 0 {
			firstID = id
			firstCreatedAt = createdAt
		}
		s.Require().NoError(persister.Create(models.TrustedDevice{
			ID:          id,
			UserID:      userID,
			DeviceToken: token,
			ExpiresAt:   lastExpiresAt,
			CreatedAt:   createdAt,
			UpdatedAt:   updatedAt,
		}))
	}

	var rows []models.TrustedDevice
	s.Require().NoError(s.Storage.GetConnection().
		Where("device_token = ? AND user_id = ?", token, userID).
		All(&rows))
	s.Require().Len(rows, 1, "re-trusting the same (device_token, user_id) pair must upsert, not accumulate rows")
	s.WithinDuration(lastExpiresAt, rows[0].ExpiresAt, time.Millisecond)

	// id and created_at are deliberately absent from the upsert's DO UPDATE SET clause, so
	// they must survive unchanged from the very first insert -- not the last -- proving
	// preservation rather than a coincidence of every iteration sharing one value.
	s.Equal(firstID, rows[0].ID, "id must be preserved from the first insert, not replaced by a later re-trust's id")
	s.WithinDuration(firstCreatedAt, rows[0].CreatedAt, time.Millisecond, "created_at must be preserved from the first insert, not overwritten by a later re-trust")

	// updated_at IS in the DO UPDATE SET clause, so -- unlike id/created_at above -- it must
	// move to the latest re-trust's value.
	s.WithinDuration(lastUpdatedAt, rows[0].UpdatedAt, time.Millisecond, "updated_at must be bumped to the latest re-trust's value")
}

// TestCreate_TwoUsersSharingDeviceToken_KeepSeparateRowsAndExpiry is the core scenario this
// whole change exists for: two users on one shared workstation, one device_token, each user
// keeping their own trust row and their own expiry.
func (s *trustedDevicePersisterSuite) TestCreate_TwoUsersSharingDeviceToken_KeepSeparateRowsAndExpiry() {
	if testing.Short() {
		s.T().Skip("skipping test in short mode.")
	}

	userA := uuid.FromStringOrNil(fixtureUserID)
	userB := uuid.FromStringOrNil(secondUserID)
	token := strings.Repeat("h", 64)
	now := time.Now().UTC().Truncate(time.Millisecond)

	persister := s.Storage.GetTrustedDevicePersister()
	s.Require().NoError(persister.Create(models.TrustedDevice{
		ID:          s.mustNewUUID(),
		UserID:      userA,
		DeviceToken: token,
		ExpiresAt:   now.Add(1 * time.Hour),
		CreatedAt:   now,
		UpdatedAt:   now,
	}))
	s.Require().NoError(persister.Create(models.TrustedDevice{
		ID:          s.mustNewUUID(),
		UserID:      userB,
		DeviceToken: token,
		ExpiresAt:   now.Add(5 * time.Hour),
		CreatedAt:   now,
		UpdatedAt:   now,
	}))

	var rows []models.TrustedDevice
	s.Require().NoError(s.Storage.GetConnection().Where("device_token = ?", token).All(&rows))
	s.Require().Len(rows, 2, "two users sharing one device_token must each keep their own row")

	foundA, err := persister.FindValidTrust(token, userA, now)
	s.Require().NoError(err)
	s.Require().NotNil(foundA)
	s.WithinDuration(now.Add(1*time.Hour), foundA.ExpiresAt, time.Second)

	foundB, err := persister.FindValidTrust(token, userB, now)
	s.Require().NoError(err)
	s.Require().NotNil(foundB)
	s.WithinDuration(now.Add(5*time.Hour), foundB.ExpiresAt, time.Second)
}

// TestCreate_RejectsDeviceTokenTooShort is the regression guard for the trap in this task: the
// upsert needs raw SQL (pop's ValidateAndCreate has no ON CONFLICT), and raw SQL bypasses
// models.TrustedDevice.Validate unless Create calls it explicitly. If that call were ever
// dropped, an undersized/malformed device_token would start persisting silently.
func (s *trustedDevicePersisterSuite) TestCreate_RejectsDeviceTokenTooShort() {
	if testing.Short() {
		s.T().Skip("skipping test in short mode.")
	}

	userID := uuid.FromStringOrNil(fixtureUserID)
	shortToken := strings.Repeat("i", 10) // Validate requires 64-128 chars
	now := time.Now().UTC().Truncate(time.Millisecond)

	err := s.Storage.GetTrustedDevicePersister().Create(models.TrustedDevice{
		ID:          s.mustNewUUID(),
		UserID:      userID,
		DeviceToken: shortToken,
		ExpiresAt:   now.Add(1 * time.Hour),
		CreatedAt:   now,
		UpdatedAt:   now,
	})
	s.Require().Error(err)
	s.Contains(err.Error(), "validation failed")

	exists, err := s.Storage.GetConnection().Where("device_token = ?", shortToken).Exists(&models.TrustedDevice{})
	s.Require().NoError(err)
	s.False(exists, "an invalid model must never reach the raw-SQL upsert")
}

func (s *trustedDevicePersisterSuite) mustNewUUID() uuid.UUID {
	id, err := uuid.NewV4()
	s.Require().NoError(err)
	return id
}

// insertTrustedDevice writes a row directly via raw SQL, bypassing the persister entirely, so
// tests can set up exact/expired expires_at values (including boundary and past values Create's
// own upsert would otherwise also happily accept, but this keeps setup independent of the code
// under test). Mirrors the identically-named helper in
// trusted_device_migration_integration_test.go.
func (s *trustedDevicePersisterSuite) insertTrustedDevice(deviceToken string, userID uuid.UUID, expiresAt time.Time) (uuid.UUID, error) {
	id := s.mustNewUUID()

	now := time.Now().UTC()
	err := s.Storage.GetConnection().RawQuery(
		"INSERT INTO trusted_devices (id, user_id, device_token, expires_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
		id, userID, deviceToken, expiresAt, now, now,
	).Exec()

	return id, err
}

// insertUser inserts a second user directly, bypassing the shared test/fixtures/user/users.yaml
// fixture (also loaded by handler/user_test.go, which is out of scope here) so
// trusted_devices.user_id's foreign key to users.id is satisfied for the wrong-user and
// two-users-sharing-a-device scenarios above.
func (s *trustedDevicePersisterSuite) insertUser(id uuid.UUID) error {
	now := time.Now().UTC()
	return s.Storage.GetConnection().RawQuery(
		"INSERT INTO users (id, created_at, updated_at) VALUES (?, ?, ?)",
		id, now, now,
	).Exec()
}
