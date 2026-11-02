package persistence_test

// This file uses the external "persistence_test" package (not "persistence") for the same
// reason as trusted_device_migration_integration_test.go in this directory: test.Suite (in
// package "test") imports package "persistence", so an internal test file here would create an
// import cycle. See that file's header comment for the full explanation. It also already
// declares fixtureUserID for test/fixtures/user/users.yaml -- since both files share the
// "persistence_test" package, that constant is reused here rather than redeclared.

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/suite"
	"github.com/teamhanko/hanko/backend/v2/persistence"
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

	found, err := persister.FindValidTrust(token, userID, nil, now)
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

	found, err := persister.FindValidTrust(token, otherUserID, nil, now)
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

	found, err := s.Storage.GetTrustedDevicePersister().FindValidTrust(token, userID, nil, now)
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

	found, err := s.Storage.GetTrustedDevicePersister().FindValidTrust(token, userID, nil, now)
	s.Require().NoError(err)
	s.Nil(found, "expires_at == now must not count as valid -- the comparison is strictly greater")

	// Complement the boundary: one millisecond past `now` must count as valid, proving the
	// nil result above is really about the boundary and not some other bug in the query.
	found, err = s.Storage.GetTrustedDevicePersister().FindValidTrust(token, userID, nil, now.Add(-1*time.Millisecond))
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

	found, err := persister.FindValidTrust(tokenX, userA, nil, now)
	s.Require().NoError(err)
	s.Require().NotNil(found)
	s.WithinDuration(now.Add(2*time.Hour), found.ExpiresAt, time.Second)

	found, err = persister.FindValidTrust(tokenX, userB, nil, now)
	s.Require().NoError(err)
	s.Nil(found, "userB's row on tokenX is expired")

	found, err = persister.FindValidTrust(tokenY, userB, nil, now)
	s.Require().NoError(err)
	s.Require().NotNil(found)
	s.WithinDuration(now.Add(3*time.Hour), found.ExpiresAt, time.Second)

	found, err = persister.FindValidTrust(tokenY, userA, nil, now)
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

	foundA, err := persister.FindValidTrust(token, userA, nil, now)
	s.Require().NoError(err)
	s.Require().NotNil(foundA)
	s.WithinDuration(now.Add(1*time.Hour), foundA.ExpiresAt, time.Second)

	foundB, err := persister.FindValidTrust(token, userB, nil, now)
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

// TestDeleteByUserID_RemovesEveryRowOfThatUserOnly backs the admin 2FA reset: every browser the
// user trusted, expired or not, must stop skipping the second factor, while another user trusting
// the same shared browser (same device_token) keeps their own trust.
func (s *trustedDevicePersisterSuite) TestDeleteByUserID_RemovesEveryRowOfThatUserOnly() {
	if testing.Short() {
		s.T().Skip("skipping test in short mode.")
	}

	userA := uuid.FromStringOrNil(fixtureUserID)
	userB := uuid.FromStringOrNil(secondUserID)
	sharedToken := strings.Repeat("j", 64)
	ownToken := strings.Repeat("k", 64)
	now := time.Now().UTC().Truncate(time.Millisecond)

	_, err := s.insertTrustedDevice(sharedToken, userA, now.Add(1*time.Hour))
	s.Require().NoError(err)
	_, err = s.insertTrustedDevice(ownToken, userA, now.Add(-1*time.Hour))
	s.Require().NoError(err)
	_, err = s.insertTrustedDevice(sharedToken, userB, now.Add(1*time.Hour))
	s.Require().NoError(err)

	persister := s.Storage.GetTrustedDevicePersister()
	s.Require().NoError(persister.DeleteByUserID(userA))

	var rowsA []models.TrustedDevice
	s.Require().NoError(s.Storage.GetConnection().Where("user_id = ?", userA).All(&rowsA))
	s.Empty(rowsA, "every trusted device of the user must be deleted, expired ones included")

	foundB, err := persister.FindValidTrust(sharedToken, userB, nil, now)
	s.Require().NoError(err)
	s.NotNil(foundB, "another user trusting the same browser must keep their trust")

	s.Require().NoError(persister.DeleteByUserID(userA), "deleting a user's trusted devices twice must not fail")
}

// tenantA and tenantB are clinics for the per-tenant trust cases below. trusted_devices.tenant_id
// has no foreign key (see 20261101235835_add_trusted_devices_tenant_id), so no tenants row is needed.
var (
	trustTenantA = uuid.FromStringOrNil("aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa")
	trustTenantB = uuid.FromStringOrNil("bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb")
)

// TestFindValidTrust_TrustUnderOneTenantDoesNotAnswerAnother is archon#1085 6.2 #20 against
// Postgres: one Hanko user signs in to several clinics, and a browser trusted while signing in to
// clinic A must not skip clinic B's second factor.
func (s *trustedDevicePersisterSuite) TestFindValidTrust_TrustUnderOneTenantDoesNotAnswerAnother() {
	if testing.Short() {
		s.T().Skip("skipping test in short mode.")
	}

	userID := uuid.FromStringOrNil(fixtureUserID)
	token := strings.Repeat("l", 64)
	now := time.Now().UTC().Truncate(time.Millisecond)

	persister := s.Storage.GetTrustedDevicePersister()
	s.Require().NoError(persister.Create(models.TrustedDevice{
		ID:          s.mustNewUUID(),
		UserID:      userID,
		TenantID:    &trustTenantA,
		DeviceToken: token,
		ExpiresAt:   now.Add(1 * time.Hour),
		CreatedAt:   now,
		UpdatedAt:   now,
	}))

	found, err := persister.FindValidTrust(token, userID, &trustTenantA, now)
	s.Require().NoError(err)
	s.Require().NotNil(found, "trust recorded under A must answer A")
	s.Require().NotNil(found.TenantID)
	s.Equal(trustTenantA, *found.TenantID)

	found, err = persister.FindValidTrust(token, userID, &trustTenantB, now)
	s.Require().NoError(err)
	s.Nil(found, "trust recorded under A must not answer B")

	found, err = persister.FindValidTrust(token, userID, nil, now)
	s.Require().NoError(err)
	s.Nil(found, "trust recorded under A must not answer a flow without a tenant")
}

// A row written before trust was scoped has no tenant: it answers flows without a tenant only.
func (s *trustedDevicePersisterSuite) TestFindValidTrust_LegacyRowAnswersOnlyAFlowWithoutTenant() {
	if testing.Short() {
		s.T().Skip("skipping test in short mode.")
	}

	userID := uuid.FromStringOrNil(fixtureUserID)
	token := strings.Repeat("m", 64)
	now := time.Now().UTC().Truncate(time.Millisecond)

	_, err := s.insertTrustedDevice(token, userID, now.Add(1*time.Hour))
	s.Require().NoError(err)

	persister := s.Storage.GetTrustedDevicePersister()
	found, err := persister.FindValidTrust(token, userID, nil, now)
	s.Require().NoError(err)
	s.NotNil(found)

	found, err = persister.FindValidTrust(token, userID, &trustTenantA, now)
	s.Require().NoError(err)
	s.Nil(found, "a legacy row must not answer a clinic's flow")
}

// While trusted_devices_token_user_idx stands (until archon#1085 task 34 drops it), one browser
// holds one trust row per user: trusting it under another tenant, or without one, moves that row
// and keeps its id, so trust follows the flow that trusted last.
func (s *trustedDevicePersisterSuite) TestCreate_WhileThePairIndexStandsTrustFollowsTheLatestTenant() {
	if testing.Short() {
		s.T().Skip("skipping test in short mode.")
	}

	userID := uuid.FromStringOrNil(fixtureUserID)
	token := strings.Repeat("n", 64)
	now := time.Now().UTC().Truncate(time.Millisecond)

	persister := s.Storage.GetTrustedDevicePersister()
	var firstID uuid.UUID
	for i, tenantID := range []*uuid.UUID{&trustTenantA, &trustTenantB, nil} {
		id := s.mustNewUUID()
		if i == 0 {
			firstID = id
		}
		expiresAt := now.Add(time.Duration(i+1) * time.Hour)
		s.Require().NoError(persister.Create(models.TrustedDevice{
			ID:          id,
			UserID:      userID,
			TenantID:    tenantID,
			DeviceToken: token,
			ExpiresAt:   expiresAt,
			CreatedAt:   now,
			UpdatedAt:   now,
		}))

		var rows []models.TrustedDevice
		s.Require().NoError(s.Storage.GetConnection().
			Where("device_token = ? AND user_id = ?", token, userID).
			All(&rows))
		s.Require().Len(rows, 1, "the pair index allows one row per browser and user")
		s.Equal(firstID, rows[0].ID, "the row is moved, not replaced")
		s.Equal(tenantID, rows[0].TenantID, "trust must follow the latest tenant")
		s.WithinDuration(expiresAt, rows[0].ExpiresAt, time.Millisecond)
	}

	found, err := persister.FindValidTrust(token, userID, &trustTenantA, now)
	s.Require().NoError(err)
	s.Nil(found, "trust moved away from A must no longer answer A")
}

// The same Create after task 34 drops trusted_devices_token_user_idx: one browser holds the same
// person's trust for two clinics and for a flow without a tenant, one row each, and re-trusting
// under one of them refreshes that row only. Dropping the index here is task 34's step, run early.
func (s *trustedDevicePersisterSuite) TestCreate_WithoutThePairIndexOneBrowserHoldsTrustPerTenant() {
	if testing.Short() {
		s.T().Skip("skipping test in short mode.")
	}

	s.Require().NoError(s.Storage.GetConnection().RawQuery("DROP INDEX trusted_devices_token_user_idx").Exec())

	userID := uuid.FromStringOrNil(fixtureUserID)
	token := strings.Repeat("p", 64)
	now := time.Now().UTC().Truncate(time.Millisecond)

	persister := s.Storage.GetTrustedDevicePersister()
	create := func(tenantID *uuid.UUID, expiresAt time.Time) {
		s.Require().NoError(persister.Create(models.TrustedDevice{
			ID:          s.mustNewUUID(),
			UserID:      userID,
			TenantID:    tenantID,
			DeviceToken: token,
			ExpiresAt:   expiresAt,
			CreatedAt:   now,
			UpdatedAt:   now,
		}))
	}

	create(&trustTenantA, now.Add(1*time.Hour))
	create(&trustTenantB, now.Add(2*time.Hour))
	create(nil, now.Add(3*time.Hour))
	create(&trustTenantA, now.Add(4*time.Hour))
	create(nil, now.Add(5*time.Hour))

	var rows []models.TrustedDevice
	s.Require().NoError(s.Storage.GetConnection().
		Where("device_token = ? AND user_id = ?", token, userID).
		All(&rows))
	s.Require().Len(rows, 3, "one row per tenant, and one for flows without a tenant")

	foundA, err := persister.FindValidTrust(token, userID, &trustTenantA, now)
	s.Require().NoError(err)
	s.Require().NotNil(foundA)
	s.WithinDuration(now.Add(4*time.Hour), foundA.ExpiresAt, time.Second, "re-trusting under A refreshes A's row")

	foundB, err := persister.FindValidTrust(token, userID, &trustTenantB, now)
	s.Require().NoError(err)
	s.Require().NotNil(foundB)
	s.WithinDuration(now.Add(2*time.Hour), foundB.ExpiresAt, time.Second, "re-trusting under A leaves B's row alone")

	foundNone, err := persister.FindValidTrust(token, userID, nil, now)
	s.Require().NoError(err)
	s.Require().NotNil(foundNone)
	s.WithinDuration(now.Add(5*time.Hour), foundNone.ExpiresAt, time.Second, "re-trusting without a tenant refreshes that row")
}

// Rollout and rollback safety: the previous image upserts with ON CONFLICT (device_token, user_id)
// and keeps serving against this schema, so that statement must still find its arbiter.
func (s *trustedDevicePersisterSuite) TestSchema_PreviousImageUpsertStillHasItsArbiter() {
	if testing.Short() {
		s.T().Skip("skipping test in short mode.")
	}

	userID := uuid.FromStringOrNil(fixtureUserID)
	token := strings.Repeat("q", 64)
	now := time.Now().UTC().Truncate(time.Millisecond)

	previousImageUpsert := func(expiresAt time.Time) error {
		return s.Storage.GetConnection().RawQuery(
			`INSERT INTO trusted_devices (id, user_id, device_token, expires_at, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?)
			 ON CONFLICT (device_token, user_id)
			 DO UPDATE SET expires_at = EXCLUDED.expires_at, updated_at = EXCLUDED.updated_at`,
			s.mustNewUUID(), userID, token, expiresAt, now, now,
		).Exec()
	}

	s.Require().NoError(previousImageUpsert(now.Add(1 * time.Hour)))
	s.Require().NoError(previousImageUpsert(now.Add(2*time.Hour)), "a re-trust by the previous image must upsert, not fail")

	count, err := s.Storage.GetConnection().Where("device_token = ? AND user_id = ?", token, userID).Count(&models.TrustedDevice{})
	s.Require().NoError(err)
	s.Equal(1, count)
}

// The admin 2FA reset deletes the person's trust in every clinic, not only one tenant's.
func (s *trustedDevicePersisterSuite) TestDeleteByUserID_RemovesRowsUnderEveryTenant() {
	if testing.Short() {
		s.T().Skip("skipping test in short mode.")
	}

	userID := uuid.FromStringOrNil(fixtureUserID)
	token := strings.Repeat("o", 64)
	now := time.Now().UTC().Truncate(time.Millisecond)

	persister := s.Storage.GetTrustedDevicePersister()
	for i, tenantID := range []*uuid.UUID{&trustTenantA, &trustTenantB, nil} {
		// One browser per tenant: while trusted_devices_token_user_idx stands, a second tenant on
		// the same browser would move the row rather than add one.
		s.Require().NoError(persister.Create(models.TrustedDevice{
			ID:          s.mustNewUUID(),
			UserID:      userID,
			TenantID:    tenantID,
			DeviceToken: token + strconv.Itoa(i),
			ExpiresAt:   now.Add(1 * time.Hour),
			CreatedAt:   now,
			UpdatedAt:   now,
		}))
	}

	s.Require().NoError(persister.DeleteByUserID(userID))

	count, err := s.Storage.GetConnection().Where("user_id = ?", userID).Count(&models.TrustedDevice{})
	s.Require().NoError(err)
	s.Zero(count, "every trust row of the user must be deleted, whatever its tenant")
}

// A global user adopted on their first login under tenant A keeps the browsers they trusted: their
// trust rows without a tenant move to A with the rest of the user, so A's next flow is not asked for
// the code once more. Another user's rows on the same browser stay as they are.
func (s *trustedDevicePersisterSuite) TestAdoptUserToTenant_MovesTheUsersTrustWithoutTenantToTheTenant() {
	if testing.Short() {
		s.T().Skip("skipping test in short mode.")
	}

	adopted := uuid.FromStringOrNil(secondUserID)
	other := uuid.FromStringOrNil(fixtureUserID)
	token := strings.Repeat("q", 64)
	now := time.Now().UTC().Truncate(time.Millisecond)

	s.Require().NoError(s.Storage.GetConnection().RawQuery(
		"INSERT INTO tenants (id, name, slug, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
		trustTenantA, "Tenant A", "tenant-a", true, now, now,
	).Exec())
	_, err := s.insertTrustedDevice(token, adopted, now.Add(time.Hour))
	s.Require().NoError(err)
	_, err = s.insertTrustedDevice(token, other, now.Add(time.Hour))
	s.Require().NoError(err)

	s.Require().NoError(s.Storage.GetUserPersister().AdoptUserToTenant(adopted, trustTenantA))

	persister := s.Storage.GetTrustedDevicePersister()
	found, err := persister.FindValidTrust(token, adopted, &trustTenantA, now)
	s.Require().NoError(err)
	s.NotNil(found, "the adopted user's trust must answer the tenant they were adopted to")

	found, err = persister.FindValidTrust(token, other, nil, now)
	s.Require().NoError(err)
	s.NotNil(found, "another user's trust on the same browser must stay without a tenant")
}

// Two logins of the same user on the same browser and tenant race. The first holds its new row
// uncommitted while the second writes: the second's insert waits on the unique index, finds the
// row once the first commits, and must refresh it rather than fail or add a second row. Whether the
// second write reaches its insert before the commit depends on scheduling; the end state asserted
// is the same either way.
func (s *trustedDevicePersisterSuite) TestCreate_ConcurrentTrustOfTheSameTenantIsRefreshed() {
	if testing.Short() {
		s.T().Skip("skipping test in short mode.")
	}

	userID := uuid.FromStringOrNil(fixtureUserID)
	token := strings.Repeat("r", 64)
	now := time.Now().UTC().Truncate(time.Millisecond)
	row := func(expiresIn time.Duration) models.TrustedDevice {
		return models.TrustedDevice{
			ID:          s.mustNewUUID(),
			UserID:      userID,
			TenantID:    &trustTenantA,
			DeviceToken: token,
			ExpiresAt:   now.Add(expiresIn),
			CreatedAt:   now,
			UpdatedAt:   now,
		}
	}

	first, err := s.Storage.GetConnection().NewTransaction()
	s.Require().NoError(err)
	second, err := s.Storage.GetConnection().NewTransaction()
	s.Require().NoError(err)

	firstRow := row(time.Hour)
	s.Require().NoError(persistence.NewTrustedDevicePersister(first).Create(firstRow))

	secondDone := make(chan error, 1)
	go func() {
		secondDone <- persistence.NewTrustedDevicePersister(second).Create(row(7 * time.Hour))
	}()
	time.Sleep(200 * time.Millisecond)
	s.Require().NoError(first.TX.Commit())

	s.Require().NoError(<-secondDone, "the second login must refresh the row, not fail")
	s.Require().NoError(second.TX.Commit())

	var rows []models.TrustedDevice
	s.Require().NoError(s.Storage.GetConnection().
		Where("device_token = ? AND user_id = ?", token, userID).
		All(&rows))
	s.Require().Len(rows, 1, "the race must leave one row")
	s.Equal(firstRow.ID, rows[0].ID)
	s.Require().NotNil(rows[0].TenantID)
	s.Equal(trustTenantA, *rows[0].TenantID)
	s.WithinDuration(now.Add(7*time.Hour), rows[0].ExpiresAt, time.Millisecond, "the later login's expiry must win")
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
