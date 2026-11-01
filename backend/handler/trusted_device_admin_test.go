package handler

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/teamhanko/hanko/backend/v2/dto"
	"github.com/teamhanko/hanko/backend/v2/persistence"
	"github.com/teamhanko/hanko/backend/v2/persistence/models"
	"github.com/teamhanko/hanko/backend/v2/test"
)

const (
	trustedDeviceAdminUserWithDevices    = "328c31aa-3c80-495a-89c1-dc629393ca78"
	trustedDeviceAdminUserSharingBrowser = "91357fb5-f3fa-4c57-9cec-c23c31aff6a0"
	trustedDeviceAdminUserWithoutDevices = "3b98f2df-0a03-4dde-8996-db1f2da4a634"
	trustedDeviceAdminUnknownUser        = "dcb882bd-8cc8-492a-87e5-827b82558d2f"
)

// The tests below drive TrustedDeviceAdminHandler.Delete through a bare echo instance wired with
// the admin router's validator and error handler, against in-memory fakes, so the status contract
// ClinicOS relies on is checked without the Postgres-backed test.Suite. TestTrustedDeviceAdminSuite
// further down covers the same contract end to end through NewAdminRouter and a real database.

type trustedDeviceAdminFakeUserPersister struct {
	persistence.UserPersister
	users  map[uuid.UUID]*models.User
	getErr error
}

func (f *trustedDeviceAdminFakeUserPersister) Get(id uuid.UUID) (*models.User, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.users[id], nil
}

type trustedDeviceAdminFakeTrustedDevicePersister struct {
	persistence.TrustedDevicePersister
	rows        []models.TrustedDevice
	deleteErr   error
	deleteCalls []uuid.UUID
}

func (f *trustedDeviceAdminFakeTrustedDevicePersister) DeleteByUserID(userID uuid.UUID) error {
	f.deleteCalls = append(f.deleteCalls, userID)
	if f.deleteErr != nil {
		return f.deleteErr
	}
	kept := f.rows[:0]
	for _, row := range f.rows {
		if row.UserID != userID {
			kept = append(kept, row)
		}
	}
	f.rows = kept
	return nil
}

func (f *trustedDeviceAdminFakeTrustedDevicePersister) rowsOf(userID uuid.UUID) int {
	n := 0
	for _, row := range f.rows {
		if row.UserID == userID {
			n++
		}
	}
	return n
}

type trustedDeviceAdminFakePersister struct {
	persistence.Persister
	users          *trustedDeviceAdminFakeUserPersister
	trustedDevices *trustedDeviceAdminFakeTrustedDevicePersister
}

func (f *trustedDeviceAdminFakePersister) GetUserPersister() persistence.UserPersister {
	return f.users
}

func (f *trustedDeviceAdminFakePersister) GetTrustedDevicePersister() persistence.TrustedDevicePersister {
	return f.trustedDevices
}

func newTrustedDeviceAdminFakes() *trustedDeviceAdminFakePersister {
	withDevices := uuid.FromStringOrNil(trustedDeviceAdminUserWithDevices)
	sharingBrowser := uuid.FromStringOrNil(trustedDeviceAdminUserSharingBrowser)
	withoutDevices := uuid.FromStringOrNil(trustedDeviceAdminUserWithoutDevices)
	return &trustedDeviceAdminFakePersister{
		users: &trustedDeviceAdminFakeUserPersister{users: map[uuid.UUID]*models.User{
			withDevices:    {ID: withDevices},
			sharingBrowser: {ID: sharingBrowser},
			withoutDevices: {ID: withoutDevices},
		}},
		trustedDevices: &trustedDeviceAdminFakeTrustedDevicePersister{rows: []models.TrustedDevice{
			{UserID: withDevices, DeviceToken: "shared-browser"},
			{UserID: withDevices, DeviceToken: "own-laptop"},
			{UserID: sharingBrowser, DeviceToken: "shared-browser"},
		}},
	}
}

func serveTrustedDeviceAdminDelete(t *testing.T, persister persistence.Persister, userID string) *httptest.ResponseRecorder {
	t.Helper()
	e := echo.New()
	e.Validator = dto.NewCustomValidator()
	e.HTTPErrorHandler = dto.NewHTTPErrorHandler(dto.HTTPErrorHandlerConfig{Debug: false, Logger: e.Logger})
	e.DELETE("/users/:user_id/trusted_devices", NewTrustedDeviceAdminHandler(persister).Delete)

	req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/users/%s/trusted_devices", userID), nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

func TestTrustedDeviceAdminHandler_Delete_RemovesOnlyThatUsersDevices(t *testing.T) {
	fakes := newTrustedDeviceAdminFakes()
	userID := uuid.FromStringOrNil(trustedDeviceAdminUserWithDevices)

	rec := serveTrustedDeviceAdminDelete(t, fakes, trustedDeviceAdminUserWithDevices)

	require.Equal(t, http.StatusNoContent, rec.Code)
	assert.Empty(t, rec.Body.String())
	assert.Equal(t, []uuid.UUID{userID}, fakes.trustedDevices.deleteCalls)
	assert.Zero(t, fakes.trustedDevices.rowsOf(userID))
	assert.Equal(t, 1, fakes.trustedDevices.rowsOf(uuid.FromStringOrNil(trustedDeviceAdminUserSharingBrowser)),
		"another user trusting the same browser must keep their trust")
}

func TestTrustedDeviceAdminHandler_Delete_UserWithoutDevicesIsNoContent(t *testing.T) {
	fakes := newTrustedDeviceAdminFakes()

	rec := serveTrustedDeviceAdminDelete(t, fakes, trustedDeviceAdminUserWithoutDevices)

	require.Equal(t, http.StatusNoContent, rec.Code)
	assert.Len(t, fakes.trustedDevices.rows, 3)
}

func TestTrustedDeviceAdminHandler_Delete_UnknownUserIsNotFound(t *testing.T) {
	fakes := newTrustedDeviceAdminFakes()

	rec := serveTrustedDeviceAdminDelete(t, fakes, trustedDeviceAdminUnknownUser)

	require.Equal(t, http.StatusNotFound, rec.Code)
	assert.Empty(t, fakes.trustedDevices.deleteCalls)
}

func TestTrustedDeviceAdminHandler_Delete_MalformedUserIDIsBadRequest(t *testing.T) {
	for name, userID := range map[string]string{
		"non uuid": "customUserId",
		"empty":    "",
	} {
		t.Run(name, func(t *testing.T) {
			fakes := newTrustedDeviceAdminFakes()

			rec := serveTrustedDeviceAdminDelete(t, fakes, userID)

			require.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Empty(t, fakes.trustedDevices.deleteCalls)
		})
	}
}

func TestTrustedDeviceAdminHandler_Delete_UserLookupFailureIsInternalServerError(t *testing.T) {
	fakes := newTrustedDeviceAdminFakes()
	fakes.users.getErr = errors.New("connection refused")

	rec := serveTrustedDeviceAdminDelete(t, fakes, trustedDeviceAdminUserWithDevices)

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Empty(t, fakes.trustedDevices.deleteCalls)
}

func TestTrustedDeviceAdminHandler_Delete_DeleteFailureIsInternalServerError(t *testing.T) {
	fakes := newTrustedDeviceAdminFakes()
	fakes.trustedDevices.deleteErr = errors.New("connection refused")

	rec := serveTrustedDeviceAdminDelete(t, fakes, trustedDeviceAdminUserWithDevices)

	require.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestTrustedDeviceAdminSuite(t *testing.T) {
	t.Parallel()
	suite.Run(t, new(trustedDeviceAdminSuite))
}

type trustedDeviceAdminSuite struct {
	test.Suite
}

func (s *trustedDeviceAdminSuite) TestTrustedDeviceAdminHandler_Delete() {
	if testing.Short() {
		s.T().Skip("skipping test in short mode.")
	}

	tests := []struct {
		name               string
		userId             string
		expectedStatusCode int
	}{
		{
			name:               "should delete every trusted device of the user",
			userId:             trustedDeviceAdminUserWithDevices,
			expectedStatusCode: http.StatusNoContent,
		},
		{
			name:               "should succeed if user has no trusted devices",
			userId:             trustedDeviceAdminUserWithoutDevices,
			expectedStatusCode: http.StatusNoContent,
		},
		{
			name:               "should fail on non uuid userID",
			userId:             "customUserId",
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name:               "should fail on empty userID",
			userId:             "",
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name:               "should fail on non existing user",
			userId:             trustedDeviceAdminUnknownUser,
			expectedStatusCode: http.StatusNotFound,
		},
	}

	for _, currentTest := range tests {
		s.Run(currentTest.name, func() {
			s.Require().NoError(s.LoadFixtures("../test/fixtures/trusted_device_admin"))
			e := NewAdminRouter(&test.DefaultConfig, s.Storage, nil)

			req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/users/%s/trusted_devices", currentTest.userId), nil)
			rec := httptest.NewRecorder()

			e.ServeHTTP(rec, req)

			s.Require().Equal(currentTest.expectedStatusCode, rec.Code)

			var ownRows []models.TrustedDevice
			s.Require().NoError(s.Storage.GetConnection().
				Where("user_id = ?", trustedDeviceAdminUserWithDevices).
				All(&ownRows))
			if currentTest.userId == trustedDeviceAdminUserWithDevices {
				s.Empty(ownRows, "the expired trust row goes too, not only the unexpired ones")
			} else {
				s.Len(ownRows, 3, "a request for another user must not touch this user's trusted devices, expired or not")
			}

			var kept []models.TrustedDevice
			s.Require().NoError(s.Storage.GetConnection().
				Where("user_id = ?", trustedDeviceAdminUserSharingBrowser).
				All(&kept))
			s.Len(kept, 1, "another user trusting the same browser must keep their trust")
		})
	}
}
