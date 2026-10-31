package handler

import (
	"fmt"
	"net/http"

	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	"github.com/teamhanko/hanko/backend/v2/dto/admin"
	"github.com/teamhanko/hanko/backend/v2/persistence"
)

type TrustedDeviceAdminHandler interface {
	Delete(ctx echo.Context) error
}

type trustedDeviceAdminHandler struct {
	persister persistence.Persister
}

func NewTrustedDeviceAdminHandler(persister persistence.Persister) TrustedDeviceAdminHandler {
	return &trustedDeviceAdminHandler{persister: persister}
}

// Delete revokes every browser the user trusted, so each one asks for the second factor again.
// A ClinicOS 2FA reset of a user shared with other clinics deletes only the user's OTP secret, not
// the user, and the trusted_devices cascade on user deletion never fires. A user with no trusted
// devices is still 204: the caller wants the end state, not a record that something was removed.
func (h *trustedDeviceAdminHandler) Delete(ctx echo.Context) error {
	deleteDto, err := loadDto[admin.DeleteTrustedDevicesRequestDto](ctx)
	if err != nil {
		return err
	}

	userID, err := uuid.FromString(deleteDto.UserID)
	if err != nil {
		return fmt.Errorf(parseUserUuidFailureMessage, err)
	}

	userModel, err := h.persister.GetUserPersister().Get(userID)
	if err != nil {
		return err
	}

	if userModel == nil {
		return echo.NewHTTPError(http.StatusNotFound, "user not found")
	}

	err = h.persister.GetTrustedDevicePersister().DeleteByUserID(userModel.ID)
	if err != nil {
		return err
	}

	return ctx.NoContent(http.StatusNoContent)
}
