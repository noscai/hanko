package admin

type DeleteTrustedDevicesRequestDto struct {
	UserID string `param:"user_id" validate:"required,uuid"`
}
