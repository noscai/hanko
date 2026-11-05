package models

import (
	"github.com/gobuffalo/pop/v6"
	"github.com/gobuffalo/validate/v3"
	"github.com/gobuffalo/validate/v3/validators"
	"github.com/gofrs/uuid"
	"time"
)

type TrustedDevice struct {
	AuthenticatedAt time.Time  `db:"-" json:"-"`
	ID              uuid.UUID  `db:"id"`
	UserID          uuid.UUID  `db:"user_id"`
	TenantID        *uuid.UUID `db:"tenant_id"`
	DeviceToken     string     `db:"device_token"`
	ExpiresAt       time.Time  `db:"expires_at"`
	CreatedAt       time.Time  `db:"created_at"`
	UpdatedAt       time.Time  `db:"updated_at"`
}

// MatchesTenant reports whether this trust may skip the second factor in a flow that runs under
// flowTenantID. Trust is recorded per clinic (archon#1085 Q15): one Hanko user signs in to every
// clinic they belong to, so a browser trusted under clinic A must not skip clinic B's code. A row
// with no tenant -- written before trust was scoped, or by a flow that ran without a tenant --
// answers only a flow without a tenant.
//
// TrustedDevicePersister.FindValidTrust filters on the same rule in SQL; DeviceTrustService
// re-asserts it in Go on the row it gets back, as it does for the user.
func (trustedDevice *TrustedDevice) MatchesTenant(flowTenantID *uuid.UUID) bool {
	if trustedDevice.TenantID == nil || flowTenantID == nil {
		return trustedDevice.TenantID == nil && flowTenantID == nil
	}
	return *trustedDevice.TenantID == *flowTenantID
}

func (trustedDevice *TrustedDevice) Validate(tx *pop.Connection) (*validate.Errors, error) {
	return validate.Validate(
		&validators.UUIDIsPresent{Name: "ID", Field: trustedDevice.ID},
		&validators.UUIDIsPresent{Name: "UserID", Field: trustedDevice.UserID},
		&validators.StringIsPresent{Name: "DeviceToken", Field: trustedDevice.DeviceToken},
		&validators.StringLengthInRange{Name: "DeviceToken", Field: trustedDevice.DeviceToken, Min: 64, Max: 128},
		&validators.TimeIsPresent{Name: "ExpiresAt", Field: trustedDevice.ExpiresAt},
		&validators.TimeIsPresent{Name: "UpdatedAt", Field: trustedDevice.UpdatedAt},
		&validators.TimeIsPresent{Name: "CreatedAt", Field: trustedDevice.CreatedAt},
	), nil
}
