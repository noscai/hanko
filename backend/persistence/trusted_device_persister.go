package persistence

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/teamhanko/hanko/backend/v2/persistence/models"
)

type TrustedDevicePersister interface {
	Create(models.TrustedDevice) error
	FindByDeviceToken(string) (*models.TrustedDevice, error)
	// FindValidTrust looks up a still-valid trust row for the exact (deviceToken, userID) pair.
	// It returns the row itself rather than a bool so callers can re-assert row.UserID == userID
	// in Go as an independent check on top of the SQL predicate -- see the persister's Create doc
	// for why a shared device_token makes that redundancy load-bearing rather than defensive
	// dead code.
	FindValidTrust(deviceToken string, userID uuid.UUID, now time.Time) (*models.TrustedDevice, error)
}

type trustedDevicePersister struct {
	db *pop.Connection
}

func NewTrustedDevicePersister(db *pop.Connection) TrustedDevicePersister {
	return &trustedDevicePersister{db: db}
}

// Create upserts on (device_token, user_id) -- see trusted_devices_token_user_idx
// (20260828085758_add_trusted_devices_token_user_unique). A device_token is now shared by every
// user who has trusted that browser, so re-trusting the same (device_token, user_id) pair on
// login must refresh the existing row's expires_at rather than insert a second row for the same
// pair: a plain INSERT would violate the unique index on re-trust, and a SELECT-then-decide
// would race two concurrent re-trusts of the same pair into two INSERTs. ON CONFLICT resolves
// both by constraint instead of by luck.
//
// This can't go through pop's ValidateAndCreate (no ON CONFLICT support), so it validates the
// model explicitly before the raw-SQL upsert. Skipping that step would let an empty or
// malformed device_token persist silently -- Validate is what enforces the 64-128 char length
// that makes a device_token a device_token; see models.TrustedDevice.Validate.
func (p *trustedDevicePersister) Create(trustedDevice models.TrustedDevice) error {
	vErr, err := trustedDevice.Validate(p.db)
	if err != nil {
		return fmt.Errorf("failed to store trustedDevice: %w", err)
	}
	if vErr != nil && vErr.HasAny() {
		return fmt.Errorf("trustedDevice object validation failed: %w", vErr)
	}

	err = p.db.RawQuery(
		`INSERT INTO trusted_devices (id, user_id, device_token, expires_at, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT (device_token, user_id)
		 DO UPDATE SET expires_at = EXCLUDED.expires_at, updated_at = EXCLUDED.updated_at`,
		trustedDevice.ID, trustedDevice.UserID, trustedDevice.DeviceToken, trustedDevice.ExpiresAt,
		trustedDevice.CreatedAt, trustedDevice.UpdatedAt,
	).Exec()
	if err != nil {
		return fmt.Errorf("failed to store trustedDevice: %w", err)
	}

	return nil
}

// FindByDeviceToken answers "has this device token ever been issued?" -- device_token alone, no
// user scoping. Its only production caller is the write path's anti-planting gate
// (IssueTrustDeviceCookie), which reuses a token presented in the cookie only if it already backs
// at least one row; without that check somebody with devtools access to a shared workstation could
// plant a token they choose and have every later truster's row filed under it.
//
// The unscoped lookup is therefore deliberate and must stay unscoped -- but for that reason it must
// never be used to decide whether a user is trusted. FindValidTrust is the scoped counterpart every
// read path uses. (This was the v0/v1 read lookup until those branches moved to FindValidTrust.)
func (p *trustedDevicePersister) FindByDeviceToken(token string) (*models.TrustedDevice, error) {
	return p.findOne(p.db.Where("device_token = ?", token))
}

func (p *trustedDevicePersister) FindValidTrust(deviceToken string, userID uuid.UUID, now time.Time) (*models.TrustedDevice, error) {
	return p.findOne(p.db.Where("device_token = ? AND user_id = ? AND expires_at > ?", deviceToken, userID, now))
}

func (p *trustedDevicePersister) findOne(q *pop.Query) (*models.TrustedDevice, error) {
	trustedDevice := models.TrustedDevice{}
	err := q.First(&trustedDevice)
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get trustedDevice: %w", err)
	}

	return &trustedDevice, nil
}
