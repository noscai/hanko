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
	// FindValidTrust looks up a still-valid trust row for the exact (deviceToken, userID) pair,
	// recorded under tenantID -- or, for a nil tenantID, recorded under no tenant (see
	// models.TrustedDevice.MatchesTenant). It returns the row itself rather than a bool so callers
	// can re-assert row.UserID == userID and the tenant in Go as an independent check on top of the
	// SQL predicate -- see the persister's Create doc for why a shared device_token makes that
	// redundancy load-bearing rather than defensive dead code.
	FindValidTrust(deviceToken string, userID uuid.UUID, tenantID *uuid.UUID, now time.Time) (*models.TrustedDevice, error)
	// DeleteByUserID deletes every trust row of the user, expired or not, under every tenant, and
	// only that user's: another user who trusted the same browser shares its device_token but keeps
	// their row.
	DeleteByUserID(userID uuid.UUID) error
}

type trustedDevicePersister struct {
	db *pop.Connection
}

func NewTrustedDevicePersister(db *pop.Connection) TrustedDevicePersister {
	return &trustedDevicePersister{db: db}
}

// Create records trust for (device_token, user_id) under the row's tenant: it refreshes the row
// that already holds it, or inserts one. A device_token is shared by every user who has trusted
// that browser, so re-trusting must refresh the existing row's expires_at rather than pile up a
// second row for it.
//
// Trust is per clinic (archon#1085 Q15), and the unique keys move in two releases. This one adds
// the per-tenant partial indexes (trusted_devices_token_user_tenant_idx and
// trusted_devices_token_user_global_idx, 20261101235835_add_trusted_devices_tenant_id) and keeps
// trusted_devices_token_user_idx on (device_token, user_id), because the previous image upserts
// with ON CONFLICT (device_token, user_id) and keeps serving while a rollout runs. Task 34 drops
// the pair index once no such pod is left. Create therefore names no conflict target and works
// under both sets of indexes; see upsertTrustedDevice for the order of its statements.
//
// It validates the model explicitly before the raw SQL: skipping that would let an empty or
// malformed device_token persist silently -- Validate is what enforces the 64-128 char length
// that makes a device_token a device_token; see models.TrustedDevice.Validate.
//
// POSTGRES-ONLY, deliberately: `ON CONFLICT DO NOTHING` is PostgreSQL syntax. That is not a
// regression this introduces: the fork already cannot run on MySQL, because
// 20260120000003_change_unique_constraints.up.fizz creates PARTIAL unique indexes (`... WHERE
// tenant_id IS NOT NULL`) for the multi-tenant model, and MySQL has no partial indexes at all. All
// three clusters use `postgres://`.
func (p *trustedDevicePersister) Create(trustedDevice models.TrustedDevice) error {
	vErr, err := trustedDevice.Validate(p.db)
	if err != nil {
		return fmt.Errorf("failed to store trustedDevice: %w", err)
	}
	if vErr != nil && vErr.HasAny() {
		return fmt.Errorf("trustedDevice object validation failed: %w", vErr)
	}

	return upsertTrustedDevice(sqlTrustWriter{db: p.db}, trustedDevice)
}

// trustWriter is the three statements Create is built from, so the order they run in can be
// tested without a database.
type trustWriter interface {
	// refresh moves expires_at of the row holding this trust: same device_token, user and tenant
	// (both NULL counting as the same).
	refresh(models.TrustedDevice) (int, error)
	// insertIfAbsent inserts the row unless any unique index already holds one like it.
	insertIfAbsent(models.TrustedDevice) (int, error)
	// moveToTenant gives the latest-expiring row of this (device_token, user_id) the row's tenant
	// and expiry.
	moveToTenant(models.TrustedDevice) (int, error)
}

// upsertTrustedDevice refreshes the row holding this trust, or inserts it, or -- while the pair
// index stands -- moves the browser's one row for this user to this tenant. It stops at the first
// statement that writes a row.
//
//  1. refresh: re-trusting under the same tenant, the common case.
//  2. insertIfAbsent: first trust. ON CONFLICT DO NOTHING without a target, so a conflict on any
//     unique index -- the pair index now, the per-tenant ones after task 34 -- writes nothing and
//     raises nothing. Raising would abort the flow's transaction; a SAVEPOINT per write is the
//     alternative this avoids.
//  3. refresh again: the insert lost a race to a concurrent trust of the same tenant, committed
//     between 1 and 2. That row is ours to refresh.
//  4. moveToTenant: reached only while the pair index stands, when this browser and user already
//     hold one row under another tenant (or none). The index allows no second row, so trust follows
//     the flow that trusted last. Before task 34 a user belongs to one tenant, so this is the move
//     between that tenant and a flow sent without X-Tenant-ID. It only ever grants the tenant
//     whose flow just authenticated the user, and takes away the other one's skip.
func upsertTrustedDevice(w trustWriter, trustedDevice models.TrustedDevice) error {
	steps := []func(models.TrustedDevice) (int, error){w.refresh, w.insertIfAbsent, w.refresh, w.moveToTenant}
	for _, step := range steps {
		written, err := step(trustedDevice)
		if err != nil {
			return fmt.Errorf("failed to store trustedDevice: %w", err)
		}
		if written > 0 {
			return nil
		}
	}

	return fmt.Errorf("failed to store trustedDevice: no row was inserted or updated")
}

type sqlTrustWriter struct {
	db *pop.Connection
}

func (w sqlTrustWriter) refresh(trustedDevice models.TrustedDevice) (int, error) {
	return w.db.RawQuery(
		`UPDATE trusted_devices SET expires_at = ?, updated_at = ?
		 WHERE device_token = ? AND user_id = ? AND tenant_id IS NOT DISTINCT FROM ?`,
		trustedDevice.ExpiresAt, trustedDevice.UpdatedAt,
		trustedDevice.DeviceToken, trustedDevice.UserID, nullableTenant(trustedDevice.TenantID),
	).ExecWithCount()
}

func (w sqlTrustWriter) insertIfAbsent(trustedDevice models.TrustedDevice) (int, error) {
	return w.db.RawQuery(
		`INSERT INTO trusted_devices (id, user_id, tenant_id, device_token, expires_at, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT DO NOTHING`,
		trustedDevice.ID, trustedDevice.UserID, nullableTenant(trustedDevice.TenantID), trustedDevice.DeviceToken,
		trustedDevice.ExpiresAt, trustedDevice.CreatedAt, trustedDevice.UpdatedAt,
	).ExecWithCount()
}

func (w sqlTrustWriter) moveToTenant(trustedDevice models.TrustedDevice) (int, error) {
	return w.db.RawQuery(
		`UPDATE trusted_devices SET tenant_id = ?, expires_at = ?, updated_at = ?
		 WHERE id = (SELECT id FROM trusted_devices WHERE device_token = ? AND user_id = ?
		             ORDER BY expires_at DESC, id DESC LIMIT 1)`,
		nullableTenant(trustedDevice.TenantID), trustedDevice.ExpiresAt, trustedDevice.UpdatedAt,
		trustedDevice.DeviceToken, trustedDevice.UserID,
	).ExecWithCount()
}

// nullableTenant passes a missing tenant to the driver as an untyped nil, i.e. SQL NULL.
func nullableTenant(tenantID *uuid.UUID) interface{} {
	if tenantID == nil {
		return nil
	}
	return *tenantID
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

func (p *trustedDevicePersister) FindValidTrust(deviceToken string, userID uuid.UUID, tenantID *uuid.UUID, now time.Time) (*models.TrustedDevice, error) {
	query := p.db.Where("device_token = ? AND user_id = ? AND expires_at > ?", deviceToken, userID, now)
	if tenantID != nil {
		query = query.Where("tenant_id = ?", *tenantID)
	} else {
		query = query.Where("tenant_id IS NULL")
	}
	return p.findOne(query)
}

func (p *trustedDevicePersister) DeleteByUserID(userID uuid.UUID) error {
	err := p.db.RawQuery("DELETE FROM trusted_devices WHERE user_id = ?", userID).Exec()
	if err != nil {
		return fmt.Errorf("failed to delete trustedDevices of user: %w", err)
	}

	return nil
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
