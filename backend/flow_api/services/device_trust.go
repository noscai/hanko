package services

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	"github.com/teamhanko/hanko/backend/v2/config"
	"github.com/teamhanko/hanko/backend/v2/persistence"
	"github.com/teamhanko/hanko/backend/v2/persistence/models"
	"time"
)

// DeviceTrustEntry represents a single user's device trust token entry
type DeviceTrustEntry struct {
	UserID      uuid.UUID
	DeviceToken string
}

const (
	// entrySeparator separates multiple user entries in the cookie
	entrySeparator = "|"
	// fieldSeparator separates user ID from token within an entry
	fieldSeparator = ":"
	// DefaultMaxUsersPerDevice is the fallback cap on how many users may trust one device when
	// DeviceTrustMaxUsersPerDevice is unset or non-positive.
	DefaultMaxUsersPerDevice = 20
)

// MergeDeviceTrustEntries computes the trust-cookie entry list after a user (re)trusts a device.
//
// Extracted from the flowpilot hook (archon#1667 §4.5) so the single most safety-relevant rule on
// a shared clinic device -- who is evicted when user 21 trusts it, and does the person logging in
// survive? -- is assertable without a flowpilot context or a database.
//
// The acting user's entry is always placed first, so the len>maxUsers truncation can only ever
// evict the OLDEST entries and never the user currently logging in (invariant I3). Re-trusting
// replaces the user's own prior entry rather than duplicating it.
func MergeDeviceTrustEntries(existing []DeviceTrustEntry, newEntry DeviceTrustEntry, maxUsers int) []DeviceTrustEntry {
	if maxUsers <= 0 {
		maxUsers = DefaultMaxUsersPerDevice
	}

	merged := make([]DeviceTrustEntry, 0, len(existing)+1)
	merged = append(merged, newEntry)
	for _, entry := range existing {
		if entry.UserID != newEntry.UserID {
			merged = append(merged, entry)
		}
	}

	if len(merged) > maxUsers {
		merged = merged[:maxUsers]
	}

	return merged
}

// ResolveTrustCookieEntries decides what the device-trust cookie should become for a login, or
// reports that it must not be written at all.
//
// When the trust lifetime is not positive, device trust is disabled for this login: it returns
// (nil, false) so the caller persists nothing and leaves any existing cookie untouched. Writing
// entries in that state is archon#1667 OQ3 -- the hook used to prepend a token that was never
// stored and truncate a real user off the end, a phantom entry that evicts a genuinely-trusted
// user while never validating itself. Concretely reachable only at maxAgeSeconds == 0 (Go renders
// a negative cookie MaxAge as immediate deletion). Not prod-reachable -- every cluster sets 168h --
// but a config change to 0 would trigger it, so the guard is enforced here, not left implicit.
func ResolveTrustCookieEntries(existing []DeviceTrustEntry, newEntry DeviceTrustEntry, maxUsers, maxAgeSeconds int) (entries []DeviceTrustEntry, active bool) {
	if maxAgeSeconds <= 0 {
		return nil, false
	}
	return MergeDeviceTrustEntries(existing, newEntry, maxUsers), true
}

type DeviceTrustService struct {
	Persister   persistence.TrustedDevicePersister
	Cfg         config.Config
	HttpContext echo.Context
}

func (s DeviceTrustService) CreateTrustedDevice(userID uuid.UUID, deviceToken string) error {
	deviceID, err := uuid.NewV4()
	if err != nil {
		return fmt.Errorf("failed to generate device id: %w", err)
	}

	trustedDeviceModel := models.TrustedDevice{
		ID:          deviceID,
		UserID:      userID,
		DeviceToken: deviceToken,
		ExpiresAt:   time.Now().Add(s.Cfg.MFA.DeviceTrustDuration).UTC(),
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}

	err = s.Persister.Create(trustedDeviceModel)
	if err != nil {
		return fmt.Errorf("failed to store trusted device: %w", err)
	}

	return nil
}

func (s DeviceTrustService) CheckDeviceTrust(userID uuid.UUID) bool {
	if userID.IsNil() || s.Cfg.MFA.DeviceTrustPolicy == "never" {
		return false
	}

	cookieName := s.Cfg.MFA.DeviceTrustCookieName
	cookie, _ := s.HttpContext.Cookie(cookieName)

	if cookie == nil {
		return false
	}

	entries := s.ParseDeviceTrustCookie(cookie.Value)

	// Handle legacy format (single token without user ID)
	if entries == nil && cookie.Value != "" {
		// Legacy: look up token in DB to check if it belongs to this user
		trustedDevice, err := s.Persister.FindByDeviceToken(cookie.Value)
		if err == nil && trustedDevice != nil &&
			time.Now().UTC().Before(trustedDevice.ExpiresAt.UTC()) &&
			trustedDevice.UserID.String() == userID.String() {
			return true
		}
		return false
	}

	// New format: find entry for this user
	for _, entry := range entries {
		if entry.UserID.String() == userID.String() {
			trustedDevice, err := s.Persister.FindByDeviceToken(entry.DeviceToken)
			if err == nil && trustedDevice != nil &&
				time.Now().UTC().Before(trustedDevice.ExpiresAt.UTC()) &&
				trustedDevice.UserID.String() == userID.String() {
				return true
			}
		}
	}

	return false
}

func (s DeviceTrustService) GenerateRandomToken(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// ParseDeviceTrustCookie parses a composite device trust cookie value into individual entries.
// Returns nil if the cookie is empty or in legacy format (single token without user ID).
// Legacy format detection: no separators means it's a single token.
func (s DeviceTrustService) ParseDeviceTrustCookie(cookieValue string) []DeviceTrustEntry {
	if cookieValue == "" {
		return nil
	}

	// Legacy format detection (no separators = single token)
	if !strings.Contains(cookieValue, entrySeparator) && !strings.Contains(cookieValue, fieldSeparator) {
		return nil // Caller handles legacy migration
	}

	var entries []DeviceTrustEntry
	parts := strings.Split(cookieValue, entrySeparator)

	for _, part := range parts {
		fields := strings.SplitN(part, fieldSeparator, 2)
		if len(fields) != 2 {
			continue // Skip malformed entries
		}

		userID, err := uuid.FromString(fields[0])
		if err != nil {
			continue // Skip invalid user IDs
		}

		entries = append(entries, DeviceTrustEntry{
			UserID:      userID,
			DeviceToken: fields[1],
		})
	}

	return entries
}

// SerializeDeviceTrustCookie serializes device trust entries into a composite cookie value.
// Format: <user_id_1>:<token_1>|<user_id_2>:<token_2>|...
func (s DeviceTrustService) SerializeDeviceTrustCookie(entries []DeviceTrustEntry) string {
	if len(entries) == 0 {
		return ""
	}

	parts := make([]string, len(entries))
	for i, entry := range entries {
		parts[i] = entry.UserID.String() + fieldSeparator + entry.DeviceToken
	}

	return strings.Join(parts, entrySeparator)
}
