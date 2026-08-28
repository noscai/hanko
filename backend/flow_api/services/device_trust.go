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
	// deviceTokenPrefix marks a v2 device-scoped cookie value. base64.URLEncoding never produces
	// ".", ":" or "|", so this prefix makes v0 (bare token), v1 (composite) and v2 mutually
	// exclusive by construction -- without it, a v2 value would be misread by
	// ParseDeviceTrustCookie's separator sniffing as a v0 legacy token and matched against one
	// arbitrary DB row, silently breaking trust for every other user on a shared device.
	deviceTokenPrefix = "d1."
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

// CheckDeviceTrust answers "may this user skip the second factor on this browser?" by trying
// every cookie format the migration window can present -- v2, then v1, then v0 -- and returning
// true on the first branch that VALIDATES. False is returned only once every applicable branch
// has been tried.
//
// This is a logical OR over results, not a dispatch on cookie format, and the difference is the
// whole point. On deploy day a shared clinic workstation carries the legacy cookie holding N
// colleagues' v1 entries. The moment one of them re-trusts the browser it also gains a v2 cookie,
// while every other pre-deploy user on that machine still has only a v1 entry and no v2 row of
// their own. Stopping at the v2 branch because a v2 cookie merely exists and parses would refuse
// all of them and re-challenge an entire clinic for a full 2FA code -- the exact outcome this
// design exists to prevent. Each branch therefore tolerates its own cookie being absent,
// unreadable, or backed by no row, and falls through to the next.
//
// Fails closed at branch granularity: a persister error is a false for that branch only, never a
// true and never a panic.
func (s DeviceTrustService) CheckDeviceTrust(userID uuid.UUID) bool {
	if userID.IsNil() || s.Cfg.MFA.DeviceTrustPolicy == "never" {
		return false
	}

	// One clock for all three branches, so the expiry boundary cannot move mid-decision.
	now := time.Now().UTC()

	return s.checkV2(userID, now) ||
		s.checkComposite(userID, now) ||
		s.checkLegacy(userID, now)
}

// cookieValue returns the value of the named cookie, or "" when the cookie is absent, unreadable,
// or the name is unconfigured.
//
// Each branch of CheckDeviceTrust's OR calls this instead of the function returning early on a
// missing cookie. With two cookie names in play, a single "no cookie -> false" short-circuit at
// the top would end the OR before any branch was evaluated: a browser holding only the legacy
// cookie would be refused the moment the v2 name was the one checked first, re-challenging every
// pre-deploy user on a shared workstation. Absence is a property of one branch, not of the
// decision.
func (s DeviceTrustService) cookieValue(name string) string {
	if name == "" {
		return ""
	}
	cookie, err := s.HttpContext.Cookie(name)
	if err != nil || cookie == nil {
		return ""
	}
	return cookie.Value
}

// checkV2 reads the device-scoped cookie ("d1.<token>"): one token for the whole browser, with
// trust recorded per (device_token, user_id) in the database. A token another colleague minted on
// this device is therefore not, by itself, trust for this user.
func (s DeviceTrustService) checkV2(userID uuid.UUID, now time.Time) bool {
	token, ok := ParseDeviceIDCookie(s.cookieValue(s.Cfg.MFA.DeviceTrustDeviceCookieName))
	if !ok {
		return false
	}
	return s.hasValidTrust(token, userID, now)
}

// checkComposite reads the v1 legacy-cookie format, "<uuid>:<token>|<uuid>:<token>|...", and
// validates every entry claiming this user rather than only the first. The cookie is
// attacker-editable, so an entry merely nominates a token; the database decides.
func (s DeviceTrustService) checkComposite(userID uuid.UUID, now time.Time) bool {
	for _, entry := range s.ParseDeviceTrustCookie(s.cookieValue(s.Cfg.MFA.DeviceTrustCookieName)) {
		if entry.UserID == userID && s.hasValidTrust(entry.DeviceToken, userID, now) {
			return true
		}
	}
	return false
}

// checkLegacy reads a v0 legacy-cookie value: a bare token carrying no user id, issued before the
// composite format existed. It shares the cookie with v1 and is told apart from it by the same
// predicate ParseDeviceTrustCookie uses, so the cookie's two readers cannot disagree about which
// format they are looking at (invariant I1).
func (s DeviceTrustService) checkLegacy(userID uuid.UUID, now time.Time) bool {
	value := s.cookieValue(s.Cfg.MFA.DeviceTrustCookieName)
	if !isLegacyBareToken(value) {
		return false
	}
	return s.hasValidTrust(value, userID, now)
}

// hasValidTrust is the one place where a nominated token becomes trust. The persister filters
// (device_token, user_id, expires_at > now) in SQL and returns the row; the row's user is then
// re-asserted here in Go.
//
// The redundancy is deliberate and load-bearing. One device_token is now shared by every user who
// has trusted the browser, so a dropped user_id predicate in that query would not merely widen a
// lookup -- it would hand every user on a shared device a second-factor bypass the moment one of
// them trusted it. A field comparison is cheap enough to keep as a standing assertion against
// that.
func (s DeviceTrustService) hasValidTrust(deviceToken string, userID uuid.UUID, now time.Time) bool {
	trustedDevice, err := s.Persister.FindValidTrust(deviceToken, userID, now)
	if err != nil || trustedDevice == nil {
		return false
	}
	return trustedDevice.UserID == userID
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
	if isLegacyBareToken(cookieValue) {
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

// ParseDeviceIDCookie decodes a v2 device-scoped cookie value ("d1.<token>") into its bare
// token. Named for the cookie it reads (clinicos-2fa-device-id, config key
// device_trust_device_cookie_name) rather than "v2" or "...Token" -- it sits ~35 lines from
// ParseDeviceTrustCookie, which parses a different cookie into a different shape
// ([]DeviceTrustEntry vs (string, bool)); a same-prefixed name would make the two easy to
// transpose once later tasks wire both into the same resolution path. A pure function,
// deliberately independent of DeviceTrustService (no receiver, no DB, no echo context) so the
// v0/v1/v2 discrimination rule stays testable in isolation from the rest of the cookie machinery.
//
// Rejects an empty remainder ("d1." -> ("", false)) rather than returning ok=true with an empty
// token: defense-in-depth -- fail closed here rather than trust the downstream DB constraints
// (TrustedDevice.DeviceToken's StringIsPresent + StringLengthInRange) to hold forever.
// isLegacyBareToken reports whether a legacy-cookie value is a v0 token: a bare token carrying no
// user id, told apart from the v1 composite format only by the absence of both separators.
// base64.URLEncoding (the token alphabet) never produces ":" or "|", so the test is exact.
//
// Shared by ParseDeviceTrustCookie and CheckDeviceTrust's v0 branch so the legacy cookie's two
// readers can never drift apart about which format a value is (invariant I1).
func isLegacyBareToken(cookieValue string) bool {
	return cookieValue != "" &&
		!strings.Contains(cookieValue, entrySeparator) &&
		!strings.Contains(cookieValue, fieldSeparator)
}

func ParseDeviceIDCookie(cookieValue string) (token string, ok bool) {
	rest, found := strings.CutPrefix(cookieValue, deviceTokenPrefix)
	if !found || rest == "" {
		return "", false
	}
	return rest, true
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
