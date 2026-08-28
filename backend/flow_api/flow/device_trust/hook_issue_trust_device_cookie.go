package device_trust

import (
	"fmt"
	"net/http"

	"github.com/gofrs/uuid"
	"github.com/teamhanko/hanko/backend/v2/flow_api/flow/shared"
	"github.com/teamhanko/hanko/backend/v2/flow_api/services"
	"github.com/teamhanko/hanko/backend/v2/flowpilot"
)

// deviceTokenBytes is the entropy behind a device token, base64url-encoded into the cookie (64
// bytes -> 88 chars, inside models.TrustedDevice's 64..128 length validation).
const deviceTokenBytes = 64

type IssueTrustDeviceCookie struct {
	shared.Action
}

// Execute records "trust this browser for the next N days" for the user who just authenticated.
//
// The browser is given ONE device token, in the v2 device cookie, and trust is recorded per
// (device_token, user_id) in trusted_devices. That is the whole point of this shape: the cookie
// used to carry an entry per user ("<uuid>:<token>|...") capped at 20, so on a shared clinic
// workstation the 21st person to trust the browser silently evicted the 1st -- whose row was
// still there, unexpired, with the browser's only pointer to it gone. Cookie size no longer
// depends on headcount, so there is nothing to evict.
//
// The legacy cookie is never written here again. CheckDeviceTrust still READS it, so everyone
// already trusted through it keeps their skip until it expires on its own; rewriting it would
// keep the per-user growth alive indefinitely.
func (h IssueTrustDeviceCookie) Execute(c flowpilot.HookExecutionContext) error {
	deps := h.GetDeps(c)

	if deps.Cfg.MFA.DeviceTrustPolicy == "never" ||
		(deps.Cfg.MFA.DeviceTrustPolicy == "prompt" && !c.Stash().Get(shared.StashPathDeviceTrustGranted).Bool()) {
		return nil
	}

	if !c.Stash().Get(shared.StashPathUserID).Exists() {
		return fmt.Errorf("user id does not exist in the stash")
	}

	userID, err := uuid.FromString(c.Stash().Get(shared.StashPathUserID).String())
	if err != nil {
		return fmt.Errorf("failed to parse stashed user_id into a uuid: %w", err)
	}

	maxAge := int(deps.Cfg.MFA.DeviceTrustDuration.Seconds())

	// Device trust disabled for this login (non-positive lifetime): persist nothing and leave any
	// existing cookie untouched. Writing here is archon#1667 OQ3 -- a trust record the browser is
	// handed but that can never validate itself. Concretely reachable only at maxAge == 0 (Go
	// renders a negative cookie MaxAge as immediate deletion). Not prod-reachable -- every cluster
	// sets 168h -- but a config change to 0 would trigger it, so the guard is explicit.
	if maxAge <= 0 {
		return nil
	}

	deviceTrustService := services.DeviceTrustService{
		Persister:   deps.Persister.GetTrustedDevicePersisterWithConnection(deps.Tx),
		Cfg:         deps.Cfg,
		HttpContext: deps.HttpContext,
	}

	deviceToken, err := resolveDeviceToken(deviceTrustService, presentedDeviceCookie(deps))
	if err != nil {
		return fmt.Errorf("failed to resolve trusted device token: %w", err)
	}

	if err = deviceTrustService.CreateTrustedDevice(userID, deviceToken); err != nil {
		return fmt.Errorf("failed to store trusted device: %w", err)
	}

	cookie := new(http.Cookie)
	cookie.Name = deps.Cfg.MFA.DeviceTrustDeviceCookieName
	cookie.Value = services.FormatDeviceIDCookie(deviceToken)
	cookie.Path = "/"
	cookie.HttpOnly = true
	cookie.Secure = true
	cookie.MaxAge = maxAge
	cookie.SameSite = http.SameSiteNoneMode

	deps.HttpContext.SetCookie(cookie)

	return nil
}

// resolveDeviceToken decides which device token this browser carries away from this login: reuse
// the one it presented, or mint a fresh one.
func resolveDeviceToken(svc services.DeviceTrustService, presentedCookie string) (string, error) {
	if token, ok := services.ParseDeviceIDCookie(presentedCookie); ok && isIssuedDeviceToken(svc, token) {
		return token, nil
	}
	return svc.GenerateRandomToken(deviceTokenBytes)
}

// isIssuedDeviceToken reports whether a token the browser presented is one this server actually
// issued -- i.e. at least one user already trusts this browser under it.
//
// This check is a deliberate addition to the design, which says only "reuse the cookie's token
// when present". The cookie is attacker-writable: anyone with devtools or a minute at a shared
// front desk can plant d1.<token-they-chose>. Reused unvalidated, every colleague who trusted
// that browser afterwards would get a row under a token the attacker already holds, and that one
// cookie would then skip the second factor for all of them, anywhere. Requiring the token to
// already exist closes drive-by planting; it does NOT stop someone who has their own account on
// that machine from seeding a token they know first, and that residual is accepted, not solved
// here.
//
// A read failure is reported as "not issued", so the login mints a fresh token rather than
// reusing one it could not verify or failing the flow outright. Fail-closed on the security
// question (an unverified token is never adopted) and open on the convenience one (a database
// blip must not block a second-factor flow). The blast radius is bounded: the very next call
// writes through the same persister, so a real outage errors there and the hook aborts with no
// cookie written; a read-only failure costs colleagues on this browser one extra 2FA code and
// never grants a skip.
func isIssuedDeviceToken(svc services.DeviceTrustService, token string) bool {
	trustedDevice, err := svc.Persister.FindByDeviceToken(token)
	return err == nil && trustedDevice != nil
}

// presentedDeviceCookie returns the raw v2 cookie value the request carries, or "" when the
// cookie is absent, unreadable, or its name is unconfigured.
func presentedDeviceCookie(deps *shared.Dependencies) string {
	name := deps.Cfg.MFA.DeviceTrustDeviceCookieName
	if name == "" {
		return ""
	}
	cookie, err := deps.HttpContext.Cookie(name)
	if err != nil || cookie == nil {
		return ""
	}
	return cookie.Value
}
