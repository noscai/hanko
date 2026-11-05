package shared

import (
	"github.com/gofrs/uuid"

	"github.com/teamhanko/hanko/backend/v2/flow_api/services"
	"github.com/teamhanko/hanko/backend/v2/flowpilot/jsonmanager"
)

// FlowTenantID returns the tenant this flow runs under: the one pinned in the stash, or, until a
// tenant is pinned, the request's (X-Tenant-ID). Device trust is created and matched under it and a
// global user's session names it (archon#1085 Q15, Q18).
//
// The pin exists because X-Tenant-ID is a client header, sent again on every request of a flow. A
// flow that decided device trust under one clinic's header must not issue its trust row or its
// session under another clinic's header on a later request: that would let trust recorded for
// clinic A skip clinic B's second factor.
//
// A pinned value that does not parse resolves to no tenant, which matches only legacy trust rows
// and puts no tenant in the session, so a switch to a clinic refuses it rather than trusting it.
func FlowTenantID(stash jsonmanager.ReadJSONManager, requestTenantID *uuid.UUID) *uuid.UUID {
	pinned := stash.Get(StashPathFlowTenantID)
	if !pinned.Exists() {
		return requestTenantID
	}

	tenantID, err := uuid.FromString(pinned.String())
	if err != nil {
		return nil
	}

	return &tenantID
}

// PinFlowTenantID fixes the flow's tenant for the rest of the flow. A nil tenantID pins "no
// tenant", so a header sent on a later request cannot add one either.
func PinFlowTenantID(stash jsonmanager.JSONManager, tenantID *uuid.UUID) error {
	value := ""
	if tenantID != nil {
		value = tenantID.String()
	}

	return stash.Set(StashPathFlowTenantID, value)
}

// FlowDeviceTrustService is the device-trust service for this flow: trust is checked and written
// under the flow tenant (FlowTenantID). Every hook builds it here, so none can forget the tenant:
// a zero TenantID means "tenantless flow" and matches legacy rows, it does not fail closed.
func FlowDeviceTrustService(stash jsonmanager.ReadJSONManager, deps *Dependencies) services.DeviceTrustService {
	return services.DeviceTrustService{
		Persister:   deps.Persister.GetTrustedDevicePersisterWithConnection(deps.Tx),
		Cfg:         deps.Cfg,
		HttpContext: deps.HttpContext,
		TenantID:    FlowTenantID(stash, deps.TenantID),
	}
}
