package credential_usage

import (
	"fmt"

	"github.com/gofrs/uuid"
	"github.com/teamhanko/hanko/backend/v2/flow_api/flow/shared"
	"github.com/teamhanko/hanko/backend/v2/flowpilot"
)

type PreAuthenticatedContinue struct {
	shared.Action
}

func (a PreAuthenticatedContinue) GetName() flowpilot.ActionName {
	return shared.ActionPreAuthenticatedContinue
}

func (a PreAuthenticatedContinue) GetDescription() string {
	return "Continue login flow with a pre-authenticated user via service token."
}

func (a PreAuthenticatedContinue) Initialize(c flowpilot.InitializationContext) {
	deps := a.GetDeps(c)
	if deps.Cfg.ServiceToken.Secret == "" {
		c.SuspendAction()
		return
	}
	c.AddInputs(flowpilot.StringInput("service_token").Required(true).Hidden(true))
}

func (a PreAuthenticatedContinue) Execute(c flowpilot.ExecutionContext) error {
	deps := a.GetDeps(c)
	serviceToken := c.Input().Get("service_token").String()

	claims, err := validateServiceToken(
		serviceToken,
		deps.Cfg.ServiceToken.Secret,
		deps.Cfg.ServiceToken.Issuer,
	)
	if err != nil {
		return c.Error(flowpilot.ErrorFormDataInvalid.Wrap(fmt.Errorf("service token validation failed: %w", err)))
	}

	userID := uuid.FromStringOrNil(claims.UserID)
	if userID.IsNil() {
		return c.Error(flowpilot.ErrorFormDataInvalid.Wrap(fmt.Errorf("invalid user_id in service token")))
	}

	userModel, err := deps.Persister.GetUserPersisterWithConnection(deps.Tx).Get(userID)
	if err != nil {
		return c.Error(flowpilot.ErrorFormDataInvalid.Wrap(fmt.Errorf("failed to get user: %w", err)))
	}

	if userModel == nil {
		return c.Error(flowpilot.ErrorFormDataInvalid.Wrap(fmt.Errorf("user not found")))
	}

	_ = c.Stash().Set(shared.StashPathUserID, userModel.ID.String())
	if primaryEmail := userModel.Emails.GetPrimary(); primaryEmail != nil {
		_ = c.Stash().Set(shared.StashPathEmail, primaryEmail.Address)
	}
	_ = c.Stash().Set(shared.StashPathUserHasPassword, userModel.PasswordCredential != nil)
	_ = c.Stash().Set(shared.StashPathUserHasPasskey, len(userModel.GetPasskeys()) > 0)
	_ = c.Stash().Set(shared.StashPathUserHasWebauthnCredential, len(userModel.WebauthnCredentials) > 0)
	_ = c.Stash().Set(shared.StashPathUserHasUsername, userModel.GetUsername() != nil)
	_ = c.Stash().Set(shared.StashPathUserHasEmails, len(userModel.Emails) > 0)
	_ = c.Stash().Set(shared.StashPathUserHasOTPSecret, userModel.OTPSecret != nil)
	_ = c.Stash().Set(shared.StashPathUserHasSecurityKey, len(userModel.GetSecurityKeys()) > 0)
	_ = c.Stash().Set(shared.StashPathLoginMethod, "preauthenticated")

	c.PreventRevert()

	return c.Continue()
}
