package registration

import (
	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	auditlog "github.com/teamhanko/hanko/backend/v2/audit_log"
	"github.com/teamhanko/hanko/backend/v2/flow_api/flow/shared"
	"github.com/teamhanko/hanko/backend/v2/flowpilot"
	"github.com/teamhanko/hanko/backend/v2/persistence"
	"github.com/teamhanko/hanko/backend/v2/persistence/models"
	"github.com/tidwall/gjson"
	"testing"
)

type registrationContext struct {
	flowpilot.HookExecutionContext
	deps *shared.Dependencies
}

func (c *registrationContext) Get(key string) interface{} {
	if key == "deps" {
		return c.deps
	}
	return c.HookExecutionContext.Get(key)
}

type registrationUsers struct {
	persistence.UserPersister
	created models.User
}

func (p *registrationUsers) Create(v models.User) error { p.created = v; return nil }

type registrationStore struct {
	persistence.Persister
	users   *registrationUsers
	tenants map[string]*uuid.UUID
}

func (p registrationStore) GetUserPersisterWithConnection(*pop.Connection) persistence.UserPersister {
	return p.users
}
func TestFreshRegistrationGlobalIdentity(t *testing.T) {
	tenant := uuid.FromStringOrNil("aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa")
	for _, keep := range []bool{false, true} {
		name := "legacy"
		if keep {
			name = "global"
		}
		t.Run(name, func(t *testing.T) {
			users := &registrationUsers{}
			deps := &shared.Dependencies{TenantID: &tenant, Persister: &registrationStore{users: users, tenants: map[string]*uuid.UUID{}}, AuditLogger: registrationAudit{}}
			deps.Cfg.MultiTenant.Enabled = true
			deps.Cfg.MultiTenant.AllowGlobalUsers = true
			deps.Cfg.MultiTenant.KeepUsersGlobal = keep
			ctx := &registrationContext{HookExecutionContext: flowpilot.NewMockHookExecutionContext(), deps: deps}
			hook := CreateUser{}
			err := hook.createUser(ctx, tenant, "fresh@test.nosc.ai", true, "fresh", []gjson.Result{gjson.Parse(`{"id":"credential"}`)}, "hash", "secret")
			require.NoError(t, err)
			for kind, scope := range deps.Persister.(*registrationStore).tenants {
				if keep {
					require.Nil(t, scope, kind)
				} else {
					require.Equal(t, &tenant, scope, kind)
				}
			}
			require.Len(t, deps.Persister.(*registrationStore).tenants, 5)
			if keep {
				require.Nil(t, users.created.TenantID)
			} else {
				require.Equal(t, &tenant, users.created.TenantID)
			}
			require.Equal(t, &tenant, deps.TenantID)
		})
	}
}

func (p *registrationUsers) Get(uuid.UUID) (*models.User, error) { return &p.created, nil }

type registrationAudit struct{ auditlog.Logger }

func (registrationAudit) Create(echo.Context, models.AuditLogType, *models.User, error, ...auditlog.DetailOption) error {
	return nil
}

type registrationEmail struct {
	persistence.EmailPersister
	store *registrationStore
}

func (p registrationEmail) Create(v models.Email) error {
	p.store.tenants["Email"] = v.TenantID
	return nil
}
func (p *registrationStore) GetEmailPersisterWithConnection(*pop.Connection) persistence.EmailPersister {
	return registrationEmail{store: p}
}

type registrationPrimaryEmail struct {
	persistence.PrimaryEmailPersister
	store *registrationStore
}

func (p registrationPrimaryEmail) Create(v models.PrimaryEmail) error { return nil }
func (p *registrationStore) GetPrimaryEmailPersisterWithConnection(*pop.Connection) persistence.PrimaryEmailPersister {
	return registrationPrimaryEmail{store: p}
}

type registrationWebauthnCredential struct {
	persistence.WebauthnCredentialPersister
	store *registrationStore
}

func (p registrationWebauthnCredential) Create(v models.WebauthnCredential) error {
	p.store.tenants["WebauthnCredential"] = v.TenantID
	return nil
}
func (p *registrationStore) GetWebauthnCredentialPersisterWithConnection(*pop.Connection) persistence.WebauthnCredentialPersister {
	return registrationWebauthnCredential{store: p}
}

type registrationPasswordCredential struct {
	persistence.PasswordCredentialPersister
	store *registrationStore
}

func (p registrationPasswordCredential) Create(v models.PasswordCredential) error {
	p.store.tenants["PasswordCredential"] = v.TenantID
	return nil
}
func (p *registrationStore) GetPasswordCredentialPersisterWithConnection(*pop.Connection) persistence.PasswordCredentialPersister {
	return registrationPasswordCredential{store: p}
}

type registrationOTPSecret struct {
	persistence.OTPSecretPersister
	store *registrationStore
}

func (p registrationOTPSecret) Create(v models.OTPSecret) error {
	p.store.tenants["OTPSecret"] = v.TenantID
	return nil
}
func (p *registrationStore) GetOTPSecretPersisterWithConnection(*pop.Connection) persistence.OTPSecretPersister {
	return registrationOTPSecret{store: p}
}

type registrationUsername struct {
	persistence.UsernamePersister
	store *registrationStore
}

func (p registrationUsername) Create(v models.Username) error {
	p.store.tenants["Username"] = v.TenantID
	return nil
}
func (p *registrationStore) GetUsernamePersisterWithConnection(*pop.Connection) persistence.UsernamePersister {
	return registrationUsername{store: p}
}

func (c *registrationContext) GetFlowID() uuid.UUID { return uuid.Nil }
