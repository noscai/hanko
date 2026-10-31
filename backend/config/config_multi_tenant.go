package config

import "errors"

// MultiTenant configures multi-tenant mode for Hanko
type MultiTenant struct {
	// Enabled enables multi-tenant mode. When disabled (default), Hanko operates in single-tenant mode
	// with global email/username uniqueness.
	Enabled bool `yaml:"enabled" json:"enabled,omitempty" koanf:"enabled" jsonschema:"default=false"`

	// TenantHeader is the HTTP header name used to identify the tenant.
	// The value must be a valid UUID.
	TenantHeader string `yaml:"tenant_header" json:"tenant_header,omitempty" koanf:"tenant_header" split_words:"true" jsonschema:"default=X-Tenant-ID"`

	// AllowGlobalUsers allows users without a tenant_id (backward compatibility).
	// When true, requests without the tenant header will create/access global users.
	// When false, the tenant header is required for all requests.
	AllowGlobalUsers bool `yaml:"allow_global_users" json:"allow_global_users,omitempty" koanf:"allow_global_users" split_words:"true" jsonschema:"default=true"`

	// AutoProvision enables automatic tenant creation when a request includes a tenant ID
	// that doesn't exist yet. The tenant is created with default values.
	// When false, requests with unknown tenant IDs will return a 404 error.
	AutoProvision bool `yaml:"auto_provision" json:"auto_provision,omitempty" koanf:"auto_provision" split_words:"true" jsonschema:"default=true"`

	// KeepUsersGlobal keeps a global user global on login instead of adopting them
	// to the first tenant they authenticate against. When true, a user found via the
	// global fallback (tenant_id IS NULL) is NOT bound to the login tenant, so the same
	// identity can authenticate against every tenant it is a member of — the prerequisite
	// for the ClinicOS in-app organisation switcher (archon#1085 task 16). Which clinics a person
	// belongs to is then decided by ClinicOS (its user rows that share this Hanko user), not by
	// Hanko's single user.tenant_id. This covers the pre-authenticated path too.
	// It only stops the adoption of users who are already global: registration under a tenant
	// header still creates a tenant-bound user, and users adopted before it was turned on stay
	// adopted. Requires allow_global_users to be true. Environment variable:
	// MULTI_TENANT_KEEP_USERS_GLOBAL.
	// Do not enable it on a cluster before archon#1085 task 17 runs on that cluster's Hanko: until
	// then a kept-global user's session JWT carries no tenant_id.
	// When false (default), the historical single-tenant adoption behaviour is preserved.
	KeepUsersGlobal bool `yaml:"keep_users_global" json:"keep_users_global,omitempty" koanf:"keep_users_global" split_words:"true" jsonschema:"default=false"`
}

func DefaultMultiTenantConfig() MultiTenant {
	return MultiTenant{
		Enabled:          false,
		TenantHeader:     "X-Tenant-ID",
		AllowGlobalUsers: true,
		AutoProvision:    true,
		KeepUsersGlobal:  false,
	}
}

// Validate refuses keep_users_global without allow_global_users. A user kept global has no
// tenant, and the pre-authenticated step-up refuses tenant-less users when global users are
// disabled, so the pair would let a login succeed and then fail every step-up for that user.
func (m *MultiTenant) Validate() error {
	if m.KeepUsersGlobal && !m.AllowGlobalUsers {
		return errors.New("keep_users_global requires allow_global_users to be true: users kept global have no tenant, and allow_global_users=false refuses tenant-less users")
	}
	return nil
}
