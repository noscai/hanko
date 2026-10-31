package config

import (
	"testing"

	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// keep_users_global leaves users global; allow_global_users=false refuses global users on the
// pre-authenticated step-up. Together, login succeeds and the PIN step-up then fails.
func TestMultiTenantConfig_RefusesKeepUsersGlobalWithoutGlobalUsers(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MultiTenant.Enabled = true
	cfg.MultiTenant.KeepUsersGlobal = true
	cfg.MultiTenant.AllowGlobalUsers = false

	err := cfg.Validate()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "keep_users_global requires allow_global_users")
}

func TestMultiTenantConfig_AcceptsKeepUsersGlobalWithGlobalUsers(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MultiTenant.Enabled = true
	cfg.MultiTenant.KeepUsersGlobal = true
	cfg.MultiTenant.AllowGlobalUsers = true

	require.NoError(t, cfg.Validate())
}

func TestLoad_RefusesKeepUsersGlobalWithoutGlobalUsers(t *testing.T) {
	t.Setenv("MULTI_TENANT_ENABLED", "true")
	t.Setenv("MULTI_TENANT_KEEP_USERS_GLOBAL", "true")
	t.Setenv("MULTI_TENANT_ALLOW_GLOBAL_USERS", "false")

	configPath := "./minimal-config.yaml"
	_, err := Load(&configPath)

	require.Error(t, err, "the contradictory pair must be refused at config load")
	assert.Contains(t, err.Error(), "keep_users_global requires allow_global_users")
}

func TestDefaultConfigKeepUsersGlobal(t *testing.T) {
	cfg := DefaultConfig()
	assert.False(t, cfg.MultiTenant.KeepUsersGlobal, "adoption stays on unless a deployment opts out")
}

func TestParseKeepUsersGlobalConfig(t *testing.T) {
	configPath := "./multi-tenant-keep-users-global-config.yaml"
	cfg, err := Load(&configPath)
	require.NoError(t, err)

	assert.True(t, cfg.MultiTenant.KeepUsersGlobal)
}

func TestKeepUsersGlobalFromEnvironment(t *testing.T) {
	t.Setenv("MULTI_TENANT_KEEP_USERS_GLOBAL", "true")

	configPath := "./minimal-config.yaml"
	cfg, err := Load(&configPath)
	require.NoError(t, err)

	assert.True(t, cfg.MultiTenant.KeepUsersGlobal)
}

func TestMultiTenant_JSONSchemaRequiresGlobalUsersWhenKeepingUsersGlobal(t *testing.T) {
	schema := &jsonschema.Schema{}

	MultiTenant{}.JSONSchemaExtend(schema)

	require.NotNil(t, schema.If)
	require.NotNil(t, schema.Then)
	assert.Equal(t, []string{"keep_users_global"}, schema.If.Required)
	keep, ok := schema.If.Properties.Get("keep_users_global")
	require.True(t, ok)
	assert.Equal(t, true, keep.Const)
	allow, ok := schema.Then.Properties.Get("allow_global_users")
	require.True(t, ok)
	assert.Equal(t, true, allow.Const)
}
