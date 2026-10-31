package config

import (
	"testing"

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
