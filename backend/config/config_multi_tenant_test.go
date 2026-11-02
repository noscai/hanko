package config

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xeipuuv/gojsonschema"
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

// The checked-in schema (json_schema/hanko.config.json, what editors and CI validate configs
// against) must refuse keep_users_global without allow_global_users, as Validate does, and its
// rule must be the one JSONSchemaExtend generates, so a regeneration cannot silently drop it.
func TestMultiTenant_JSONSchemaRequiresGlobalUsersWhenKeepingUsersGlobal(t *testing.T) {
	raw, err := os.ReadFile("../json_schema/hanko.config.json")
	require.NoError(t, err)
	var checkedIn struct {
		Defs map[string]json.RawMessage `json:"$defs"`
	}
	require.NoError(t, json.Unmarshal(raw, &checkedIn))
	multiTenant, ok := checkedIn.Defs["MultiTenant"]
	require.True(t, ok, "the checked-in schema must define MultiTenant")

	schema, err := gojsonschema.NewSchema(gojsonschema.NewBytesLoader(multiTenant))
	require.NoError(t, err)

	for name, tc := range map[string]struct {
		doc   string
		valid bool
	}{
		"keep without global users is refused":           {`{"keep_users_global": true, "allow_global_users": false}`, false},
		"keep with global users is accepted":             {`{"keep_users_global": true, "allow_global_users": true}`, true},
		"no keep without global users is accepted":       {`{"keep_users_global": false, "allow_global_users": false}`, true},
		"keep with the default global users is accepted": {`{"keep_users_global": true}`, true},
	} {
		t.Run(name, func(t *testing.T) {
			result, err := schema.Validate(gojsonschema.NewStringLoader(tc.doc))
			require.NoError(t, err)
			assert.Equal(t, tc.valid, result.Valid(), "%v", result.Errors())
		})
	}

	generated := &jsonschema.Schema{}
	MultiTenant{}.JSONSchemaExtend(generated)
	var checkedInRule struct {
		If   json.RawMessage `json:"if"`
		Then json.RawMessage `json:"then"`
	}
	require.NoError(t, json.Unmarshal(multiTenant, &checkedInRule))
	generatedIf, err := json.Marshal(generated.If)
	require.NoError(t, err)
	generatedThen, err := json.Marshal(generated.Then)
	require.NoError(t, err)
	assert.JSONEq(t, string(generatedIf), string(checkedInRule.If), "the checked-in if must be the generated one")
	assert.JSONEq(t, string(generatedThen), string(checkedInRule.Then), "the checked-in then must be the generated one")
}
