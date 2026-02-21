package config

// ServiceToken configures service token validation for pre-authenticated login flows.
// When configured with a secret, trusted backend services can generate HMAC-signed JWTs
// to bypass the normal login flow (password/passkey/OTP) and establish sessions directly.
// If the secret is empty, the preauthenticated_continue action is automatically suspended.
type ServiceToken struct {
	// Secret is the shared HMAC secret used to sign and validate service tokens.
	// Must be at least 32 characters for adequate security. Both Hanko and the
	// trusted backend must use the same secret. If empty, service token
	// authentication is disabled.
	Secret string `yaml:"secret" json:"secret,omitempty" koanf:"secret" split_words:"true" jsonschema:"default="`

	// Issuer is the expected JWT issuer claim. If set, service tokens must include
	// a matching "iss" claim. If empty, issuer validation is skipped.
	Issuer string `yaml:"issuer" json:"issuer,omitempty" koanf:"issuer" split_words:"true" jsonschema:"default="`
}

// DefaultServiceTokenConfig returns the default ServiceToken configuration.
// Both fields are empty by default, meaning the feature is disabled.
func DefaultServiceTokenConfig() ServiceToken {
	return ServiceToken{
		Secret: "",
		Issuer: "",
	}
}
