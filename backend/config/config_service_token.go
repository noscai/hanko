package config

type ServiceToken struct {
	Secret string `yaml:"secret" json:"secret,omitempty" koanf:"secret" split_words:"true"`
	Issuer string `yaml:"issuer" json:"issuer,omitempty" koanf:"issuer" split_words:"true"`
}
