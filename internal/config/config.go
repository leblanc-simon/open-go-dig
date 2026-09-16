package config

import (
	"leblanc.io/open-go-base/appconf"
)

// Config holds the application configuration loaded from a YAML file or
// environment variables (prefix OGD_, "Open Go Dig"). The cross-cutting
// concerns are described by the shared appconf fragments; only DNS is
// specific to this app.
type Config struct {
	Web  appconf.Web     `yaml:"web"     env-prefix:"OGD_"`
	CORS appconf.CORS    `yaml:"cors"    env-prefix:"OGD_"`
	Log  appconf.Logging `yaml:"logging" env-prefix:"OGD_"`
	DNS  DNS             `yaml:"dns"     env-prefix:"OGD_"`
}

// DNS describes the resolvers used for lookups. Env vars are declared without
// the project prefix; it is applied at the composition point above via
// env-prefix (cleanenv only supports a static prefix).
type DNS struct {
	// Resolvers accepts "host:port" or "Name=host:port"; the name is only ever
	// shown in the resolver picker ("Name - host:port") and is never accepted
	// as input, so the SSRF allowlist keeps matching on the address alone.
	Resolvers []string `yaml:"resolvers" env:"DNS_RESOLVERS" env-separator:"," env-description:"Upstream DNS resolvers ([Name=]host:port), comma-separated"`
	Timeout   int      `yaml:"timeout"   env:"DNS_TIMEOUT"   env-default:"5" env-description:"Per-resolver query timeout in seconds"`
	// MaxParallel bounds the record-type queries a single lookup sends at
	// once. ?type= accepts the whole catalogue, so an unbounded fan-out would
	// turn one HTTP request into 44 simultaneous packets per resolver.
	MaxParallel int `yaml:"max_parallel" env:"DNS_MAX_PARALLEL" env-default:"8" env-description:"Maximum record-type queries sent in parallel per lookup"`
}

// IsDebug reports whether the configured log level enables debug output. It is
// used to toggle verbose logging in components that predate slog (e.g. the DNS
// client).
func (c *Config) IsDebug() bool {
	return c.Log.Level == "debug"
}
