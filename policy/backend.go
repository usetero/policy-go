package policy

import (
	"github.com/usetero/policy-go/policy/internal/engine"
	"github.com/usetero/policy-go/policy/regexbackend"
)

// RegexBackend is the pluggable regex engine used to compile and scan policy
// patterns. The core module ships no implementation: choose one and pass it via
// WithRegexBackend — the pure-Go github.com/usetero/policy-go/backend/teroscan
// (no cgo) or the faster github.com/usetero/policy-go/backend/hyperscan (cgo).
type RegexBackend = regexbackend.Backend

// RegexMatcher is a compiled group of patterns produced by a RegexBackend.
type RegexMatcher = regexbackend.Matcher

// RegistryOption configures a PolicyRegistry.
type RegistryOption func(*registryConfig)

type registryConfig struct {
	compilerOpts []engine.CompilerOption
}

// WithRegexBackend sets the regex backend used to compile policy patterns. There
// is no default backend, so this is required for any registry that compiles
// regex-based policies.
func WithRegexBackend(b RegexBackend) RegistryOption {
	return func(c *registryConfig) {
		c.compilerOpts = append(c.compilerOpts, engine.WithBackend(b))
	}
}

// testBackend, when non-nil, is prepended as the backend for NewPolicyRegistry.
// It exists only so this package's own tests can run without importing a backend
// module (which would be an import cycle); it is always nil in production and is
// set by a _test.go init. A WithRegexBackend option still overrides it.
var testBackend RegexBackend
