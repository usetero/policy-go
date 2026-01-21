// Package policy implements the Tero Policy Specification for high-performance
// log policy evaluation and transformation.
package policy

import "github.com/usetero/policy-go/internal/engine"

// Re-export types from internal/engine.
type (
	Matcher   = engine.Matcher
	LogPolicy = engine.LogPolicy
	Policy    = engine.Policy
)

// NewPolicy creates a new Policy with the given configuration.
func NewPolicy(id, name string, log *LogPolicy) *Policy {
	return &Policy{
		ID:   id,
		Name: name,
		Log:  log,
	}
}
