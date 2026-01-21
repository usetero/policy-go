package policy

import (
	"iter"

	"github.com/usetero/policy-go/internal/engine"
)

// PolicySnapshot is an immutable, read-only view of compiled policies.
// It is safe for concurrent use across multiple goroutines.
// Snapshots are managed by the PolicyRegistry - when policies are reloaded,
// old snapshots remain valid until garbage collected.
type PolicySnapshot struct {
	matchers *engine.CompiledMatchers
	stats    map[string]*engine.PolicyStats
}

// newPolicySnapshot creates a new snapshot from compiled matchers.
func newPolicySnapshot(matchers *engine.CompiledMatchers, stats map[string]*engine.PolicyStats) *PolicySnapshot {
	return &PolicySnapshot{
		matchers: matchers,
		stats:    stats,
	}
}

// CompiledMatchers returns the compiled matchers for this snapshot.
func (s *PolicySnapshot) CompiledMatchers() *engine.CompiledMatchers {
	return s.matchers
}

// GetStats returns the stats for a policy, or nil if not found.
func (s *PolicySnapshot) GetStats(policyID string) *engine.PolicyStats {
	return s.stats[policyID]
}

// GetPolicy returns a compiled policy by ID.
func (s *PolicySnapshot) GetPolicy(id string) (*engine.CompiledPolicy, bool) {
	return s.matchers.GetPolicy(id)
}

// Iter returns an iterator over all policies in the snapshot.
func (s *PolicySnapshot) Iter() iter.Seq2[string, *engine.CompiledPolicy] {
	return func(yield func(string, *engine.CompiledPolicy) bool) {
		for id, p := range s.matchers.Policies() {
			if !yield(id, p) {
				return
			}
		}
	}
}
