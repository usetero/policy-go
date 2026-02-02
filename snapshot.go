package policy

import (
	"iter"

	"github.com/usetero/policy-go/internal/engine"
)

// PolicySnapshot is an immutable, read-only view of compiled policies for a single telemetry type.
// It is safe for concurrent use across multiple goroutines.
// Snapshots are managed by the PolicyRegistry - when policies are reloaded,
// old snapshots remain valid until garbage collected.
type PolicySnapshot[T engine.FieldType] struct {
	matchers *engine.CompiledMatchers[T]
	stats    map[string]*engine.PolicyStats
}

// newPolicySnapshot creates a new snapshot from compiled matchers.
func newPolicySnapshot[T engine.FieldType](matchers *engine.CompiledMatchers[T], stats map[string]*engine.PolicyStats) *PolicySnapshot[T] {
	if matchers == nil {
		return nil
	}
	return &PolicySnapshot[T]{
		matchers: matchers,
		stats:    stats,
	}
}

// CompiledMatchers returns the compiled matchers for this snapshot.
func (s *PolicySnapshot[T]) CompiledMatchers() *engine.CompiledMatchers[T] {
	if s == nil {
		return nil
	}
	return s.matchers
}

// GetStats returns the stats for a policy, or nil if not found.
func (s *PolicySnapshot[T]) GetStats(policyID string) *engine.PolicyStats {
	if s == nil {
		return nil
	}
	return s.stats[policyID]
}

// GetPolicy returns a compiled policy by ID.
func (s *PolicySnapshot[T]) GetPolicy(id string) (*engine.CompiledPolicy[T], bool) {
	if s == nil {
		return nil, false
	}
	return s.matchers.GetPolicy(id)
}

// Iter returns an iterator over all policies in the snapshot.
func (s *PolicySnapshot[T]) Iter() iter.Seq2[string, *engine.CompiledPolicy[T]] {
	return func(yield func(string, *engine.CompiledPolicy[T]) bool) {
		if s == nil || s.matchers == nil {
			return
		}
		for id, p := range s.matchers.Policies() {
			if !yield(id, p) {
				return
			}
		}
	}
}

// Type aliases for convenience
type LogSnapshot = PolicySnapshot[engine.LogField]
type MetricSnapshot = PolicySnapshot[engine.MetricField]
type TraceSnapshot = PolicySnapshot[engine.TraceField]
