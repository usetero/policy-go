package policy

import (
	"iter"
	"sync/atomic"

	"github.com/usetero/policy-go/internal/engine"
)

// PolicySnapshot is an immutable, read-only view of compiled policies.
// It is safe for concurrent use across multiple goroutines.
type PolicySnapshot struct {
	matchers *engine.CompiledMatchers
	stats    map[string]*PolicyStats
	refCount atomic.Int64
}

// newPolicySnapshot creates a new snapshot from compiled matchers.
func newPolicySnapshot(matchers *engine.CompiledMatchers, stats map[string]*PolicyStats) *PolicySnapshot {
	s := &PolicySnapshot{
		matchers: matchers,
		stats:    stats,
	}
	s.refCount.Store(1)
	return s
}

// CompiledMatchers returns the compiled matchers for this snapshot.
func (s *PolicySnapshot) CompiledMatchers() *engine.CompiledMatchers {
	return s.matchers
}

// GetStats returns the stats for a policy, or nil if not found.
func (s *PolicySnapshot) GetStats(policyID string) *PolicyStats {
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

// Retain increments the reference count.
// Call this when you want to keep the snapshot alive.
func (s *PolicySnapshot) Retain() {
	s.refCount.Add(1)
}

// Release decrements the reference count.
// When the count reaches zero, resources may be freed.
func (s *PolicySnapshot) Release() {
	if s.refCount.Add(-1) == 0 {
		// Last reference released, clean up
		if s.matchers != nil {
			s.matchers.Close()
		}
	}
}
