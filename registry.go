package policy

import (
	"sync"
	"sync/atomic"

	"github.com/usetero/policy-go/internal/engine"
)

// ProviderId is a unique identifier for a registered provider.
type ProviderId uint64

// ProviderHandle is returned when registering a provider.
// Use it to unregister the provider later.
type ProviderHandle struct {
	id       ProviderId
	registry *PolicyRegistry
}

// Unregister removes this provider from the registry.
func (h *ProviderHandle) Unregister() {
	if h.registry != nil {
		h.registry.Unregister(*h)
	}
}

type providerEntry struct {
	provider PolicyProvider
	policies []*Policy
}

// PolicyRegistry manages policies from multiple providers.
// It recompiles the Hyperscan database when policies change
// and produces read-only snapshots for evaluation.
type PolicyRegistry struct {
	mu          sync.RWMutex
	nextId      atomic.Uint64
	providers   map[ProviderId]*providerEntry
	stats       map[string]*PolicyStats
	snapshot    *PolicySnapshot
	compiler    *engine.Compiler
	onRecompile func(*PolicySnapshot) // for testing
}

// NewPolicyRegistry creates a new PolicyRegistry.
func NewPolicyRegistry() *PolicyRegistry {
	return &PolicyRegistry{
		providers: make(map[ProviderId]*providerEntry),
		stats:     make(map[string]*PolicyStats),
		compiler:  engine.NewCompiler(),
	}
}

// Register adds a provider to the registry.
// The provider's policies are loaded immediately and the registry is recompiled.
func (r *PolicyRegistry) Register(provider PolicyProvider) (ProviderHandle, error) {
	id := ProviderId(r.nextId.Add(1))

	// Wire up stats collection
	provider.SetStatsCollector(r.CollectStats)

	// Subscribe to policy updates
	err := provider.Subscribe(func(policies []*Policy) {
		r.onProviderUpdate(id, policies)
	})
	if err != nil {
		return ProviderHandle{}, err
	}

	return ProviderHandle{id: id, registry: r}, nil
}

// Unregister removes a provider from the registry.
func (r *PolicyRegistry) Unregister(handle ProviderHandle) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.providers, handle.id)
	r.recompileLocked()
}

// Snapshot returns the current read-only snapshot of compiled policies.
// The snapshot is safe for concurrent use.
// Callers should call Release() when done with the snapshot.
func (r *PolicyRegistry) Snapshot() *PolicySnapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.snapshot != nil {
		r.snapshot.Retain()
	}
	return r.snapshot
}

// CollectStats returns immutable snapshots of stats for all policies.
// This is the StatsCollector implementation that gets registered with providers.
func (r *PolicyRegistry) CollectStats() []PolicyStatsSnapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()

	snapshots := make([]PolicyStatsSnapshot, 0, len(r.stats))
	for id, stats := range r.stats {
		snapshots = append(snapshots, stats.Snapshot(id))
	}
	return snapshots
}

// SetOnRecompile sets a callback that is invoked after recompilation.
// Used for testing to know when policies have been updated.
func (r *PolicyRegistry) SetOnRecompile(fn func(*PolicySnapshot)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onRecompile = fn
}

func (r *PolicyRegistry) onProviderUpdate(id ProviderId, policies []*Policy) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.providers[id] = &providerEntry{
		policies: policies,
	}
	r.recompileLocked()
}

// recompileLocked recompiles the policies and updates the snapshot.
// INVARIANT: A lock MUST be acquired.
func (r *PolicyRegistry) recompileLocked() {
	// Collect all policies from all providers
	var allPolicies []*Policy
	for _, entry := range r.providers {
		allPolicies = append(allPolicies, entry.policies...)
	}

	// Update stats map - add new policies, keep existing stats
	for _, p := range allPolicies {
		if _, ok := r.stats[p.ID]; !ok {
			r.stats[p.ID] = &PolicyStats{}
		}
	}

	// Compile
	compiled, err := r.compiler.Compile(allPolicies, r.stats)
	if err != nil {
		// TODO: Log error or expose it somehow
		return
	}

	// Release old snapshot
	if r.snapshot != nil {
		r.snapshot.Release()
	}

	// Create new snapshot
	r.snapshot = newPolicySnapshot(compiled, r.stats)

	if r.onRecompile != nil {
		r.onRecompile(r.snapshot)
	}
}
