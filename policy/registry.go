package policy

import (
	"sync"
	"sync/atomic"

	"github.com/usetero/policy-go/policy/internal/engine"
	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
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
	policies []*policyv1.Policy
}

// PolicyRegistry manages policies from multiple providers.
// It recompiles the regex pattern database when policies change
// and produces read-only snapshots for evaluation.
type PolicyRegistry struct {
	mu             sync.RWMutex
	nextId         atomic.Uint64
	providers      map[ProviderId]*providerEntry
	stats          map[string]*engine.PolicyStats
	compileErrors  map[string][]string
	logSnapshot    *LogSnapshot
	metricSnapshot *MetricSnapshot
	traceSnapshot  *TraceSnapshot
	compiler       *engine.Compiler
	onRecompile    func(error)
}

// NewPolicyRegistry creates a new PolicyRegistry. It has no default regex
// backend: pass WithRegexBackend with the teroscan (pure-Go) or hyperscan (cgo)
// backend. A registry without one errors when it compiles a regex-based policy.
func NewPolicyRegistry(opts ...RegistryOption) *PolicyRegistry {
	var cfg registryConfig
	if testBackend != nil {
		cfg.compilerOpts = append(cfg.compilerOpts, engine.WithBackend(testBackend))
	}
	for _, o := range opts {
		o(&cfg)
	}
	return &PolicyRegistry{
		providers: make(map[ProviderId]*providerEntry),
		stats:     make(map[string]*engine.PolicyStats),
		compiler:  engine.NewCompiler(cfg.compilerOpts...),
	}
}

// Register adds a provider to the registry.
// The provider's policies are loaded immediately and the registry is recompiled.
func (r *PolicyRegistry) Register(provider PolicyProvider) (ProviderHandle, error) {
	id := ProviderId(r.nextId.Add(1))

	// Wire up stats collection
	provider.SetStatsCollector(r.CollectStats)

	// Subscribe to policy updates
	err := provider.Subscribe(func(policies []*policyv1.Policy) {
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
	delete(r.providers, handle.id)
	compileErr := r.recompileLocked()
	onRecompile := r.onRecompile
	r.mu.Unlock()

	if onRecompile != nil {
		onRecompile(compileErr)
	}
}

// Snapshot returns the current read-only snapshot of compiled log policies.
// Deprecated: Use LogSnapshot instead.
func (r *PolicyRegistry) Snapshot() *LogSnapshot {
	return r.LogSnapshot()
}

// LogSnapshot returns the current read-only snapshot of compiled log policies.
// The snapshot is safe for concurrent use and remains valid even after
// new policies are loaded (the registry maintains the old snapshot until
// all references are released via garbage collection).
func (r *PolicyRegistry) LogSnapshot() *LogSnapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.logSnapshot
}

// MetricSnapshot returns the current read-only snapshot of compiled metric policies.
// The snapshot is safe for concurrent use and remains valid even after
// new policies are loaded (the registry maintains the old snapshot until
// all references are released via garbage collection).
func (r *PolicyRegistry) MetricSnapshot() *MetricSnapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.metricSnapshot
}

// TraceSnapshot returns the current read-only snapshot of compiled trace policies.
// The snapshot is safe for concurrent use and remains valid even after
// new policies are loaded (the registry maintains the old snapshot until
// all references are released via garbage collection).
func (r *PolicyRegistry) TraceSnapshot() *TraceSnapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.traceSnapshot
}

// CollectStats atomically reads and resets stats for all policies, returning
// snapshots of the delta since the last call. Compile errors from the most
// recent recompile are attached to each snapshot's Errors field so providers
// can forward them to the policy server. Policies that failed validation but
// have no runtime counters are still reported when they have errors.
// This is the StatsCollector implementation that gets registered with providers.
func (r *PolicyRegistry) CollectStats() []PolicyStatsSnapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()

	seen := make(map[string]bool, len(r.stats))
	snapshots := make([]PolicyStatsSnapshot, 0, len(r.stats))
	for id, stats := range r.stats {
		snapshot := stats.Snapshot(id)
		snapshot.Errors = r.compileErrors[id]
		seen[id] = true
		snapshots = append(snapshots, snapshot)
	}
	// Policies that failed validation never got a PolicyStats entry; emit
	// them so the server learns about the error even with no runtime counters.
	for id, errs := range r.compileErrors {
		if seen[id] {
			continue
		}
		snapshots = append(snapshots, PolicyStatsSnapshot{PolicyID: id, Errors: errs})
	}
	return snapshots
}

// SetOnRecompile sets a callback that is invoked after recompilation.
// The callback receives nil on success or the compilation error on failure.
// The callback is invoked without holding the registry lock, so it is safe
// to call LogSnapshot/MetricSnapshot/TraceSnapshot from within the callback.
func (r *PolicyRegistry) SetOnRecompile(fn func(error)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onRecompile = fn
}

func (r *PolicyRegistry) onProviderUpdate(id ProviderId, policies []*policyv1.Policy) {
	r.mu.Lock()
	r.providers[id] = &providerEntry{
		policies: policies,
	}
	compileErr := r.recompileLocked()
	onRecompile := r.onRecompile
	r.mu.Unlock()

	if onRecompile != nil {
		onRecompile(compileErr)
	}
}

// recompileLocked recompiles the policies and updates the snapshots.
// Returns nil on success or the compilation error.
// INVARIANT: A write lock MUST be held by the caller.
func (r *PolicyRegistry) recompileLocked() error {
	// Collect all enabled policies from all providers
	var allPolicies []*policyv1.Policy
	for _, entry := range r.providers {
		for _, p := range entry.policies {
			if p.GetEnabled() {
				allPolicies = append(allPolicies, p)
			}
		}
	}

	// Update stats map - add new policies, keep existing stats
	for _, p := range allPolicies {
		if _, ok := r.stats[p.GetId()]; !ok {
			r.stats[p.GetId()] = &engine.PolicyStats{}
		}
	}

	// Compile
	result, err := r.compiler.Compile(allPolicies, r.stats)
	if err != nil {
		return err
	}

	r.compileErrors = result.Errors

	// Create new snapshots
	// Note: Old snapshots remain valid - backend resources are cleaned up
	// by Go's garbage collector via finalizers set by the gohs library.
	r.logSnapshot = newPolicySnapshot(result.Logs, r.stats)
	r.metricSnapshot = newPolicySnapshot(result.Metrics, r.stats)
	r.traceSnapshot = newPolicySnapshot(result.Traces, r.stats)

	return nil
}
