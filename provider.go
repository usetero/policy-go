package policy

// PolicyCallback is called when policies are updated by a provider.
type PolicyCallback func(policies []*Policy)

// PolicyProvider is the interface for policy sources.
// Providers load policies and notify the registry of changes.
type PolicyProvider interface {
	// Load performs an immediate load and returns the current policies.
	Load() ([]*Policy, error)

	// Subscribe registers a callback for policy changes.
	// The callback is invoked immediately with current policies,
	// and again whenever policies change.
	Subscribe(callback PolicyCallback) error

	// SetStatsCollector registers a function to collect stats for reporting.
	// Providers can use this to include stats in sync requests to backends.
	SetStatsCollector(collector StatsCollector)
}
