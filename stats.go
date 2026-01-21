package policy

import "github.com/usetero/policy-go/internal/engine"

// Re-export types from internal/engine.
type (
	PolicyStats         = engine.PolicyStats
	PolicyStatsSnapshot = engine.PolicyStatsSnapshot
)

// StatsCollector is a function that returns current stats for all policies.
// Registered with providers so they can include stats in sync requests.
type StatsCollector func() []PolicyStatsSnapshot
