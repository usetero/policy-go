package policy

import (
	"sync"

	"github.com/usetero/policy-go/internal/engine"
)

// EvaluateResult represents the result of policy evaluation.
type EvaluateResult int

const (
	// ResultNoMatch indicates no policy matched the telemetry.
	ResultNoMatch EvaluateResult = iota
	// ResultKeep indicates the telemetry should be kept.
	ResultKeep
	// ResultKeepWithTransform indicates the telemetry should be kept and transformed.
	ResultKeepWithTransform
	// ResultDrop indicates the telemetry should be dropped.
	ResultDrop
	// ResultSample indicates the telemetry was sampled (kept or dropped based on percentage).
	ResultSample
	// ResultRateLimit indicates the telemetry was rate limited.
	ResultRateLimit
)

func (r EvaluateResult) String() string {
	switch r {
	case ResultNoMatch:
		return "no_match"
	case ResultKeep:
		return "keep"
	case ResultKeepWithTransform:
		return "keep_with_transform"
	case ResultDrop:
		return "drop"
	case ResultSample:
		return "sample"
	case ResultRateLimit:
		return "rate_limit"
	default:
		return "unknown"
	}
}

// PolicyEngine evaluates telemetry against compiled policies.
type PolicyEngine struct {
	scratchPool sync.Pool
}

// NewPolicyEngine creates a new PolicyEngine.
func NewPolicyEngine() *PolicyEngine {
	return &PolicyEngine{}
}

// Evaluate checks a log record against the snapshot and returns the result.
// This method is designed for zero allocations in the hot path.
func (e *PolicyEngine) Evaluate(snapshot *PolicySnapshot, record Matchable) EvaluateResult {
	if snapshot == nil || snapshot.matchers == nil {
		return ResultNoMatch
	}

	matchers := snapshot.matchers

	// Track which policies have all matchers satisfied
	// Using a map here, but could optimize with a bitset for zero-alloc
	matchCounts := make(map[string]int)
	disqualified := make(map[string]bool)

	// Process existence checks first
	for _, check := range matchers.ExistenceChecks() {
		value := record.GetField(check.Selector)
		exists := value != nil || len(value) > 0

		if check.MustExist && !exists {
			disqualified[check.PolicyID] = true
		} else if !check.MustExist && exists {
			disqualified[check.PolicyID] = true
		} else {
			matchCounts[check.PolicyID]++
		}
	}

	// Process Hyperscan databases
	for key, db := range matchers.Databases() {
		value := record.GetField(key.Selector)
		if len(value) == 0 {
			// No value to match - policies requiring this field are disqualified
			// unless this is a negated match (which would succeed on absence)
			if !key.Negated {
				// Mark all policies using this database as disqualified
				for _, ref := range db.PatternIndex() {
					disqualified[ref.PolicyID] = true
				}
			}
			continue
		}

		// Scan the value using the database
		matched, err := db.Scan(value)
		if err != nil {
			continue
		}

		// Update match counts based on results
		for patternID, ref := range db.PatternIndex() {
			if disqualified[ref.PolicyID] {
				continue
			}

			if key.Negated {
				// Negated match - pattern should NOT match
				if matched[patternID] {
					disqualified[ref.PolicyID] = true
				} else {
					matchCounts[ref.PolicyID]++
				}
			} else {
				// Normal match - pattern should match
				if matched[patternID] {
					matchCounts[ref.PolicyID]++
				}
			}
		}
	}

	// Find the most restrictive matching policy
	var bestPolicy *engine.CompiledPolicy
	bestRestrictiveness := -1

	for policyID, count := range matchCounts {
		if disqualified[policyID] {
			continue
		}

		policy, ok := matchers.GetPolicy(policyID)
		if !ok {
			continue
		}

		// Check if all matchers are satisfied
		if count < policy.MatcherCount {
			continue
		}

		// Record hit
		if policy.Stats != nil {
			policy.Stats.RecordHit()
		}

		// Select most restrictive
		restrictiveness := policy.Keep.Restrictiveness()
		if restrictiveness > bestRestrictiveness {
			bestPolicy = policy
			bestRestrictiveness = restrictiveness
		}
	}

	if bestPolicy == nil {
		return ResultNoMatch
	}

	// Apply the keep action
	return e.applyKeepAction(bestPolicy)
}

func (e *PolicyEngine) applyKeepAction(policy *engine.CompiledPolicy) EvaluateResult {
	switch policy.Keep.Action {
	case KeepAll:
		return ResultKeep

	case KeepNone:
		if policy.Stats != nil {
			policy.Stats.RecordDrop()
		}
		return ResultDrop

	case KeepSample:
		// TODO: Implement proper sampling with hash-based determinism
		// For now, just use the percentage as a simple probability
		if policy.Stats != nil {
			policy.Stats.RecordSample()
		}
		return ResultSample

	case KeepRatePerSecond, KeepRatePerMinute:
		// TODO: Implement rate limiting
		if policy.Stats != nil {
			policy.Stats.RecordRateLimited()
		}
		return ResultRateLimit

	default:
		return ResultKeep
	}
}
