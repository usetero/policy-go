package policy

import (
	"hash/fnv"
	"sync"

	"github.com/usetero/policy-go/internal/engine"
)

// evalState holds reusable slices for policy evaluation to avoid allocations.
type evalState struct {
	matchCounts    []int
	disqualified   []bool
	matchedIndices []int
	matchedCount   int
}

var evalStatePool = sync.Pool{
	New: func() any {
		return &evalState{}
	},
}

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
	registry *PolicyRegistry
}

// NewPolicyEngine creates a new PolicyEngine with the given registry.
func NewPolicyEngine(registry *PolicyRegistry) *PolicyEngine {
	return &PolicyEngine{registry: registry}
}

// ============================================================================
// LOG EVALUATION
// ============================================================================

// EvaluateLog checks a log record against the current policies and returns the result.
// This method uses index-based arrays instead of maps for better performance.
//
// The match function is called to extract field values from the record.
// Optional behaviors can be provided via LogOption functions (e.g., WithLogTransform).
func EvaluateLog[T any](e *PolicyEngine, record T, match LogMatchFunc[T], opts ...LogOption[T]) EvaluateResult {
	var options logOptions[T]
	for _, opt := range opts {
		opt(&options)
	}

	snapshot := e.registry.LogSnapshot()
	if snapshot == nil || snapshot.matchers == nil {
		return ResultNoMatch
	}

	matchers := snapshot.matchers
	policyCount := matchers.PolicyCount()
	if policyCount == 0 {
		return ResultNoMatch
	}

	// Get evaluation state from pool
	state := evalStatePool.Get().(*evalState)
	defer evalStatePool.Put(state)

	// Ensure slices are sized correctly and cleared
	if cap(state.matchCounts) < policyCount {
		state.matchCounts = make([]int, policyCount)
		state.disqualified = make([]bool, policyCount)
		state.matchedIndices = make([]int, policyCount)
	} else {
		state.matchCounts = state.matchCounts[:policyCount]
		state.disqualified = state.disqualified[:policyCount]
		state.matchedIndices = state.matchedIndices[:policyCount]
		for i := range state.matchCounts {
			state.matchCounts[i] = 0
			state.disqualified[i] = false
		}
	}
	state.matchedCount = 0

	matchCounts := state.matchCounts
	disqualified := state.disqualified

	// Process existence checks first
	for _, check := range matchers.ExistenceChecks() {
		if disqualified[check.PolicyIndex] {
			continue
		}

		value := match(record, check.Ref)
		exists := value != nil || len(value) > 0

		if check.MustExist && !exists {
			disqualified[check.PolicyIndex] = true
		} else if !check.MustExist && exists {
			disqualified[check.PolicyIndex] = true
		} else {
			matchCounts[check.PolicyIndex]++
		}
	}

	// Process Hyperscan databases
	for _, entry := range matchers.Databases() {
		key := entry.Key
		db := entry.Database

		value := match(record, key.Ref)
		if len(value) == 0 {
			// No value to match - policies requiring this field are disqualified
			// unless this is a negated match (which would succeed on absence)
			if !key.Negated {
				// Mark all policies using this database as disqualified
				for _, patternRef := range db.PatternIndex() {
					disqualified[patternRef.PolicyIndex] = true
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
		for patternID, patternRef := range db.PatternIndex() {
			if disqualified[patternRef.PolicyIndex] {
				continue
			}

			if key.Negated {
				// Negated match - pattern should NOT match
				if matched[patternID] {
					disqualified[patternRef.PolicyIndex] = true
				} else {
					matchCounts[patternRef.PolicyIndex]++
				}
			} else {
				// Normal match - pattern should match
				if matched[patternID] {
					matchCounts[patternRef.PolicyIndex]++
				}
			}
		}

		// Return matched slice to pool
		db.ReleaseMatched(matched)
	}

	// Find all matching policies and track the most restrictive one
	var bestPolicy *engine.CompiledPolicy[engine.LogField]
	bestRestrictiveness := -1

	for i := range policyCount {
		if disqualified[i] {
			continue
		}

		policy := matchers.PolicyByIndex(i)

		// Check if all matchers are satisfied
		if matchCounts[i] < policy.MatcherCount {
			continue
		}

		// Record hit
		if policy.Stats != nil {
			policy.Stats.RecordHit()
		}

		state.matchedIndices[state.matchedCount] = i
		state.matchedCount++

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

	// Apply the keep action, with transforms from all matched policies
	return applyKeepActionLog(e, bestPolicy, matchers, state.matchedIndices[:state.matchedCount], record, match, &options)
}

func applyKeepActionLog[T any](e *PolicyEngine, policy *engine.CompiledPolicy[engine.LogField], matchers *engine.CompiledMatchers[engine.LogField], matchedIndices []int, record T, match LogMatchFunc[T], options *logOptions[T]) EvaluateResult {
	switch policy.Keep.Action {
	case KeepNone:
		if policy.Stats != nil {
			policy.Stats.RecordDrop()
		}
		return ResultDrop

	case KeepSample:
		shouldKeep := shouldSampleLog(e, policy, record, match)
		if policy.Stats != nil {
			policy.Stats.RecordSample()
		}
		if !shouldKeep {
			return ResultDrop
		}

	case KeepRatePerSecond, KeepRatePerMinute:
		if policy.RateLimiter != nil && !policy.RateLimiter.ShouldKeep() {
			if policy.Stats != nil {
				policy.Stats.RecordRateLimited()
			}
			return ResultDrop
		}
	}

	// Apply transforms from all matching policies
	hasTransforms := false
	for _, idx := range matchedIndices {
		p := matchers.PolicyByIndex(idx)
		if len(p.Transforms) == 0 {
			continue
		}
		hasTransforms = true
		if options.transform != nil {
			for _, op := range p.Transforms {
				hit := options.transform(record, op)
				if p.Stats != nil {
					if hit {
						p.Stats.RecordTransformHit(op.Kind)
					} else {
						p.Stats.RecordTransformMiss(op.Kind)
					}
				}
			}
		}
	}

	if hasTransforms {
		return ResultKeepWithTransform
	}
	return ResultKeep
}

// shouldSampleLog determines if a record should be kept based on the sampling configuration.
// If a sample key is configured, it uses hash-based deterministic sampling for consistency.
// Otherwise, it uses the hash of the entire record for pseudo-random sampling.
func shouldSampleLog[T any](e *PolicyEngine, policy *engine.CompiledPolicy[engine.LogField], record T, match LogMatchFunc[T]) bool {
	percentage := policy.Keep.Value
	if percentage >= 100 {
		return true
	}
	if percentage <= 0 {
		return false
	}

	// Get the value to hash for sampling
	var hashInput []byte
	if policy.SampleKey != nil {
		// Use the configured sample key field
		hashInput = match(record, *policy.SampleKey)
	}

	// If no sample key or the field is empty, we can't do consistent sampling
	// Fall back to not sampling (treat as keep all for this record)
	if len(hashInput) == 0 {
		return true
	}

	// Hash the value and determine if it falls within the sample percentage
	h := fnv.New64a()
	h.Write(hashInput)
	hashValue := h.Sum64()

	// Map the hash to a percentage (0-100)
	// Use modulo to get a value in range [0, 10000) for 0.01% precision
	hashPercentage := float64(hashValue%10000) / 100.0

	return hashPercentage < percentage
}

// ============================================================================
// METRIC EVALUATION
// ============================================================================

// EvaluateMetric checks a metric against the current policies and returns the result.
// This method uses index-based arrays instead of maps for better performance.
//
// The match function is called to extract field values from the metric.
// Consumers provide this function to bridge their metric type to the policy engine.
func EvaluateMetric[T any](e *PolicyEngine, metric T, match MetricMatchFunc[T]) EvaluateResult {
	snapshot := e.registry.MetricSnapshot()
	if snapshot == nil || snapshot.matchers == nil {
		return ResultNoMatch
	}

	matchers := snapshot.matchers
	policyCount := matchers.PolicyCount()
	if policyCount == 0 {
		return ResultNoMatch
	}

	// Get evaluation state from pool
	state := evalStatePool.Get().(*evalState)
	defer evalStatePool.Put(state)

	// Ensure slices are sized correctly and cleared
	if cap(state.matchCounts) < policyCount {
		state.matchCounts = make([]int, policyCount)
		state.disqualified = make([]bool, policyCount)
	} else {
		state.matchCounts = state.matchCounts[:policyCount]
		state.disqualified = state.disqualified[:policyCount]
		for i := range state.matchCounts {
			state.matchCounts[i] = 0
			state.disqualified[i] = false
		}
	}

	matchCounts := state.matchCounts
	disqualified := state.disqualified

	// Process existence checks first
	for _, check := range matchers.ExistenceChecks() {
		if disqualified[check.PolicyIndex] {
			continue
		}

		value := match(metric, check.Ref)
		exists := value != nil || len(value) > 0

		if check.MustExist && !exists {
			disqualified[check.PolicyIndex] = true
		} else if !check.MustExist && exists {
			disqualified[check.PolicyIndex] = true
		} else {
			matchCounts[check.PolicyIndex]++
		}
	}

	// Process Hyperscan databases
	for _, entry := range matchers.Databases() {
		key := entry.Key
		db := entry.Database

		value := match(metric, key.Ref)
		if len(value) == 0 {
			if !key.Negated {
				for _, patternRef := range db.PatternIndex() {
					disqualified[patternRef.PolicyIndex] = true
				}
			}
			continue
		}

		matched, err := db.Scan(value)
		if err != nil {
			continue
		}

		for patternID, patternRef := range db.PatternIndex() {
			if disqualified[patternRef.PolicyIndex] {
				continue
			}

			if key.Negated {
				if matched[patternID] {
					disqualified[patternRef.PolicyIndex] = true
				} else {
					matchCounts[patternRef.PolicyIndex]++
				}
			} else {
				if matched[patternID] {
					matchCounts[patternRef.PolicyIndex]++
				}
			}
		}

		db.ReleaseMatched(matched)
	}

	// Find the most restrictive matching policy
	var bestPolicy *engine.CompiledPolicy[engine.MetricField]
	bestRestrictiveness := -1

	for i := range policyCount {
		if disqualified[i] {
			continue
		}

		policy := matchers.PolicyByIndex(i)

		if matchCounts[i] < policy.MatcherCount {
			continue
		}

		if policy.Stats != nil {
			policy.Stats.RecordHit()
		}

		restrictiveness := policy.Keep.Restrictiveness()
		if restrictiveness > bestRestrictiveness {
			bestPolicy = policy
			bestRestrictiveness = restrictiveness
		}
	}

	if bestPolicy == nil {
		return ResultNoMatch
	}

	return applyKeepActionMetric(bestPolicy)
}

func applyKeepActionMetric(policy *engine.CompiledPolicy[engine.MetricField]) EvaluateResult {
	switch policy.Keep.Action {
	case KeepAll:
		return ResultKeep

	case KeepNone:
		if policy.Stats != nil {
			policy.Stats.RecordDrop()
		}
		return ResultDrop

	case KeepSample:
		// Metrics don't support sample keys, so we just use the percentage directly
		// For deterministic sampling, the caller should implement their own logic
		if policy.Stats != nil {
			policy.Stats.RecordSample()
		}
		return ResultSample

	case KeepRatePerSecond, KeepRatePerMinute:
		if policy.RateLimiter == nil {
			return ResultKeep
		}
		if policy.RateLimiter.ShouldKeep() {
			return ResultKeep
		}
		if policy.Stats != nil {
			policy.Stats.RecordRateLimited()
		}
		return ResultDrop

	default:
		return ResultKeep
	}
}

// ============================================================================
// TRACE EVALUATION
// ============================================================================

// EvaluateTrace checks a span against the current policies and returns the result.
// This method uses index-based arrays instead of maps for better performance.
//
// The match function is called to extract field values from the span.
// Consumers provide this function to bridge their span type to the policy engine.
func EvaluateTrace[T any](e *PolicyEngine, span T, match TraceMatchFunc[T]) EvaluateResult {
	snapshot := e.registry.TraceSnapshot()
	if snapshot == nil || snapshot.matchers == nil {
		return ResultNoMatch
	}

	matchers := snapshot.matchers
	policyCount := matchers.PolicyCount()
	if policyCount == 0 {
		return ResultNoMatch
	}

	// Get evaluation state from pool
	state := evalStatePool.Get().(*evalState)
	defer evalStatePool.Put(state)

	// Ensure slices are sized correctly and cleared
	if cap(state.matchCounts) < policyCount {
		state.matchCounts = make([]int, policyCount)
		state.disqualified = make([]bool, policyCount)
	} else {
		state.matchCounts = state.matchCounts[:policyCount]
		state.disqualified = state.disqualified[:policyCount]
		for i := range state.matchCounts {
			state.matchCounts[i] = 0
			state.disqualified[i] = false
		}
	}

	matchCounts := state.matchCounts
	disqualified := state.disqualified

	// Process existence checks first
	for _, check := range matchers.ExistenceChecks() {
		if disqualified[check.PolicyIndex] {
			continue
		}

		value := match(span, check.Ref)
		exists := value != nil || len(value) > 0

		if check.MustExist && !exists {
			disqualified[check.PolicyIndex] = true
		} else if !check.MustExist && exists {
			disqualified[check.PolicyIndex] = true
		} else {
			matchCounts[check.PolicyIndex]++
		}
	}

	// Process Hyperscan databases
	for _, entry := range matchers.Databases() {
		key := entry.Key
		db := entry.Database

		value := match(span, key.Ref)
		if len(value) == 0 {
			if !key.Negated {
				for _, patternRef := range db.PatternIndex() {
					disqualified[patternRef.PolicyIndex] = true
				}
			}
			continue
		}

		matched, err := db.Scan(value)
		if err != nil {
			continue
		}

		for patternID, patternRef := range db.PatternIndex() {
			if disqualified[patternRef.PolicyIndex] {
				continue
			}

			if key.Negated {
				if matched[patternID] {
					disqualified[patternRef.PolicyIndex] = true
				} else {
					matchCounts[patternRef.PolicyIndex]++
				}
			} else {
				if matched[patternID] {
					matchCounts[patternRef.PolicyIndex]++
				}
			}
		}

		db.ReleaseMatched(matched)
	}

	// Find the most restrictive matching policy
	var bestPolicy *engine.CompiledPolicy[engine.TraceField]
	bestRestrictiveness := -1

	for i := range policyCount {
		if disqualified[i] {
			continue
		}

		policy := matchers.PolicyByIndex(i)

		if matchCounts[i] < policy.MatcherCount {
			continue
		}

		if policy.Stats != nil {
			policy.Stats.RecordHit()
		}

		restrictiveness := policy.Keep.Restrictiveness()
		if restrictiveness > bestRestrictiveness {
			bestPolicy = policy
			bestRestrictiveness = restrictiveness
		}
	}

	if bestPolicy == nil {
		return ResultNoMatch
	}

	return applyKeepActionTrace(bestPolicy, span, match)
}

func applyKeepActionTrace[T any](policy *engine.CompiledPolicy[engine.TraceField], span T, match TraceMatchFunc[T]) EvaluateResult {
	switch policy.Keep.Action {
	case KeepAll:
		return ResultKeep

	case KeepNone:
		if policy.Stats != nil {
			policy.Stats.RecordDrop()
		}
		return ResultDrop

	case KeepSample:
		// Hash-based deterministic sampling using trace ID
		shouldKeep := shouldSampleTrace(policy, span, match)
		if policy.Stats != nil {
			policy.Stats.RecordSample()
		}
		if shouldKeep {
			return ResultKeep
		}
		return ResultDrop

	case KeepRatePerSecond, KeepRatePerMinute:
		if policy.RateLimiter == nil {
			return ResultKeep
		}
		if policy.RateLimiter.ShouldKeep() {
			return ResultKeep
		}
		if policy.Stats != nil {
			policy.Stats.RecordRateLimited()
		}
		return ResultDrop

	default:
		return ResultKeep
	}
}

// shouldSampleTrace determines if a span should be kept based on the sampling configuration.
// It implements consistent probability sampling per the OpenTelemetry specification:
// https://opentelemetry.io/docs/specs/otel/trace/tracestate-probability-sampling/
//
// The decision is: if R >= T, keep the span, else drop it.
// Where R is a 56-bit randomness value and T is the rejection threshold.
func shouldSampleTrace[T any](policy *engine.CompiledPolicy[engine.TraceField], span T, match TraceMatchFunc[T]) bool {
	percentage := policy.Keep.Value
	if percentage >= 100 {
		return true
	}
	if percentage <= 0 {
		return false
	}

	// Get the randomness value (R) - 56 bits
	// First try to get explicit randomness from tracestate rv sub-key
	// Fall back to least-significant 56 bits of trace ID
	randomness, ok := getTraceRandomness(span, match)
	if !ok {
		// If no randomness source is available, keep the span (fail open)
		return true
	}

	// Calculate rejection threshold (T) from percentage
	// T = (1 - percentage/100) * 2^56
	// Using integer math to avoid floating point precision issues
	threshold := calculateRejectionThreshold(percentage)

	// OTel consistent sampling decision: if R >= T, keep the span
	return randomness >= threshold
}

// maxThreshold is 2^56, the maximum value for the 56-bit threshold/randomness space
const maxThreshold uint64 = 1 << 56

// getTraceRandomness extracts the 56-bit randomness value for sampling.
// It first checks for explicit randomness in tracestate (rv sub-key),
// then falls back to the least-significant 56 bits of the trace ID.
func getTraceRandomness[T any](span T, match TraceMatchFunc[T]) (uint64, bool) {
	// Try to get explicit randomness from tracestate first
	traceStateRef := engine.SpanTraceState()
	traceState := match(span, traceStateRef)
	if len(traceState) > 0 {
		if rv, ok := parseTracestateRandomness(traceState); ok {
			return rv, true
		}
	}

	// Fall back to trace ID
	traceIDRef := engine.SpanTraceID()
	traceID := match(span, traceIDRef)
	if len(traceID) == 0 {
		return 0, false
	}

	// Extract least-significant 56 bits from trace ID
	// Trace IDs are typically 16 bytes (128 bits), we want the last 7 bytes (56 bits)
	return extractRandomnessFromTraceID(traceID), true
}

// extractRandomnessFromTraceID extracts the least-significant 56 bits from a trace ID.
// Per OTel spec, this is the source of randomness when explicit rv is not present.
func extractRandomnessFromTraceID(traceID []byte) uint64 {
	// Handle both binary (16 bytes) and hex-encoded (32 bytes) trace IDs
	var raw []byte
	if len(traceID) == 32 {
		// Hex-encoded, decode the last 14 hex chars (7 bytes = 56 bits)
		raw = make([]byte, 7)
		hexDecode(raw, traceID[len(traceID)-14:])
	} else if len(traceID) >= 7 {
		// Binary format, take last 7 bytes
		raw = traceID[len(traceID)-7:]
	} else if len(traceID) > 0 {
		// Short trace ID, use what we have
		raw = traceID
	} else {
		return 0
	}

	// Convert to uint64 (big-endian)
	var result uint64
	for _, b := range raw {
		result = (result << 8) | uint64(b)
	}

	// Mask to 56 bits
	return result & (maxThreshold - 1)
}

// hexDecode decodes hex bytes into dst. Simple implementation for trace ID parsing.
func hexDecode(dst, src []byte) {
	for i := 0; i < len(dst) && i*2+1 < len(src); i++ {
		dst[i] = hexVal(src[i*2])<<4 | hexVal(src[i*2+1])
	}
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	default:
		return 0
	}
}

// parseTracestateRandomness extracts the rv (randomness) value from OTel tracestate.
// Format: "ot=...;rv:XXXXXXXXXXXXXX;..." where rv is exactly 14 hex digits.
func parseTracestateRandomness(traceState []byte) (uint64, bool) {
	// Look for "ot=" vendor entry
	otStart := findOTelEntry(traceState)
	if otStart < 0 {
		return 0, false
	}

	// Find rv sub-key within the ot entry
	// Format: rv:XXXXXXXXXXXXXX (14 hex digits)
	rvStart := findSubKey(traceState[otStart:], []byte("rv:"))
	if rvStart < 0 {
		return 0, false
	}

	rvStart += otStart + 3 // Skip "rv:"

	// Extract 14 hex digits
	if rvStart+14 > len(traceState) {
		return 0, false
	}

	rvHex := traceState[rvStart : rvStart+14]

	// Parse as 56-bit hex value
	var rv uint64
	for _, c := range rvHex {
		rv = (rv << 4) | uint64(hexVal(c))
	}

	return rv, true
}

// findOTelEntry finds the start of "ot=" in tracestate, returns index after "ot="
func findOTelEntry(traceState []byte) int {
	for i := 0; i <= len(traceState)-3; i++ {
		if traceState[i] == 'o' && traceState[i+1] == 't' && traceState[i+2] == '=' {
			return i + 3
		}
	}
	return -1
}

// findSubKey finds a sub-key like "rv:" within an OTel tracestate entry
func findSubKey(data, key []byte) int {
	for i := 0; i <= len(data)-len(key); i++ {
		// Check if we're at start or after a separator (semicolon)
		if i == 0 || data[i-1] == ';' {
			match := true
			for j := 0; j < len(key); j++ {
				if data[i+j] != key[j] {
					match = false
					break
				}
			}
			if match {
				return i
			}
		}
	}
	return -1
}

// calculateRejectionThreshold calculates the 56-bit rejection threshold from a percentage.
// Per OTel spec: T = (1 - percentage/100) * 2^56
func calculateRejectionThreshold(percentage float64) uint64 {
	if percentage >= 100 {
		return 0 // 0 threshold means keep everything (R >= 0 is always true)
	}
	if percentage <= 0 {
		return maxThreshold // Max threshold means drop everything
	}

	// T = (1 - p/100) * 2^56
	// Using float64 for the calculation, then convert to uint64
	rejectionProbability := 1.0 - (percentage / 100.0)
	threshold := uint64(rejectionProbability * float64(maxThreshold))

	return threshold
}
