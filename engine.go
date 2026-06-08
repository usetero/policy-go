package policy

import (
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

// EvaluateLog checks a log record against the current policies and returns
// the result. The Value/Exists options drive matching; if the winning policy
// has transforms, the engine applies them via the Set/Delete/Move options.
// Consumers that don't want mutation can omit those options.
func EvaluateLog[T any](e *PolicyEngine, record T, opts ...LogOption[T]) EvaluateResult {
	// Stack-allocate the accessor. Options dispatch via switch (no closures)
	// so the compiler can prove a doesn't escape from this function — every
	// downstream call uses it transiently, none retain it past return.
	var a engine.LogAccessor[T]
	applyLogOpts(&a, opts)
	c := &a
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

		exists := c.Exists(record, check.Ref)

		if check.MustExist && !exists {
			disqualified[check.PolicyIndex] = true
		} else if !check.MustExist && exists {
			disqualified[check.PolicyIndex] = true
		} else {
			matchCounts[check.PolicyIndex]++
		}
	}

	// Process typed comparison checks (equals/gt/gte/lt/lte). Type mismatch
	// or absent values fail-open (non-match).
	for _, check := range matchers.TypedChecks() {
		if disqualified[check.PolicyIndex] {
			continue
		}
		fv := logTypedValue(c, record, check.Ref)
		matched := check.Matcher.Evaluate(fv)
		if check.Negate {
			matched = !matched
		}
		if matched {
			matchCounts[check.PolicyIndex]++
		} else {
			disqualified[check.PolicyIndex] = true
		}
	}

	// Process Hyperscan databases
	for _, entry := range matchers.Databases() {
		key := entry.Key
		db := entry.Database

		value := c.Value(record, key.Ref)
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
	return applyKeepActionLog(e, bestPolicy, matchers, state.matchedIndices[:state.matchedCount], record, c)
}

func applyKeepActionLog[T any](e *PolicyEngine, policy *engine.CompiledPolicy[engine.LogField], matchers *engine.CompiledMatchers[engine.LogField], matchedIndices []int, record T, c *engine.LogAccessor[T]) EvaluateResult {
	dropped := false

	switch policy.Keep.Action {
	case KeepNone:
		dropped = true

	case KeepSample:
		if !shouldSampleLog(policy, record, c) {
			dropped = true
		}

	case KeepRatePerSecond, KeepRatePerMinute:
		if policy.RateLimiter != nil && !policy.RateLimiter.ShouldKeep() {
			dropped = true
		}
	}

	// Record match hits/misses based on outcome.
	// If kept: all matching policies get a match hit.
	// If dropped: the winning policy gets a match hit; all others get a match miss.
	recordMatchStats(matchers, matchedIndices, policy, dropped)

	if dropped {
		return ResultDrop
	}

	// Apply transforms from all matching policies. The library owns the full
	// spec semantics in ApplyLogTransform; the consumer only sees the
	// primitive Set/Delete/Move calls.
	hasTransforms := false
	for _, idx := range matchedIndices {
		p := matchers.PolicyByIndex(idx)
		if len(p.Transforms) == 0 {
			continue
		}
		hasTransforms = true
		for _, op := range p.Transforms {
			hit := engine.ApplyLogTransform(record, op, c)
			if p.Stats != nil {
				if hit {
					p.Stats.RecordTransformHit(op.Kind)
				} else {
					p.Stats.RecordTransformMiss(op.Kind)
				}
			}
		}
	}

	if hasTransforms {
		return ResultKeepWithTransform
	}
	return ResultKeep
}

// recordMatchStats records match hits and misses for all matched policies based on the outcome.
// If the record was kept, all matching policies get a match hit.
// If the record was dropped, the winning (most restrictive) policy gets a match hit;
// all other matching policies get a match miss.
func recordMatchStats[T engine.FieldType](matchers *engine.CompiledMatchers[T], matchedIndices []int, bestPolicy *engine.CompiledPolicy[T], dropped bool) {
	for _, idx := range matchedIndices {
		p := matchers.PolicyByIndex(idx)
		if p.Stats == nil {
			continue
		}
		if dropped && p != bestPolicy {
			p.Stats.RecordMatchMiss()
		} else {
			p.Stats.RecordMatchHit()
		}
	}
}

// ============================================================================
// METRIC EVALUATION
// ============================================================================

// EvaluateMetric checks a metric against the current policies and returns
// the result. The Value/Exists options drive matching.
func EvaluateMetric[T any](e *PolicyEngine, metric T, opts ...MetricOption[T]) EvaluateResult {
	var a engine.MetricAccessor[T]
	applyMetricOpts(&a, opts)
	c := &a
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

		exists := c.Exists(metric, check.Ref)

		if check.MustExist && !exists {
			disqualified[check.PolicyIndex] = true
		} else if !check.MustExist && exists {
			disqualified[check.PolicyIndex] = true
		} else {
			matchCounts[check.PolicyIndex]++
		}
	}

	// Process typed comparison checks.
	for _, check := range matchers.TypedChecks() {
		if disqualified[check.PolicyIndex] {
			continue
		}
		fv := metricTypedValue(c, metric, check.Ref)
		matched := check.Matcher.Evaluate(fv)
		if check.Negate {
			matched = !matched
		}
		if matched {
			matchCounts[check.PolicyIndex]++
		} else {
			disqualified[check.PolicyIndex] = true
		}
	}

	// Process Hyperscan databases
	for _, entry := range matchers.Databases() {
		key := entry.Key
		db := entry.Database

		value := c.Value(metric, key.Ref)
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

		state.matchedIndices[state.matchedCount] = i
		state.matchedCount++

		restrictiveness := policy.Keep.Restrictiveness()
		if restrictiveness > bestRestrictiveness {
			bestPolicy = policy
			bestRestrictiveness = restrictiveness
		}
	}

	if bestPolicy == nil {
		return ResultNoMatch
	}

	return applyKeepActionMetric(bestPolicy, matchers, state.matchedIndices[:state.matchedCount])
}

func applyKeepActionMetric(policy *engine.CompiledPolicy[engine.MetricField], matchers *engine.CompiledMatchers[engine.MetricField], matchedIndices []int) EvaluateResult {
	dropped := false

	switch policy.Keep.Action {
	case KeepNone:
		dropped = true

	case KeepSample:
		// Metrics don't support sample keys, so we just use the percentage directly.
		// Sample result is returned to the caller to decide; treat as kept for match stats.
		recordMatchStats(matchers, matchedIndices, policy, false)
		return ResultSample

	case KeepRatePerSecond, KeepRatePerMinute:
		if policy.RateLimiter != nil && !policy.RateLimiter.ShouldKeep() {
			dropped = true
		}
	}

	recordMatchStats(matchers, matchedIndices, policy, dropped)

	if dropped {
		return ResultDrop
	}
	return ResultKeep
}

// ============================================================================
// TRACE EVALUATION
// ============================================================================

// EvaluateTrace checks a span against the current policies and returns
// the result. The Value/Exists options drive matching; after a sampling
// decision, the engine writes the effective threshold back through the
// Set option (using SpanSamplingThreshold() as the ref).
func EvaluateTrace[T any](e *PolicyEngine, span T, opts ...TraceOption[T]) EvaluateResult {
	var a engine.TraceAccessor[T]
	applyTraceOpts(&a, opts)
	c := &a
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

		exists := c.Exists(span, check.Ref)

		if check.MustExist && !exists {
			disqualified[check.PolicyIndex] = true
		} else if !check.MustExist && exists {
			disqualified[check.PolicyIndex] = true
		} else {
			matchCounts[check.PolicyIndex]++
		}
	}

	// Process typed comparison checks.
	for _, check := range matchers.TypedChecks() {
		if disqualified[check.PolicyIndex] {
			continue
		}
		fv := traceTypedValue(c, span, check.Ref)
		matched := check.Matcher.Evaluate(fv)
		if check.Negate {
			matched = !matched
		}
		if matched {
			matchCounts[check.PolicyIndex]++
		} else {
			disqualified[check.PolicyIndex] = true
		}
	}

	// Process Hyperscan databases
	for _, entry := range matchers.Databases() {
		key := entry.Key
		db := entry.Database

		value := c.Value(span, key.Ref)
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

		state.matchedIndices[state.matchedCount] = i
		state.matchedCount++

		restrictiveness := policy.Keep.Restrictiveness()
		if restrictiveness > bestRestrictiveness {
			bestPolicy = policy
			bestRestrictiveness = restrictiveness
		}
	}

	if bestPolicy == nil {
		return ResultNoMatch
	}

	return applyKeepActionTrace(bestPolicy, matchers, state.matchedIndices[:state.matchedCount], span, c)
}

func applyKeepActionTrace[T any](policy *engine.CompiledPolicy[engine.TraceField], matchers *engine.CompiledMatchers[engine.TraceField], matchedIndices []int, span T, c *engine.TraceAccessor[T]) EvaluateResult {
	dropped := false
	var effectiveThreshold uint64
	writeThreshold := false

	switch policy.Keep.Action {
	case KeepNone:
		dropped = true

	case KeepSample:
		keep, threshold, hasThreshold := shouldSampleTrace(policy, span, c)
		if !keep {
			dropped = true
		}
		effectiveThreshold = threshold
		writeThreshold = hasThreshold

	case KeepAll:
		// 100% keep — threshold is 0
		effectiveThreshold = 0
		writeThreshold = true

	case KeepRatePerSecond, KeepRatePerMinute:
		if policy.RateLimiter != nil && !policy.RateLimiter.ShouldKeep() {
			dropped = true
		}
	}

	recordMatchStats(matchers, matchedIndices, policy, dropped)

	if dropped {
		return ResultDrop
	}

	// Write the effective threshold back to the span. Per W3C spec, only
	// write threshold when sampling probability is known (i.e. randomness
	// was successfully derived).
	if writeThreshold {
		encoded := encodeThreshold(effectiveThreshold, policy.Keep.SamplingPrecision)
		c.Set(span, engine.SpanSamplingThreshold(), encoded)
		return ResultKeepWithTransform
	}

	return ResultKeep
}

// logTypedValue returns the field's typed value for ref. If the consumer
// supplied a TypedValue accessor, defer to it. Otherwise fall back to the
// string Value accessor and wrap a present result as TypedValue.String — this
// matches the Rust SDK's default trait impl and means string-targeted typed
// matchers (equals against an exact string... wait no, equals has no string
// variant per spec) still get the right answer without forcing every consumer
// to implement TypedValue. Consumers who want bool/int/double/bytes matching
// must implement TypedValue.
func logTypedValue[T any](c *engine.LogAccessor[T], rec T, ref engine.LogFieldRef) engine.TypedValue {
	if c.TypedValue != nil {
		return c.TypedValue(rec, ref)
	}
	if c.Value == nil {
		return engine.TypedValue{}
	}
	v := c.Value(rec, ref)
	if v == nil {
		return engine.TypedValue{}
	}
	return engine.TypedValue{Kind: engine.TypedValueString, Str: string(v)}
}

func metricTypedValue[T any](c *engine.MetricAccessor[T], rec T, ref engine.MetricFieldRef) engine.TypedValue {
	if c.TypedValue != nil {
		return c.TypedValue(rec, ref)
	}
	if c.Value == nil {
		return engine.TypedValue{}
	}
	v := c.Value(rec, ref)
	if v == nil {
		return engine.TypedValue{}
	}
	return engine.TypedValue{Kind: engine.TypedValueString, Str: string(v)}
}

func traceTypedValue[T any](c *engine.TraceAccessor[T], rec T, ref engine.TraceFieldRef) engine.TypedValue {
	if c.TypedValue != nil {
		return c.TypedValue(rec, ref)
	}
	if c.Value == nil {
		return engine.TypedValue{}
	}
	v := c.Value(rec, ref)
	if v == nil {
		return engine.TypedValue{}
	}
	return engine.TypedValue{Kind: engine.TypedValueString, Str: string(v)}
}
