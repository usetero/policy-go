package policy

import (
	"hash/fnv"
	"sync"

	"github.com/usetero/policy-go/internal/engine"
	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
)

// evalState holds reusable slices for policy evaluation to avoid allocations.
type evalState struct {
	matchCounts  []int
	disqualified []bool
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
// FIELD REF CONVERTERS
// ============================================================================

// logFieldRefFromSelector converts an internal FieldSelector to a LogFieldRef.
func logFieldRefFromSelector(selector engine.FieldSelector[engine.LogField]) LogFieldRef {
	if selector.IsAttribute() {
		switch selector.AttrScope {
		case engine.AttrScopeResource:
			return LogResourceAttr(selector.AttrPath...)
		case engine.AttrScopeScope:
			return LogScopeAttr(selector.AttrPath...)
		case engine.AttrScopeRecord:
			return LogAttr(selector.AttrPath...)
		default:
			return LogFieldRef{}
		}
	}
	switch selector.Field {
	case engine.LogFieldBody:
		return LogField(policyv1.LogField_LOG_FIELD_BODY)
	case engine.LogFieldSeverityText:
		return LogField(policyv1.LogField_LOG_FIELD_SEVERITY_TEXT)
	case engine.LogFieldTraceID:
		return LogField(policyv1.LogField_LOG_FIELD_TRACE_ID)
	case engine.LogFieldSpanID:
		return LogField(policyv1.LogField_LOG_FIELD_SPAN_ID)
	case engine.LogFieldEventName:
		return LogField(policyv1.LogField_LOG_FIELD_EVENT_NAME)
	case engine.LogFieldResourceSchemaURL:
		return LogField(policyv1.LogField_LOG_FIELD_RESOURCE_SCHEMA_URL)
	case engine.LogFieldScopeSchemaURL:
		return LogField(policyv1.LogField_LOG_FIELD_SCOPE_SCHEMA_URL)
	default:
		return LogFieldRef{}
	}
}

// metricFieldRefFromSelector converts an internal FieldSelector to a MetricFieldRef.
func metricFieldRefFromSelector(selector engine.FieldSelector[engine.MetricField]) MetricFieldRef {
	if selector.IsAttribute() {
		switch selector.AttrScope {
		case engine.AttrScopeResource:
			return MetricResourceAttr(selector.AttrPath...)
		case engine.AttrScopeScope:
			return MetricScopeAttr(selector.AttrPath...)
		case engine.AttrScopeRecord:
			return DatapointAttr(selector.AttrPath...)
		default:
			return MetricFieldRef{}
		}
	}
	switch selector.Field {
	case engine.MetricFieldName:
		return MetricField(policyv1.MetricField_METRIC_FIELD_NAME)
	case engine.MetricFieldDescription:
		return MetricField(policyv1.MetricField_METRIC_FIELD_DESCRIPTION)
	case engine.MetricFieldUnit:
		return MetricField(policyv1.MetricField_METRIC_FIELD_UNIT)
	case engine.MetricFieldResourceSchemaURL:
		return MetricField(policyv1.MetricField_METRIC_FIELD_RESOURCE_SCHEMA_URL)
	case engine.MetricFieldScopeSchemaURL:
		return MetricField(policyv1.MetricField_METRIC_FIELD_SCOPE_SCHEMA_URL)
	case engine.MetricFieldScopeName:
		return MetricField(policyv1.MetricField_METRIC_FIELD_SCOPE_NAME)
	case engine.MetricFieldScopeVersion:
		return MetricField(policyv1.MetricField_METRIC_FIELD_SCOPE_VERSION)
	case engine.MetricFieldType:
		return MetricTypeRef(policyv1.MetricType_METRIC_TYPE_UNSPECIFIED)
	case engine.MetricFieldAggregationTemporality:
		return AggTemporalityRef(policyv1.AggregationTemporality_AGGREGATION_TEMPORALITY_UNSPECIFIED)
	default:
		return MetricFieldRef{}
	}
}

// traceFieldRefFromSelector converts an internal FieldSelector to a TraceFieldRef.
func traceFieldRefFromSelector(selector engine.FieldSelector[engine.TraceField]) TraceFieldRef {
	if selector.IsAttribute() {
		switch selector.AttrScope {
		case engine.AttrScopeResource:
			return TraceResourceAttr(selector.AttrPath...)
		case engine.AttrScopeScope:
			return TraceScopeAttr(selector.AttrPath...)
		case engine.AttrScopeRecord:
			return SpanAttr(selector.AttrPath...)
		case engine.AttrScopeEvent:
			return EventAttr(selector.AttrPath...)
		default:
			return TraceFieldRef{}
		}
	}
	switch selector.Field {
	case engine.TraceFieldName:
		return TraceField(policyv1.TraceField_TRACE_FIELD_NAME)
	case engine.TraceFieldTraceID:
		return TraceField(policyv1.TraceField_TRACE_FIELD_TRACE_ID)
	case engine.TraceFieldSpanID:
		return TraceField(policyv1.TraceField_TRACE_FIELD_SPAN_ID)
	case engine.TraceFieldParentSpanID:
		return TraceField(policyv1.TraceField_TRACE_FIELD_PARENT_SPAN_ID)
	case engine.TraceFieldTraceState:
		return TraceField(policyv1.TraceField_TRACE_FIELD_TRACE_STATE)
	case engine.TraceFieldResourceSchemaURL:
		return TraceField(policyv1.TraceField_TRACE_FIELD_RESOURCE_SCHEMA_URL)
	case engine.TraceFieldKind:
		return SpanKindRef(policyv1.SpanKind_SPAN_KIND_UNSPECIFIED)
	case engine.TraceFieldStatus:
		return SpanStatusRef(policyv1.SpanStatusCode_SPAN_STATUS_CODE_UNSPECIFIED)
	case engine.TraceFieldEventName:
		return EventName()
	case engine.TraceFieldLinkTraceID:
		return LinkTraceID()
	default:
		return TraceFieldRef{}
	}
}

// ============================================================================
// LOG EVALUATION
// ============================================================================

// EvaluateLog checks a log record against the current policies and returns the result.
// This method uses index-based arrays instead of maps for better performance.
//
// The match function is called to extract field values from the record.
// Consumers provide this function to bridge their record type to the policy engine.
func EvaluateLog[T any](e *PolicyEngine, record T, match LogMatchFunc[T]) EvaluateResult {
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

		ref := logFieldRefFromSelector(check.Selector)
		value := match(record, ref)
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

		ref := logFieldRefFromSelector(key.Selector)
		value := match(record, ref)
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

	// Find the most restrictive matching policy
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
	return applyKeepActionLog(e, bestPolicy, record, match)
}

func applyKeepActionLog[T any](e *PolicyEngine, policy *engine.CompiledPolicy[engine.LogField], record T, match LogMatchFunc[T]) EvaluateResult {
	switch policy.Keep.Action {
	case KeepAll:
		return ResultKeep

	case KeepNone:
		if policy.Stats != nil {
			policy.Stats.RecordDrop()
		}
		return ResultDrop

	case KeepSample:
		// Hash-based deterministic sampling
		// If a sample key is configured, use it for consistent sampling
		// Otherwise, sample randomly based on percentage
		shouldKeep := shouldSampleLog(e, policy, record, match)
		if policy.Stats != nil {
			policy.Stats.RecordSample()
		}
		if shouldKeep {
			return ResultKeep
		}
		return ResultDrop

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
		ref := logFieldRefFromSelector(*policy.SampleKey)
		hashInput = match(record, ref)
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

		ref := metricFieldRefFromSelector(check.Selector)
		value := match(metric, ref)
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

		ref := metricFieldRefFromSelector(key.Selector)
		value := match(metric, ref)
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
		if policy.Stats != nil {
			policy.Stats.RecordRateLimited()
		}
		return ResultRateLimit

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

		ref := traceFieldRefFromSelector(check.Selector)
		value := match(span, ref)
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

		ref := traceFieldRefFromSelector(key.Selector)
		value := match(span, ref)
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

	return applyKeepActionTrace(bestPolicy)
}

func applyKeepActionTrace(policy *engine.CompiledPolicy[engine.TraceField]) EvaluateResult {
	switch policy.Keep.Action {
	case KeepAll:
		return ResultKeep

	case KeepNone:
		if policy.Stats != nil {
			policy.Stats.RecordDrop()
		}
		return ResultDrop

	case KeepSample:
		// Trace sampling typically uses trace ID for consistency
		// The caller should implement their own sampling logic based on trace ID
		if policy.Stats != nil {
			policy.Stats.RecordSample()
		}
		return ResultSample

	case KeepRatePerSecond, KeepRatePerMinute:
		if policy.Stats != nil {
			policy.Stats.RecordRateLimited()
		}
		return ResultRateLimit

	default:
		return ResultKeep
	}
}
