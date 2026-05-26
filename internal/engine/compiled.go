package engine

import (
	"cmp"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sync"

	"github.com/flier/gohs/hyperscan"
	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
)

// PatternRef links a compiled pattern back to its source policy and matcher.
type PatternRef struct {
	PolicyID     string
	PolicyIndex  int // Dense index for array-based tracking
	MatcherIndex int
}

// CompiledDatabase holds a Hyperscan database and scratch space for a group of patterns.
type CompiledDatabase struct {
	db           hyperscan.BlockDatabase
	scratch      *hyperscan.Scratch
	scratchPool  sync.Pool
	matchedPool  sync.Pool    // Pool for []bool match results
	patternIndex []PatternRef // maps pattern ID → policy
}

// Close releases resources associated with the compiled database.
func (c *CompiledDatabase) Close() error {
	if c.scratch != nil {
		if err := c.scratch.Free(); err != nil {
			return err
		}
	}
	if c.db != nil {
		return c.db.Close()
	}
	return nil
}

// PatternIndex returns the pattern index mapping pattern IDs to policies.
func (c *CompiledDatabase) PatternIndex() []PatternRef {
	return c.patternIndex
}

// Scan scans the input data against the compiled database and returns which patterns matched.
// The caller must call ReleaseMatched when done with the result to return it to the pool.
func (c *CompiledDatabase) Scan(data []byte) ([]bool, error) {
	// Get or create a scratch from the pool
	var scratch *hyperscan.Scratch
	if pooled := c.scratchPool.Get(); pooled != nil {
		scratch = pooled.(*hyperscan.Scratch)
	} else {
		var err error
		scratch, err = c.scratch.Clone()
		if err != nil {
			return nil, err
		}
	}

	// Get or create matched slice from pool
	var matched []bool
	if pooled := c.matchedPool.Get(); pooled != nil {
		matched = pooled.([]bool)
		// Clear the slice
		for i := range matched {
			matched[i] = false
		}
	} else {
		matched = make([]bool, len(c.patternIndex))
	}

	err := c.db.Scan(data, scratch, func(id uint, from, to uint64, flags uint, context any) error {
		matched[id] = true
		return nil
	}, nil)

	// Return scratch to pool
	c.scratchPool.Put(scratch)

	if err != nil {
		c.matchedPool.Put(matched)
		return nil, err
	}

	return matched, nil
}

// ReleaseMatched returns a matched slice to the pool.
func (c *CompiledDatabase) ReleaseMatched(matched []bool) {
	if matched != nil {
		c.matchedPool.Put(matched)
	}
}

// ExistenceCheck represents a field existence check that can't be compiled to Hyperscan.
type ExistenceCheck[T FieldType] struct {
	Ref         FieldRef[T]
	MustExist   bool
	PolicyID    string
	PolicyIndex int // Dense index for array-based tracking
	MatchIndex  int
}

// CompiledPolicy holds the compiled representation of a policy for evaluation.
type CompiledPolicy[T FieldType] struct {
	ID           string
	Index        int // Dense index for array-based tracking (0 to N-1)
	Keep         Keep
	MatcherCount int
	SampleKey    *FieldRef[T] // Optional field to use for consistent sampling
	RateLimiter  *RateLimiter // Rate limiter for KeepRatePerSecond/KeepRatePerMinute
	Stats        *PolicyStats
	Transforms   []TransformOp // Log transform operations (nil for metrics/traces)
}

// CompiledMatchers holds all compiled pattern databases for policy evaluation.
type CompiledMatchers[T FieldType] struct {
	databases       []DatabaseEntry[T]
	existenceChecks []ExistenceCheck[T]
	policies        map[string]*CompiledPolicy[T]
	policyList      []*CompiledPolicy[T] // Index-ordered list for fast lookup
}

// Close releases all resources.
func (c *CompiledMatchers[T]) Close() error {
	if c == nil {
		return nil
	}
	for _, entry := range c.databases {
		if err := entry.Database.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Databases returns the compiled databases.
func (c *CompiledMatchers[T]) Databases() []DatabaseEntry[T] {
	return c.databases
}

// ExistenceChecks returns the existence checks.
func (c *CompiledMatchers[T]) ExistenceChecks() []ExistenceCheck[T] {
	return c.existenceChecks
}

// Policies returns the compiled policies.
func (c *CompiledMatchers[T]) Policies() map[string]*CompiledPolicy[T] {
	return c.policies
}

// GetPolicy returns a compiled policy by ID.
func (c *CompiledMatchers[T]) GetPolicy(id string) (*CompiledPolicy[T], bool) {
	p, ok := c.policies[id]
	return p, ok
}

// PolicyCount returns the number of compiled policies.
func (c *CompiledMatchers[T]) PolicyCount() int {
	return len(c.policyList)
}

// PolicyByIndex returns a compiled policy by its dense index.
func (c *CompiledMatchers[T]) PolicyByIndex(index int) *CompiledPolicy[T] {
	return c.policyList[index]
}

// CompileResult contains compiled matchers for all telemetry types.
type CompileResult struct {
	Logs    *CompiledMatchers[LogField]
	Metrics *CompiledMatchers[MetricField]
	Traces  *CompiledMatchers[TraceField]
	// Errors maps policy ID → per-policy compile errors. A policy with any
	// entries here is excluded from the compiled matchers; valid policies in
	// the same batch still compile. Use these to report bad policies back to
	// the policy server via PolicySyncStatus.errors.
	Errors map[string][]string
}

// Close releases all resources.
func (r *CompileResult) Close() error {
	if err := r.Logs.Close(); err != nil {
		return err
	}
	if err := r.Metrics.Close(); err != nil {
		return err
	}
	if err := r.Traces.Close(); err != nil {
		return err
	}
	return nil
}

// Compiler compiles policies into Hyperscan databases.
type Compiler struct{}

// NewCompiler creates a new Compiler.
func NewCompiler() *Compiler {
	return &Compiler{}
}

// Compile compiles a set of proto policies into CompileResult with separate
// CompiledMatchers for logs, metrics, and traces. Per-policy compile failures
// (bad regex, empty attribute path, unspecified field enum, missing match
// oneof, etc.) are reported via CompileResult.Errors. A broken policy is
// still added to the matchers but with one or more matchers skipped, so its
// matchCount can never be reached at evaluation — it stays inert. The
// function's own error return is reserved for batch-level failures (e.g.,
// Hyperscan init).
func (c *Compiler) Compile(policies []*policyv1.Policy, stats map[string]*PolicyStats) (*CompileResult, error) {
	// Sort policies by ID for deterministic transform ordering per spec.
	slices.SortFunc(policies, func(a, b *policyv1.Policy) int {
		return cmp.Compare(a.GetId(), b.GetId())
	})

	logBuilder := newMatchersBuilder[LogField]()
	metricBuilder := newMatchersBuilder[MetricField]()
	traceBuilder := newMatchersBuilder[TraceField]()
	var perPolicyErrors map[string][]string

	for _, p := range policies {
		id := p.GetId()
		policyStats := stats[id]
		var policyErr error
		addErr := func(prefix string, err error) {
			if err == nil {
				return
			}
			// Splay joined errors so each leaf gets its own prefix when
			// stringified — fmt.Errorf("%w") collapses joined-ness.
			for _, leaf := range flattenErr(err) {
				policyErr = errors.Join(policyErr, fmt.Errorf("%s: %w", prefix, leaf))
			}
		}

		// Process log target
		if log := p.GetLog(); log != nil {
			idx := logBuilder.reservePolicy(id)

			keep, err := ParseKeep(log.GetKeep())
			addErr("log: keep", err)

			var sampleKey *LogFieldRef
			if sk := log.GetSampleKey(); sk != nil {
				ref, err := FieldRefFromLogSampleKey(sk)
				if err != nil {
					addErr("log: sampleKey", err)
				} else {
					sampleKey = &ref
				}
			}

			for i, m := range log.GetMatch() {
				ref, refErr := FieldRefFromLogMatcher(m)
				pattern, isExistence, mustExist, patErr := extractMatchPattern(m)
				addErr(fmt.Sprintf("log: match[%d]", i), refErr)
				addErr(fmt.Sprintf("log: match[%d]", i), patErr)
				if refErr != nil || patErr != nil {
					continue
				}
				logBuilder.addMatcher(ref, pattern, isExistence, mustExist, m.GetNegate(), m.GetCaseInsensitive(), id, idx, i)
			}

			transforms, err := compileLogTransform(log.GetTransform())
			addErr("log: transform", err)
			logBuilder.finalizePolicy(id, idx, keep, len(log.GetMatch()), sampleKey, policyStats, transforms)
		}

		// Process metric target
		if metric := p.GetMetric(); metric != nil {
			idx := metricBuilder.reservePolicy(id)

			keep := Keep{Action: KeepNone}
			if metric.GetKeep() {
				keep = Keep{Action: KeepAll}
			}

			for i, m := range metric.GetMatch() {
				ref, refErr := FieldRefFromMetricMatcher(m)
				pattern, isExistence, mustExist, patErr := extractMetricMatchPattern(m)
				addErr(fmt.Sprintf("metric: match[%d]", i), refErr)
				addErr(fmt.Sprintf("metric: match[%d]", i), patErr)
				if refErr != nil || patErr != nil {
					continue
				}
				metricBuilder.addMatcher(ref, pattern, isExistence, mustExist, m.GetNegate(), m.GetCaseInsensitive(), id, idx, i)
			}

			metricBuilder.finalizePolicy(id, idx, keep, len(metric.GetMatch()), nil, policyStats, nil)
		}

		// Process trace target
		if trace := p.GetTrace(); trace != nil {
			idx := traceBuilder.reservePolicy(id)

			keep, err := parseTraceSamplingConfig(trace.GetKeep())
			addErr("trace: keep", err)

			for i, m := range trace.GetMatch() {
				ref, refErr := FieldRefFromTraceMatcher(m)
				pattern, isExistence, mustExist, patErr := extractTraceMatchPattern(m)
				addErr(fmt.Sprintf("trace: match[%d]", i), refErr)
				addErr(fmt.Sprintf("trace: match[%d]", i), patErr)
				if refErr != nil || patErr != nil {
					continue
				}
				traceBuilder.addMatcher(ref, pattern, isExistence, mustExist, m.GetNegate(), m.GetCaseInsensitive(), id, idx, i)
			}

			traceBuilder.finalizePolicy(id, idx, keep, len(trace.GetMatch()), nil, policyStats, nil)
		}

		if policyErr != nil {
			if perPolicyErrors == nil {
				perPolicyErrors = make(map[string][]string)
			}
			leaves := flattenErr(policyErr)
			msgs := make([]string, len(leaves))
			for i, e := range leaves {
				msgs[i] = e.Error()
			}
			perPolicyErrors[id] = msgs
		}
	}

	logs, err := logBuilder.build()
	if err != nil {
		return nil, fmt.Errorf("compiling log policies: %w", err)
	}

	metrics, err := metricBuilder.build()
	if err != nil {
		logs.Close()
		return nil, fmt.Errorf("compiling metric policies: %w", err)
	}

	traces, err := traceBuilder.build()
	if err != nil {
		logs.Close()
		metrics.Close()
		return nil, fmt.Errorf("compiling trace policies: %w", err)
	}

	return &CompileResult{
		Logs:    logs,
		Metrics: metrics,
		Traces:  traces,
		Errors:  perPolicyErrors,
	}, nil
}

// flattenErr returns the leaf errors of a possibly errors.Join-ed error so the
// caller can wrap each one with a per-branch layer prefix. compileLogTransform
// joins per-op errors; this lets the call site prefix each op individually.
func flattenErr(err error) []error {
	if err == nil {
		return nil
	}
	type joined interface{ Unwrap() []error }
	if j, ok := err.(joined); ok {
		var out []error
		for _, e := range j.Unwrap() {
			out = append(out, flattenErr(e)...)
		}
		return out
	}
	return []error{err}
}

// extractMatchPattern extracts the pattern string from a LogMatcher and
// returns (pattern, isExistence, mustExist, error). Returns an error if the
// match oneof is missing or the regex fails to compile — both prevent the
// policy from matching anything useful so we surface them rather than
// silently ignore.
func extractMatchPattern(m *policyv1.LogMatcher) (string, bool, bool, error) {
	switch match := m.GetMatch().(type) {
	case *policyv1.LogMatcher_Regex:
		if _, err := regexp.Compile(match.Regex); err != nil {
			return "", false, false, fmt.Errorf("invalid regex %q: %w", match.Regex, err)
		}
		return match.Regex, false, false, nil
	case *policyv1.LogMatcher_Exact:
		return escapeRegex(match.Exact), false, false, nil
	case *policyv1.LogMatcher_StartsWith:
		return "^" + escapeRegex(match.StartsWith), false, false, nil
	case *policyv1.LogMatcher_EndsWith:
		return escapeRegex(match.EndsWith) + "$", false, false, nil
	case *policyv1.LogMatcher_Contains:
		return escapeRegex(match.Contains), false, false, nil
	case *policyv1.LogMatcher_Exists:
		return "", true, match.Exists, nil
	default:
		return "", false, false, errors.New("no match condition set")
	}
}

// metricTypeToString converts a MetricType enum to its lowercase string representation.
func metricTypeToString(mt policyv1.MetricType) string {
	switch mt {
	case policyv1.MetricType_METRIC_TYPE_GAUGE:
		return "gauge"
	case policyv1.MetricType_METRIC_TYPE_SUM:
		return "sum"
	case policyv1.MetricType_METRIC_TYPE_HISTOGRAM:
		return "histogram"
	case policyv1.MetricType_METRIC_TYPE_EXPONENTIAL_HISTOGRAM:
		return "exponential_histogram"
	case policyv1.MetricType_METRIC_TYPE_SUMMARY:
		return "summary"
	default:
		return ""
	}
}

// aggregationTemporalityToString converts an AggregationTemporality enum to its lowercase string representation.
func aggregationTemporalityToString(at policyv1.AggregationTemporality) string {
	switch at {
	case policyv1.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA:
		return "delta"
	case policyv1.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE:
		return "cumulative"
	default:
		return ""
	}
}

// extractMetricMatchPattern extracts the pattern string from a MetricMatcher.
// For MetricType and AggregationTemporality fields, the enum value is converted
// to lowercase for matching and supplies the pattern directly — the standard
// match oneof is not required for those fields.
func extractMetricMatchPattern(m *policyv1.MetricMatcher) (string, bool, bool, error) {
	// Special handling for MetricType - convert enum to lowercase string for matching
	if mt, ok := m.GetField().(*policyv1.MetricMatcher_MetricType); ok {
		if mt.MetricType == policyv1.MetricType_METRIC_TYPE_UNSPECIFIED {
			return "", false, false, errors.New("metricType is unspecified")
		}
		typeStr := metricTypeToString(mt.MetricType)
		if typeStr == "" {
			return "", false, false, fmt.Errorf("unknown metric type %v", mt.MetricType)
		}
		return "^" + escapeRegex(typeStr) + "$", false, false, nil
	}

	// Special handling for AggregationTemporality - convert enum to lowercase string for matching
	if at, ok := m.GetField().(*policyv1.MetricMatcher_AggregationTemporality); ok {
		if at.AggregationTemporality == policyv1.AggregationTemporality_AGGREGATION_TEMPORALITY_UNSPECIFIED {
			return "", false, false, errors.New("aggregationTemporality is unspecified")
		}
		tempStr := aggregationTemporalityToString(at.AggregationTemporality)
		if tempStr == "" {
			return "", false, false, fmt.Errorf("unknown aggregation temporality %v", at.AggregationTemporality)
		}
		return "^" + escapeRegex(tempStr) + "$", false, false, nil
	}

	// Standard match patterns
	switch match := m.GetMatch().(type) {
	case *policyv1.MetricMatcher_Regex:
		if _, err := regexp.Compile(match.Regex); err != nil {
			return "", false, false, fmt.Errorf("invalid regex %q: %w", match.Regex, err)
		}
		return match.Regex, false, false, nil
	case *policyv1.MetricMatcher_Exact:
		return escapeRegex(match.Exact), false, false, nil
	case *policyv1.MetricMatcher_StartsWith:
		return "^" + escapeRegex(match.StartsWith), false, false, nil
	case *policyv1.MetricMatcher_EndsWith:
		return escapeRegex(match.EndsWith) + "$", false, false, nil
	case *policyv1.MetricMatcher_Contains:
		return escapeRegex(match.Contains), false, false, nil
	case *policyv1.MetricMatcher_Exists:
		return "", true, match.Exists, nil
	default:
		return "", false, false, errors.New("no match condition set")
	}
}

// spanKindToString converts a SpanKind enum to its lowercase string representation.
func spanKindToString(sk policyv1.SpanKind) string {
	switch sk {
	case policyv1.SpanKind_SPAN_KIND_INTERNAL:
		return "internal"
	case policyv1.SpanKind_SPAN_KIND_SERVER:
		return "server"
	case policyv1.SpanKind_SPAN_KIND_CLIENT:
		return "client"
	case policyv1.SpanKind_SPAN_KIND_PRODUCER:
		return "producer"
	case policyv1.SpanKind_SPAN_KIND_CONSUMER:
		return "consumer"
	default:
		return ""
	}
}

// spanStatusToString converts a SpanStatusCode enum to its lowercase string representation.
func spanStatusToString(ss policyv1.SpanStatusCode) string {
	switch ss {
	case policyv1.SpanStatusCode_SPAN_STATUS_CODE_UNSPECIFIED:
		return "unset"
	case policyv1.SpanStatusCode_SPAN_STATUS_CODE_OK:
		return "ok"
	case policyv1.SpanStatusCode_SPAN_STATUS_CODE_ERROR:
		return "error"
	default:
		return ""
	}
}

// extractTraceMatchPattern extracts the pattern string from a TraceMatcher.
// For SpanKind and SpanStatus fields, the enum value is converted to lowercase
// for matching and supplies the pattern directly.
func extractTraceMatchPattern(m *policyv1.TraceMatcher) (string, bool, bool, error) {
	// Special handling for SpanKind - convert enum to lowercase string for matching
	if sk, ok := m.GetField().(*policyv1.TraceMatcher_SpanKind); ok {
		if sk.SpanKind == policyv1.SpanKind_SPAN_KIND_UNSPECIFIED {
			return "", false, false, errors.New("spanKind is unspecified")
		}
		kindStr := spanKindToString(sk.SpanKind)
		if kindStr == "" {
			return "", false, false, fmt.Errorf("unknown span kind %v", sk.SpanKind)
		}
		return "^" + escapeRegex(kindStr) + "$", false, false, nil
	}

	// Special handling for SpanStatus - convert enum to lowercase string for matching
	if ss, ok := m.GetField().(*policyv1.TraceMatcher_SpanStatus); ok {
		statusStr := spanStatusToString(ss.SpanStatus)
		if statusStr == "" {
			return "", false, false, fmt.Errorf("unknown span status %v", ss.SpanStatus)
		}
		return "^" + escapeRegex(statusStr) + "$", false, false, nil
	}

	// Standard match patterns
	switch match := m.GetMatch().(type) {
	case *policyv1.TraceMatcher_Regex:
		if _, err := regexp.Compile(match.Regex); err != nil {
			return "", false, false, fmt.Errorf("invalid regex %q: %w", match.Regex, err)
		}
		return match.Regex, false, false, nil
	case *policyv1.TraceMatcher_Exact:
		return escapeRegex(match.Exact), false, false, nil
	case *policyv1.TraceMatcher_StartsWith:
		return "^" + escapeRegex(match.StartsWith), false, false, nil
	case *policyv1.TraceMatcher_EndsWith:
		return escapeRegex(match.EndsWith) + "$", false, false, nil
	case *policyv1.TraceMatcher_Contains:
		return escapeRegex(match.Contains), false, false, nil
	case *policyv1.TraceMatcher_Exists:
		return "", true, match.Exists, nil
	default:
		return "", false, false, errors.New("no match condition set")
	}
}

// escapeRegex escapes special regex characters for literal matching.
func escapeRegex(s string) string {
	special := `\.+*?^$()[]{}|`
	result := make([]byte, 0, len(s)*2)
	for i := 0; i < len(s); i++ {
		c := s[i]
		for j := 0; j < len(special); j++ {
			if c == special[j] {
				result = append(result, '\\')
				break
			}
		}
		result = append(result, c)
	}
	return string(result)
}

// parseTraceSamplingConfig converts a TraceSamplingConfig to a Keep.
func parseTraceSamplingConfig(cfg *policyv1.TraceSamplingConfig) (Keep, error) {
	if cfg == nil {
		return Keep{Action: KeepAll, FailClosed: true, SamplingPrecision: 4}, nil
	}

	percentage := float64(cfg.GetPercentage())
	if percentage >= 100 {
		return Keep{Action: KeepAll, FailClosed: true, SamplingPrecision: 4}, nil
	}
	if percentage <= 0 {
		return Keep{Action: KeepNone, FailClosed: true, SamplingPrecision: 4}, nil
	}

	keep := Keep{
		Action:            KeepSample,
		Value:             percentage,
		SamplingMode:      cfg.GetMode(),
		SamplingPrecision: 4,
		FailClosed:        true,
	}

	if cfg.HashSeed != nil {
		keep.HashSeed = *cfg.HashSeed
	}
	if cfg.SamplingPrecision != nil {
		keep.SamplingPrecision = *cfg.SamplingPrecision
	}
	if cfg.FailClosed != nil {
		keep.FailClosed = *cfg.FailClosed
	}

	return keep, nil
}
