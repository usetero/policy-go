package engine

import (
	"fmt"
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
	Stats        *PolicyStats
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
// CompiledMatchers for logs, metrics, and traces.
func (c *Compiler) Compile(policies []*policyv1.Policy, stats map[string]*PolicyStats) (*CompileResult, error) {
	logBuilder := newMatchersBuilder[LogField]()
	metricBuilder := newMatchersBuilder[MetricField]()
	traceBuilder := newMatchersBuilder[TraceField]()

	for _, p := range policies {
		id := p.GetId()
		policyStats := stats[id]

		// Process log target
		if log := p.GetLog(); log != nil {
			idx := logBuilder.reservePolicy(id)

			keep, err := ParseKeep(log.GetKeep())
			if err != nil {
				return nil, fmt.Errorf("policy %s: %w", id, err)
			}

			var sampleKey *LogFieldRef
			if log.GetSampleKey() != nil {
				sk := FieldRefFromLogSampleKey(log.GetSampleKey())
				sampleKey = &sk
			}

			for i, m := range log.GetMatch() {
				ref := FieldRefFromLogMatcher(m)
				pattern, isExistence, mustExist := extractMatchPattern(m)
				logBuilder.addMatcher(ref, pattern, isExistence, mustExist, m.GetNegate(), m.GetCaseInsensitive(), id, idx, i)
			}

			logBuilder.finalizePolicy(id, idx, keep, len(log.GetMatch()), sampleKey, policyStats)
		}

		// Process metric target
		if metric := p.GetMetric(); metric != nil {
			idx := metricBuilder.reservePolicy(id)

			// Metrics use a simple bool keep for now
			keep := Keep{Action: KeepAll}
			if !metric.GetKeep() {
				keep = Keep{Action: KeepNone}
			}

			for i, m := range metric.GetMatch() {
				ref := FieldRefFromMetricMatcher(m)
				pattern, isExistence, mustExist := extractMetricMatchPattern(m)
				metricBuilder.addMatcher(ref, pattern, isExistence, mustExist, m.GetNegate(), m.GetCaseInsensitive(), id, idx, i)
			}

			metricBuilder.finalizePolicy(id, idx, keep, len(metric.GetMatch()), nil, policyStats)
		}

		// Process trace target
		if trace := p.GetTrace(); trace != nil {
			idx := traceBuilder.reservePolicy(id)

			// Traces have a TraceSamplingConfig - parse it
			keep, err := parseTraceSamplingConfig(trace.GetKeep())
			if err != nil {
				return nil, fmt.Errorf("policy %s: %w", id, err)
			}

			for i, m := range trace.GetMatch() {
				ref := FieldRefFromTraceMatcher(m)
				pattern, isExistence, mustExist := extractTraceMatchPattern(m)
				traceBuilder.addMatcher(ref, pattern, isExistence, mustExist, m.GetNegate(), m.GetCaseInsensitive(), id, idx, i)
			}

			traceBuilder.finalizePolicy(id, idx, keep, len(trace.GetMatch()), nil, policyStats)
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
	}, nil
}

// extractMatchPattern extracts the pattern string from a LogMatcher.
// Returns (pattern, isExistence, mustExist).
func extractMatchPattern(m *policyv1.LogMatcher) (string, bool, bool) {
	switch match := m.GetMatch().(type) {
	case *policyv1.LogMatcher_Regex:
		return match.Regex, false, false
	case *policyv1.LogMatcher_Exact:
		return escapeRegex(match.Exact), false, false
	case *policyv1.LogMatcher_StartsWith:
		return "^" + escapeRegex(match.StartsWith), false, false
	case *policyv1.LogMatcher_EndsWith:
		return escapeRegex(match.EndsWith) + "$", false, false
	case *policyv1.LogMatcher_Contains:
		return escapeRegex(match.Contains), false, false
	case *policyv1.LogMatcher_Exists:
		return "", true, match.Exists
	default:
		return "", false, false
	}
}

// extractMetricMatchPattern extracts the pattern string from a MetricMatcher.
func extractMetricMatchPattern(m *policyv1.MetricMatcher) (string, bool, bool) {
	switch match := m.GetMatch().(type) {
	case *policyv1.MetricMatcher_Regex:
		return match.Regex, false, false
	case *policyv1.MetricMatcher_Exact:
		return escapeRegex(match.Exact), false, false
	case *policyv1.MetricMatcher_StartsWith:
		return "^" + escapeRegex(match.StartsWith), false, false
	case *policyv1.MetricMatcher_EndsWith:
		return escapeRegex(match.EndsWith) + "$", false, false
	case *policyv1.MetricMatcher_Contains:
		return escapeRegex(match.Contains), false, false
	case *policyv1.MetricMatcher_Exists:
		return "", true, match.Exists
	default:
		return "", false, false
	}
}

// extractTraceMatchPattern extracts the pattern string from a TraceMatcher.
func extractTraceMatchPattern(m *policyv1.TraceMatcher) (string, bool, bool) {
	switch match := m.GetMatch().(type) {
	case *policyv1.TraceMatcher_Regex:
		return match.Regex, false, false
	case *policyv1.TraceMatcher_Exact:
		return escapeRegex(match.Exact), false, false
	case *policyv1.TraceMatcher_StartsWith:
		return "^" + escapeRegex(match.StartsWith), false, false
	case *policyv1.TraceMatcher_EndsWith:
		return escapeRegex(match.EndsWith) + "$", false, false
	case *policyv1.TraceMatcher_Contains:
		return escapeRegex(match.Contains), false, false
	case *policyv1.TraceMatcher_Exists:
		return "", true, match.Exists
	default:
		return "", false, false
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
		return Keep{Action: KeepAll}, nil
	}

	percentage := cfg.GetPercentage()
	if percentage >= 100 {
		return Keep{Action: KeepAll}, nil
	}
	if percentage <= 0 {
		return Keep{Action: KeepNone}, nil
	}

	return Keep{Action: KeepSample, Value: float64(percentage)}, nil
}
