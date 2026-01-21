package engine

import "sync/atomic"

// LogField represents the type of field to match in a log record.
type LogField int

const (
	LogFieldBody LogField = iota
	LogFieldSeverityText
	LogFieldSeverityNumber
	LogFieldTimestamp
	LogFieldTraceID
	LogFieldSpanID
)

// FieldType identifies the category of field.
type FieldType int

const (
	FieldTypeLogField FieldType = iota
	FieldTypeLogAttribute
	FieldTypeResourceAttribute
	FieldTypeScopeAttribute
)

// FieldSelector identifies a specific field to match against.
type FieldSelector struct {
	Type  FieldType
	Field LogField
	Key   string
}

// KeepAction represents what to do with matched telemetry.
type KeepAction int

const (
	KeepAll KeepAction = iota
	KeepNone
	KeepSample
	KeepRatePerSecond
	KeepRatePerMinute
)

// Keep represents a compiled keep action with its parameters.
type Keep struct {
	Action KeepAction
	Value  float64
}

// Restrictiveness returns a score indicating how restrictive this keep action is.
func (k Keep) Restrictiveness() int {
	switch k.Action {
	case KeepNone:
		return 1000
	case KeepSample:
		return int(1000 - k.Value*10)
	case KeepRatePerSecond, KeepRatePerMinute:
		return 500
	case KeepAll:
		return 0
	default:
		return 0
	}
}

// PolicyStats holds atomic counters for a single policy.
type PolicyStats struct {
	Hits        atomic.Uint64
	Misses      atomic.Uint64
	Drops       atomic.Uint64
	Samples     atomic.Uint64
	RateLimited atomic.Uint64
	Transforms  atomic.Uint64
}

// RecordHit increments the hit counter.
func (s *PolicyStats) RecordHit() {
	s.Hits.Add(1)
}

// RecordDrop increments the drop counter.
func (s *PolicyStats) RecordDrop() {
	s.Drops.Add(1)
}

// RecordSample increments the sample counter.
func (s *PolicyStats) RecordSample() {
	s.Samples.Add(1)
}

// RecordRateLimited increments the rate limited counter.
func (s *PolicyStats) RecordRateLimited() {
	s.RateLimited.Add(1)
}

// PolicyStatsSnapshot is an immutable copy of stats for reporting.
type PolicyStatsSnapshot struct {
	PolicyID    string
	Hits        uint64
	Misses      uint64
	Drops       uint64
	Samples     uint64
	RateLimited uint64
	Transforms  uint64
}

// Snapshot creates an immutable snapshot of the current stats.
func (s *PolicyStats) Snapshot(policyID string) PolicyStatsSnapshot {
	return PolicyStatsSnapshot{
		PolicyID:    policyID,
		Hits:        s.Hits.Load(),
		Misses:      s.Misses.Load(),
		Drops:       s.Drops.Load(),
		Samples:     s.Samples.Load(),
		RateLimited: s.RateLimited.Load(),
		Transforms:  s.Transforms.Load(),
	}
}

// Matcher represents a single match condition.
type Matcher struct {
	Field   FieldSelector
	Pattern string
	Negated bool
	Exists  *bool
}

// LogPolicy represents policy configuration for log records.
type LogPolicy struct {
	Matchers []Matcher
	Keep     Keep
}

// Policy represents a parsed and validated policy.
type Policy struct {
	ID   string
	Name string
	Log  *LogPolicy
}

// IsLogPolicy returns true if this policy applies to logs.
func (p *Policy) IsLogPolicy() bool {
	return p.Log != nil
}
