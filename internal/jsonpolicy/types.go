// Package jsonpolicy handles JSON parsing of policy files.
package jsonpolicy

import "encoding/json"

// File represents the root of a policy JSON file.
type File struct {
	Policies []Policy `json:"policies"`
}

// Policy represents a single policy in JSON format.
type Policy struct {
	ID     string  `json:"id"`
	Name   string  `json:"name"`
	Log    *Log    `json:"log,omitempty"`
	Metric *Metric `json:"metric,omitempty"`
	Trace  *Trace  `json:"trace,omitempty"`
}

// Log represents log policy configuration.
type Log struct {
	Match     []LogMatcher  `json:"match"`
	Keep      KeepValue     `json:"keep"`
	SampleKey *SampleKey    `json:"sample_key,omitempty"`
	Transform *LogTransform `json:"transform,omitempty"`
}

// LogTransform defines modifications to apply to matched logs.
type LogTransform struct {
	Remove []LogRemove `json:"remove,omitempty"`
	Redact []LogRedact `json:"redact,omitempty"`
	Rename []LogRename `json:"rename,omitempty"`
	Add    []LogAdd    `json:"add,omitempty"`
}

// LogRemove specifies a field to remove.
type LogRemove struct {
	LogField          string         `json:"log_field,omitempty"`
	LogAttribute      *AttributePath `json:"log_attribute,omitempty"`
	ResourceAttribute *AttributePath `json:"resource_attribute,omitempty"`
	ScopeAttribute    *AttributePath `json:"scope_attribute,omitempty"`
}

// LogRedact specifies a field to redact.
type LogRedact struct {
	LogField          string         `json:"log_field,omitempty"`
	LogAttribute      *AttributePath `json:"log_attribute,omitempty"`
	ResourceAttribute *AttributePath `json:"resource_attribute,omitempty"`
	ScopeAttribute    *AttributePath `json:"scope_attribute,omitempty"`
	Replacement       string         `json:"replacement"`
}

// LogRename specifies a field to rename.
type LogRename struct {
	LogField          string         `json:"log_field,omitempty"`
	LogAttribute      *AttributePath `json:"log_attribute,omitempty"`
	ResourceAttribute *AttributePath `json:"resource_attribute,omitempty"`
	ScopeAttribute    *AttributePath `json:"scope_attribute,omitempty"`
	To                string         `json:"to"`
	Upsert            bool           `json:"upsert,omitempty"`
}

// LogAdd specifies a field to add.
type LogAdd struct {
	LogField          string         `json:"log_field,omitempty"`
	LogAttribute      *AttributePath `json:"log_attribute,omitempty"`
	ResourceAttribute *AttributePath `json:"resource_attribute,omitempty"`
	ScopeAttribute    *AttributePath `json:"scope_attribute,omitempty"`
	Value             string         `json:"value"`
	Upsert            bool           `json:"upsert,omitempty"`
}

// Metric represents metric policy configuration.
type Metric struct {
	Match []MetricMatcher `json:"match"`
	Keep  bool            `json:"keep"`
}

// MetricMatcher represents a single matcher for metrics.
type MetricMatcher struct {
	// Field selectors
	MetricField            string         `json:"metric_field,omitempty"`
	DatapointAttribute     *AttributePath `json:"datapoint_attribute,omitempty"`
	ResourceAttribute      *AttributePath `json:"resource_attribute,omitempty"`
	ScopeAttribute         *AttributePath `json:"scope_attribute,omitempty"`
	MetricType             string         `json:"metric_type,omitempty"`
	AggregationTemporality string         `json:"aggregation_temporality,omitempty"`

	// Match conditions
	Regex      string `json:"regex,omitempty"`
	Exact      string `json:"exact,omitempty"`
	Exists     *bool  `json:"exists,omitempty"`
	StartsWith string `json:"starts_with,omitempty"`
	EndsWith   string `json:"ends_with,omitempty"`
	Contains   string `json:"contains,omitempty"`

	// Flags
	Negated         bool `json:"negated,omitempty"`
	CaseInsensitive bool `json:"case_insensitive,omitempty"`
}

// Trace represents trace policy configuration.
type Trace struct {
	Match []TraceMatcher `json:"match"`
	Keep  *TraceKeep     `json:"keep,omitempty"`
}

// TraceKeep represents trace sampling configuration.
type TraceKeep struct {
	Percentage        float32 `json:"percentage"`
	Mode              string  `json:"mode,omitempty"`
	SamplingPrecision *uint32 `json:"sampling_precision,omitempty"`
	HashSeed          *uint32 `json:"hash_seed,omitempty"`
	FailClosed        *bool   `json:"fail_closed,omitempty"`
}

// TraceMatcher represents a single matcher for traces.
type TraceMatcher struct {
	// Field selectors
	TraceField        string         `json:"trace_field,omitempty"`
	SpanAttribute     *AttributePath `json:"span_attribute,omitempty"`
	ResourceAttribute *AttributePath `json:"resource_attribute,omitempty"`
	ScopeAttribute    *AttributePath `json:"scope_attribute,omitempty"`
	SpanKind          string         `json:"span_kind,omitempty"`
	SpanStatus        string         `json:"span_status,omitempty"`
	EventName         string         `json:"event_name,omitempty"`
	EventAttribute    *AttributePath `json:"event_attribute,omitempty"`
	LinkTraceID       string         `json:"link_trace_id,omitempty"`

	// Match conditions
	Regex      string `json:"regex,omitempty"`
	Exact      string `json:"exact,omitempty"`
	Exists     *bool  `json:"exists,omitempty"`
	StartsWith string `json:"starts_with,omitempty"`
	EndsWith   string `json:"ends_with,omitempty"`
	Contains   string `json:"contains,omitempty"`

	// Flags
	Negated         bool `json:"negated,omitempty"`
	CaseInsensitive bool `json:"case_insensitive,omitempty"`
}

// AttributePath represents an attribute path that can be specified in multiple ways.
// It handles unmarshaling from:
// 1. Canonical form: {"path": ["http", "method"]}
// 2. Shorthand array: ["http", "method"]
// 3. Shorthand string (single segment): "user_id"
type AttributePath struct {
	Path []string
}

// UnmarshalJSON implements custom unmarshaling for AttributePath.
func (a *AttributePath) UnmarshalJSON(data []byte) error {
	// Try canonical form first: {"path": [...]}
	var canonical struct {
		Path []string `json:"path"`
	}
	if err := json.Unmarshal(data, &canonical); err == nil && len(canonical.Path) > 0 {
		a.Path = canonical.Path
		return nil
	}

	// Try shorthand array: [...]
	var arr []string
	if err := json.Unmarshal(data, &arr); err == nil && len(arr) > 0 {
		a.Path = arr
		return nil
	}

	// Try shorthand string: "name"
	var str string
	if err := json.Unmarshal(data, &str); err == nil && str != "" {
		a.Path = []string{str}
		return nil
	}

	return NewParseError("attribute_path", "must be object with path, array, or string")
}

// LogMatcher represents a single matcher for logs.
type LogMatcher struct {
	// Field selectors - use AttributePath for flexible input
	LogField          string         `json:"log_field,omitempty"`
	LogAttribute      *AttributePath `json:"log_attribute,omitempty"`
	ResourceAttribute *AttributePath `json:"resource_attribute,omitempty"`
	ScopeAttribute    *AttributePath `json:"scope_attribute,omitempty"`

	// Match conditions
	Regex      string `json:"regex,omitempty"`
	Exact      string `json:"exact,omitempty"`
	Exists     *bool  `json:"exists,omitempty"`
	StartsWith string `json:"starts_with,omitempty"`
	EndsWith   string `json:"ends_with,omitempty"`
	Contains   string `json:"contains,omitempty"`

	// Flags
	Negated         bool `json:"negated,omitempty"`
	CaseInsensitive bool `json:"case_insensitive,omitempty"`
}

// SampleKey represents the field to use for consistent sampling.
type SampleKey struct {
	LogField          string         `json:"log_field,omitempty"`
	LogAttribute      *AttributePath `json:"log_attribute,omitempty"`
	ResourceAttribute *AttributePath `json:"resource_attribute,omitempty"`
	ScopeAttribute    *AttributePath `json:"scope_attribute,omitempty"`
}

// KeepValue handles the polymorphic "keep" field which can be:
// - string: "all", "none"
// - bool: true (all), false (none)
// - object: { "percentage": N, ... } for sampling
type KeepValue struct {
	StringValue *string
	BoolValue   *bool
	SampleValue *SampleKeep
}

// SampleKeep represents sampling configuration.
type SampleKeep struct {
	Percentage        float64 `json:"percentage"`
	Mode              string  `json:"mode,omitempty"`
	SamplingPrecision int     `json:"sampling_precision,omitempty"`
	HashSeed          int64   `json:"hash_seed,omitempty"`
}

// UnmarshalJSON implements custom unmarshaling for KeepValue.
func (k *KeepValue) UnmarshalJSON(data []byte) error {
	// Try string first
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		k.StringValue = &s
		return nil
	}

	// Try bool
	var b bool
	if err := json.Unmarshal(data, &b); err == nil {
		k.BoolValue = &b
		return nil
	}

	// Try object (sampling)
	var sample SampleKeep
	if err := json.Unmarshal(data, &sample); err == nil {
		k.SampleValue = &sample
		return nil
	}

	return NewParseError("keep", "must be string, bool, or object")
}

// ParseError represents a JSON parsing error.
type ParseError struct {
	Field   string
	Message string
}

func (e *ParseError) Error() string {
	return "parse error in " + e.Field + ": " + e.Message
}

// NewParseError creates a new ParseError.
func NewParseError(field, message string) *ParseError {
	return &ParseError{Field: field, Message: message}
}
