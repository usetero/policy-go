// Package jsonpolicy handles JSON parsing of policy files.
package jsonpolicy

import "encoding/json"

// File represents the root of a policy JSON file.
type File struct {
	Policies []Policy `json:"policies"`
}

// Policy represents a single policy in JSON format.
type Policy struct {
	ID      string  `json:"id"`
	Name    string  `json:"name"`
	Enabled *bool   `json:"enabled,omitempty"`
	Log     *Log    `json:"log,omitempty"`
	Metric  *Metric `json:"metric,omitempty"`
	Trace   *Trace  `json:"trace,omitempty"`
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
	Regex             *string        `json:"regex,omitempty"`
}

// LogRename specifies a field to rename.
type LogRename struct {
	LogField          string         `json:"from_log_field,omitempty"`
	LogAttribute      *AttributePath `json:"from_log_attribute,omitempty"`
	ResourceAttribute *AttributePath `json:"from_resource_attribute,omitempty"`
	ScopeAttribute    *AttributePath `json:"from_scope_attribute,omitempty"`
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
	Regex      string               `json:"regex,omitempty"`
	Exact      string               `json:"exact,omitempty"`
	Exists     *bool                `json:"exists,omitempty"`
	StartsWith string               `json:"starts_with,omitempty"`
	EndsWith   string               `json:"ends_with,omitempty"`
	Contains   string               `json:"contains,omitempty"`
	Equals     *MatcherValue        `json:"equals,omitempty"`
	Gt         *MatcherNumericValue `json:"gt,omitempty"`
	Gte        *MatcherNumericValue `json:"gte,omitempty"`
	Lt         *MatcherNumericValue `json:"lt,omitempty"`
	Lte        *MatcherNumericValue `json:"lte,omitempty"`

	// Flags
	Negate          bool `json:"negate,omitempty"`
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
	Regex      string               `json:"regex,omitempty"`
	Exact      string               `json:"exact,omitempty"`
	Exists     *bool                `json:"exists,omitempty"`
	StartsWith string               `json:"starts_with,omitempty"`
	EndsWith   string               `json:"ends_with,omitempty"`
	Contains   string               `json:"contains,omitempty"`
	Equals     *MatcherValue        `json:"equals,omitempty"`
	Gt         *MatcherNumericValue `json:"gt,omitempty"`
	Gte        *MatcherNumericValue `json:"gte,omitempty"`
	Lt         *MatcherNumericValue `json:"lt,omitempty"`
	Lte        *MatcherNumericValue `json:"lte,omitempty"`

	// Flags
	Negate          bool `json:"negate,omitempty"`
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
	Regex      string               `json:"regex,omitempty"`
	Exact      string               `json:"exact,omitempty"`
	Exists     *bool                `json:"exists,omitempty"`
	StartsWith string               `json:"starts_with,omitempty"`
	EndsWith   string               `json:"ends_with,omitempty"`
	Contains   string               `json:"contains,omitempty"`
	Equals     *MatcherValue        `json:"equals,omitempty"`
	Gt         *MatcherNumericValue `json:"gt,omitempty"`
	Gte        *MatcherNumericValue `json:"gte,omitempty"`
	Lt         *MatcherNumericValue `json:"lt,omitempty"`
	Lte        *MatcherNumericValue `json:"lte,omitempty"`

	// Flags
	Negate          bool `json:"negate,omitempty"`
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

// MatcherValueKind discriminates the variants of MatcherValue.
type MatcherValueKind uint8

const (
	MatcherValueUnset MatcherValueKind = iota
	MatcherValueBool
	MatcherValueInt
	MatcherValueDouble
	MatcherValueBytes
	MatcherValueHex
)

// MatcherValue is the parsed `equals` literal. Accepts both shorthand (true,
// 200, 0.5) and canonical proto form ({bool_value, int_value, double_value,
// bytes_value, hex_value}). A bare string literal is rejected per the spec —
// use `exact` for strings. Only one field is populated based on Kind.
type MatcherValue struct {
	Kind   MatcherValueKind
	Bool   bool
	Int    int64
	Double float64
	Bytes  []byte
	Hex    string
}

// UnmarshalJSON implements polymorphic unmarshaling. Shorthand: true/false →
// bool, integer literal → int, fractional literal → double. Canonical: an
// object with exactly one of {bool_value, int_value, double_value,
// bytes_value, hex_value}. A string literal is rejected.
func (v *MatcherValue) UnmarshalJSON(data []byte) error {
	if len(data) == 0 {
		return NewParseError("equals", "empty value")
	}
	switch data[0] {
	case 't', 'f':
		var b bool
		if err := json.Unmarshal(data, &b); err == nil {
			v.Kind, v.Bool = MatcherValueBool, b
			return nil
		}
	case '"':
		return NewParseError("equals", "string literal not allowed — use exact for strings")
	case '{':
		return v.unmarshalCanonical(data)
	}
	// Numeric: prefer int when the literal has no fractional part or exponent.
	if isIntegerJSON(data) {
		var n int64
		if err := json.Unmarshal(data, &n); err == nil {
			v.Kind, v.Int = MatcherValueInt, n
			return nil
		}
	}
	var d float64
	if err := json.Unmarshal(data, &d); err == nil {
		v.Kind, v.Double = MatcherValueDouble, d
		return nil
	}
	return NewParseError("equals", "must be bool, int, double, or {bool_value|int_value|double_value|bytes_value|hex_value}")
}

func (v *MatcherValue) unmarshalCanonical(data []byte) error {
	var raw struct {
		BoolValue   *bool    `json:"bool_value,omitempty"`
		IntValue    *int64   `json:"int_value,omitempty"`
		DoubleValue *float64 `json:"double_value,omitempty"`
		BytesValue  []byte   `json:"bytes_value,omitempty"`
		HexValue    *string  `json:"hex_value,omitempty"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return NewParseError("equals", "invalid canonical Value: "+err.Error())
	}
	count := 0
	if raw.BoolValue != nil {
		count++
	}
	if raw.IntValue != nil {
		count++
	}
	if raw.DoubleValue != nil {
		count++
	}
	if raw.BytesValue != nil {
		count++
	}
	if raw.HexValue != nil {
		count++
	}
	if count == 0 {
		return NewParseError("equals", "canonical Value must set exactly one variant")
	}
	if count > 1 {
		return NewParseError("equals", "canonical Value must set exactly one variant")
	}
	switch {
	case raw.BoolValue != nil:
		v.Kind, v.Bool = MatcherValueBool, *raw.BoolValue
	case raw.IntValue != nil:
		v.Kind, v.Int = MatcherValueInt, *raw.IntValue
	case raw.DoubleValue != nil:
		v.Kind, v.Double = MatcherValueDouble, *raw.DoubleValue
	case raw.BytesValue != nil:
		v.Kind, v.Bytes = MatcherValueBytes, raw.BytesValue
	case raw.HexValue != nil:
		v.Kind, v.Hex = MatcherValueHex, *raw.HexValue
	}
	return nil
}

// MatcherNumericValue is the parsed gt/gte/lt/lte literal. Accepts shorthand
// (integer → int, fractional → double) and canonical ({int_value} or
// {double_value}). Bool, bytes, hex, and string are rejected — the schema
// admits only numbers.
type MatcherNumericValue struct {
	Kind   MatcherValueKind // MatcherValueInt or MatcherValueDouble
	Int    int64
	Double float64
}

func (v *MatcherNumericValue) UnmarshalJSON(data []byte) error {
	if len(data) == 0 {
		return NewParseError("numeric_value", "empty value")
	}
	switch data[0] {
	case 't', 'f':
		return NewParseError("numeric_value", "bool literal not allowed in numeric comparison")
	case '"':
		return NewParseError("numeric_value", "string literal not allowed in numeric comparison")
	case '{':
		return v.unmarshalCanonical(data)
	}
	if isIntegerJSON(data) {
		var n int64
		if err := json.Unmarshal(data, &n); err == nil {
			v.Kind, v.Int = MatcherValueInt, n
			return nil
		}
	}
	var d float64
	if err := json.Unmarshal(data, &d); err == nil {
		v.Kind, v.Double = MatcherValueDouble, d
		return nil
	}
	return NewParseError("numeric_value", "must be int, double, or {int_value|double_value}")
}

func (v *MatcherNumericValue) unmarshalCanonical(data []byte) error {
	var raw struct {
		IntValue    *int64   `json:"int_value,omitempty"`
		DoubleValue *float64 `json:"double_value,omitempty"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return NewParseError("numeric_value", "invalid canonical NumericValue: "+err.Error())
	}
	count := 0
	if raw.IntValue != nil {
		count++
	}
	if raw.DoubleValue != nil {
		count++
	}
	if count != 1 {
		return NewParseError("numeric_value", "canonical NumericValue must set exactly one variant")
	}
	if raw.IntValue != nil {
		v.Kind, v.Int = MatcherValueInt, *raw.IntValue
	} else {
		v.Kind, v.Double = MatcherValueDouble, *raw.DoubleValue
	}
	return nil
}

// isIntegerJSON reports whether the JSON-encoded numeric literal in data has
// no decimal point or exponent and so should be unmarshaled as int rather
// than double. Drives the type selection for shorthand literals.
func isIntegerJSON(data []byte) bool {
	for _, b := range data {
		if b == '.' || b == 'e' || b == 'E' {
			return false
		}
	}
	return true
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
