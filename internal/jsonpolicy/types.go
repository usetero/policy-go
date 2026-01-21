// Package jsonpolicy handles JSON parsing of policy files.
package jsonpolicy

import "encoding/json"

// File represents the root of a policy JSON file.
type File struct {
	Policies []Policy `json:"policies"`
}

// Policy represents a single policy in JSON format.
type Policy struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Log  *Log   `json:"log,omitempty"`
	// Metric and Trace will be added later
}

// Log represents log policy configuration.
type Log struct {
	Match []LogMatcher `json:"match"`
	Keep  KeepValue    `json:"keep"`
}

// LogMatcher represents a single matcher for logs.
type LogMatcher struct {
	// One of these field selectors will be set
	LogField          string `json:"log_field,omitempty"`
	LogAttribute      string `json:"log_attribute,omitempty"`
	ResourceAttribute string `json:"resource_attribute,omitempty"`
	ScopeAttribute    string `json:"scope_attribute,omitempty"`

	// One of these match conditions will be set
	Regex  string `json:"regex,omitempty"`
	Exact  string `json:"exact,omitempty"`
	Exists *bool  `json:"exists,omitempty"`
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
