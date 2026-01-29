package policy

import (
	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
)

// AttrScope identifies the scope for attribute lookups.
type AttrScope int

const (
	// AttrScopeResource is for resource-level attributes.
	AttrScopeResource AttrScope = iota
	// AttrScopeScope is for instrumentation scope attributes.
	AttrScopeScope
	// AttrScopeRecord is for record-level attributes (log attributes, span attributes, datapoint attributes).
	AttrScopeRecord
	// AttrScopeEvent is for span event attributes (traces only).
	AttrScopeEvent
	// AttrScopeLink is for span link attributes (traces only).
	AttrScopeLink
)

// FieldEnum is a constraint for telemetry field enum types.
type FieldEnum interface {
	policyv1.LogField | policyv1.MetricField | policyv1.TraceField
}

// Matchable is the interface for telemetry records that can be matched against policies.
// The type parameter F specifies the field enum type (LogField, MetricField, or TraceField).
//
// Implementations should return field values without allocating new memory where possible.
// The returned byte slices should be views into existing data when possible to avoid
// allocations in the hot path.
type Matchable[F FieldEnum] interface {
	// GetField returns the value of the specified field.
	// Returns nil if the field doesn't exist or isn't applicable.
	GetField(field F) []byte

	// GetAttribute returns the value of an attribute at the specified scope and path.
	// Path is a slice of strings representing nested access (e.g., ["http", "method"]).
	// For single-segment paths, this is equivalent to a flat attribute lookup.
	// Returns nil if the attribute doesn't exist or any intermediate path segment is missing.
	//
	// For logs: AttrScopeRecord = log attributes
	// For traces: AttrScopeRecord = span attributes, AttrScopeEvent = event attributes
	// For metrics: AttrScopeRecord = datapoint attributes
	GetAttribute(scope AttrScope, path []string) []byte
}

// Type aliases for convenience.
type (
	LogMatchable    = Matchable[policyv1.LogField]
	MetricMatchable = Matchable[policyv1.MetricField]
	TraceMatchable  = Matchable[policyv1.TraceField]
)

// SimpleLogRecord is a simple implementation of LogMatchable for testing.
// Attribute maps support nested structures via map[string]any values.
type SimpleLogRecord struct {
	Body               []byte
	SeverityText       []byte
	TraceID            []byte
	SpanID             []byte
	EventName          []byte
	LogAttributes      map[string]any
	ResourceAttributes map[string]any
	ScopeAttributes    map[string]any
}

// GetField implements LogMatchable.
func (r *SimpleLogRecord) GetField(field policyv1.LogField) []byte {
	switch field {
	case policyv1.LogField_LOG_FIELD_BODY:
		return r.Body
	case policyv1.LogField_LOG_FIELD_SEVERITY_TEXT:
		return r.SeverityText
	case policyv1.LogField_LOG_FIELD_TRACE_ID:
		return r.TraceID
	case policyv1.LogField_LOG_FIELD_SPAN_ID:
		return r.SpanID
	case policyv1.LogField_LOG_FIELD_EVENT_NAME:
		return r.EventName
	default:
		return nil
	}
}

// GetAttribute implements LogMatchable with path traversal support.
func (r *SimpleLogRecord) GetAttribute(scope AttrScope, path []string) []byte {
	var attrs map[string]any
	switch scope {
	case AttrScopeResource:
		attrs = r.ResourceAttributes
	case AttrScopeScope:
		attrs = r.ScopeAttributes
	case AttrScopeRecord:
		attrs = r.LogAttributes
	default:
		return nil
	}
	return traversePath(attrs, path)
}

// traversePath navigates through nested maps following the path segments.
func traversePath(m map[string]any, path []string) []byte {
	if len(path) == 0 || m == nil {
		return nil
	}

	val, ok := m[path[0]]
	if !ok {
		return nil
	}

	// If this is the last segment, return the value
	if len(path) == 1 {
		return toBytes(val)
	}

	// Otherwise, recurse into nested map
	nested, ok := val.(map[string]any)
	if !ok {
		return nil
	}
	return traversePath(nested, path[1:])
}

// toBytes converts a value to bytes for matching.
func toBytes(val any) []byte {
	switch v := val.(type) {
	case []byte:
		return v
	case string:
		return []byte(v)
	default:
		return nil
	}
}
