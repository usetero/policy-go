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

	// GetAttribute returns the value of an attribute at the specified scope.
	// For logs: AttrScopeRecord = log attributes
	// For traces: AttrScopeRecord = span attributes, AttrScopeEvent = event attributes
	// For metrics: AttrScopeRecord = datapoint attributes
	// Returns nil if the attribute doesn't exist.
	GetAttribute(scope AttrScope, name string) []byte
}

// Type aliases for convenience.
type (
	LogMatchable    = Matchable[policyv1.LogField]
	MetricMatchable = Matchable[policyv1.MetricField]
	TraceMatchable  = Matchable[policyv1.TraceField]
)

// SimpleLogRecord is a simple implementation of LogMatchable for testing.
type SimpleLogRecord struct {
	Body               []byte
	SeverityText       []byte
	TraceID            []byte
	SpanID             []byte
	EventName          []byte
	LogAttributes      map[string][]byte
	ResourceAttributes map[string][]byte
	ScopeAttributes    map[string][]byte
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

// GetAttribute implements LogMatchable.
func (r *SimpleLogRecord) GetAttribute(scope AttrScope, name string) []byte {
	switch scope {
	case AttrScopeResource:
		if r.ResourceAttributes == nil {
			return nil
		}
		return r.ResourceAttributes[name]
	case AttrScopeScope:
		if r.ScopeAttributes == nil {
			return nil
		}
		return r.ScopeAttributes[name]
	case AttrScopeRecord:
		if r.LogAttributes == nil {
			return nil
		}
		return r.LogAttributes[name]
	default:
		return nil
	}
}
