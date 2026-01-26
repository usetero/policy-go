package policy

import (
	"github.com/usetero/policy-go/internal/engine"
	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
)

// Matchable is the interface for telemetry records that can be matched against policies.
// Implementations should return field values without allocating new memory where possible.
type Matchable interface {
	// GetField returns the value of the specified field.
	// Returns nil if the field doesn't exist or isn't applicable.
	// The returned slice should be a view into existing data when possible
	// to avoid allocations in the hot path.
	GetField(selector engine.LogFieldSelector) []byte
}

// SimpleLogRecord is a simple implementation of Matchable for testing.
type SimpleLogRecord struct {
	BodyValue          []byte
	SeverityTextValue  []byte
	TraceIDValue       []byte
	SpanIDValue        []byte
	EventNameValue     []byte
	LogAttributes      map[string][]byte
	ResourceAttributes map[string][]byte
	ScopeAttributes    map[string][]byte
}

// GetField implements Matchable.
func (r *SimpleLogRecord) GetField(selector engine.LogFieldSelector) []byte {
	// Check simple log fields first
	if selector.LogField != policyv1.LogField_LOG_FIELD_UNSPECIFIED {
		switch selector.LogField {
		case policyv1.LogField_LOG_FIELD_BODY:
			return r.BodyValue
		case policyv1.LogField_LOG_FIELD_SEVERITY_TEXT:
			return r.SeverityTextValue
		case policyv1.LogField_LOG_FIELD_TRACE_ID:
			return r.TraceIDValue
		case policyv1.LogField_LOG_FIELD_SPAN_ID:
			return r.SpanIDValue
		case policyv1.LogField_LOG_FIELD_EVENT_NAME:
			return r.EventNameValue
		default:
			return nil
		}
	}

	// Check attribute selectors
	if selector.LogAttribute != "" {
		if r.LogAttributes == nil {
			return nil
		}
		return r.LogAttributes[selector.LogAttribute]
	}

	if selector.ResourceAttribute != "" {
		if r.ResourceAttributes == nil {
			return nil
		}
		return r.ResourceAttributes[selector.ResourceAttribute]
	}

	if selector.ScopeAttribute != "" {
		if r.ScopeAttributes == nil {
			return nil
		}
		return r.ScopeAttributes[selector.ScopeAttribute]
	}

	return nil
}
