package policy

import "github.com/usetero/policy-go/internal/engine"

// Re-export types from internal/engine.
type (
	LogField      = engine.LogField
	FieldType     = engine.FieldType
	FieldSelector = engine.FieldSelector
)

// LogField constants.
const (
	LogFieldBody           = engine.LogFieldBody
	LogFieldSeverityText   = engine.LogFieldSeverityText
	LogFieldSeverityNumber = engine.LogFieldSeverityNumber
	LogFieldTimestamp      = engine.LogFieldTimestamp
	LogFieldTraceID        = engine.LogFieldTraceID
	LogFieldSpanID         = engine.LogFieldSpanID
)

// FieldType constants.
const (
	FieldTypeLogField          = engine.FieldTypeLogField
	FieldTypeLogAttribute      = engine.FieldTypeLogAttribute
	FieldTypeResourceAttribute = engine.FieldTypeResourceAttribute
	FieldTypeScopeAttribute    = engine.FieldTypeScopeAttribute
)

// ParseLogField parses a string into a LogField.
func ParseLogField(s string) (LogField, bool) {
	switch s {
	case "body":
		return LogFieldBody, true
	case "severity_text":
		return LogFieldSeverityText, true
	case "severity_number":
		return LogFieldSeverityNumber, true
	case "timestamp":
		return LogFieldTimestamp, true
	case "trace_id":
		return LogFieldTraceID, true
	case "span_id":
		return LogFieldSpanID, true
	default:
		return 0, false
	}
}

// NewLogFieldSelector creates a selector for a log field.
func NewLogFieldSelector(field LogField) FieldSelector {
	return FieldSelector{Type: FieldTypeLogField, Field: field}
}

// NewLogAttributeSelector creates a selector for a log attribute.
func NewLogAttributeSelector(key string) FieldSelector {
	return FieldSelector{Type: FieldTypeLogAttribute, Key: key}
}

// NewResourceAttributeSelector creates a selector for a resource attribute.
func NewResourceAttributeSelector(key string) FieldSelector {
	return FieldSelector{Type: FieldTypeResourceAttribute, Key: key}
}

// NewScopeAttributeSelector creates a selector for a scope attribute.
func NewScopeAttributeSelector(key string) FieldSelector {
	return FieldSelector{Type: FieldTypeScopeAttribute, Key: key}
}
