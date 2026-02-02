package policy

import (
	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
)

// SimpleLogRecord is a simple implementation for testing that works with LogMatchFunc.
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

// SimpleLogMatcher is a LogMatchFunc implementation for SimpleLogRecord.
func SimpleLogMatcher(r *SimpleLogRecord, ref LogFieldRef) []byte {
	if ref.IsField() {
		switch ref.Field() {
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

	// Attribute lookup
	var attrs map[string]any
	switch {
	case ref.IsRecordAttr():
		attrs = r.LogAttributes
	case ref.IsResourceAttr():
		attrs = r.ResourceAttributes
	case ref.IsScopeAttr():
		attrs = r.ScopeAttributes
	default:
		return nil
	}
	return traversePath(attrs, ref.Path())
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
