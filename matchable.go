package policy

// ============================================================================
// LOG RECORDS
// ============================================================================

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
		switch ref.Field {
		case LogFieldBody:
			return r.Body
		case LogFieldSeverityText:
			return r.SeverityText
		case LogFieldTraceID:
			return r.TraceID
		case LogFieldSpanID:
			return r.SpanID
		case LogFieldEventName:
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
	return traversePath(attrs, ref.AttrPath)
}

// ============================================================================
// METRIC RECORDS
// ============================================================================

// SimpleMetricRecord is a simple implementation for testing that works with MetricMatchFunc.
// Attribute maps support nested structures via map[string]any values.
type SimpleMetricRecord struct {
	Name                   []byte
	Description            []byte
	Unit                   []byte
	Type                   []byte // e.g., "gauge", "sum", "histogram"
	AggregationTemporality []byte // e.g., "delta", "cumulative"
	DatapointAttributes    map[string]any
	ResourceAttributes     map[string]any
	ScopeAttributes        map[string]any
}

// SimpleMetricMatcher is a MetricMatchFunc implementation for SimpleMetricRecord.
func SimpleMetricMatcher(r *SimpleMetricRecord, ref MetricFieldRef) []byte {
	if ref.IsField() {
		switch ref.Field {
		case MetricFieldName:
			return r.Name
		case MetricFieldDescription:
			return r.Description
		case MetricFieldUnit:
			return r.Unit
		case MetricFieldType:
			return r.Type
		case MetricFieldAggregationTemporality:
			return r.AggregationTemporality
		default:
			return nil
		}
	}

	// Attribute lookup
	var attrs map[string]any
	switch {
	case ref.IsRecordAttr():
		attrs = r.DatapointAttributes
	case ref.IsResourceAttr():
		attrs = r.ResourceAttributes
	case ref.IsScopeAttr():
		attrs = r.ScopeAttributes
	default:
		return nil
	}
	return traversePath(attrs, ref.AttrPath)
}

// ============================================================================
// TRACE/SPAN RECORDS
// ============================================================================

// SimpleSpanRecord is a simple implementation for testing that works with TraceMatchFunc.
// Attribute maps support nested structures via map[string]any values.
type SimpleSpanRecord struct {
	Name               []byte
	TraceID            []byte
	SpanID             []byte
	ParentSpanID       []byte
	TraceState         []byte
	Kind               []byte // e.g., "server", "client", "internal"
	Status             []byte // e.g., "ok", "error", "unset"
	EventNames         [][]byte
	EventAttributes    []map[string]any
	LinkTraceIDs       [][]byte
	LinkAttributes     []map[string]any
	SpanAttributes     map[string]any
	ResourceAttributes map[string]any
	ScopeAttributes    map[string]any
}

// SimpleSpanMatcher is a TraceMatchFunc implementation for SimpleSpanRecord.
func SimpleSpanMatcher(r *SimpleSpanRecord, ref TraceFieldRef) []byte {
	if ref.IsField() {
		switch ref.Field {
		case TraceFieldName:
			return r.Name
		case TraceFieldTraceID:
			return r.TraceID
		case TraceFieldSpanID:
			return r.SpanID
		case TraceFieldParentSpanID:
			return r.ParentSpanID
		case TraceFieldTraceState:
			return r.TraceState
		case TraceFieldKind:
			return r.Kind
		case TraceFieldStatus:
			return r.Status
		case TraceFieldEventName:
			// Return first event name if available
			if len(r.EventNames) > 0 {
				return r.EventNames[0]
			}
			return nil
		case TraceFieldLinkTraceID:
			// Return first link trace ID if available
			if len(r.LinkTraceIDs) > 0 {
				return r.LinkTraceIDs[0]
			}
			return nil
		default:
			return nil
		}
	}

	// Attribute lookup
	var attrs map[string]any
	switch {
	case ref.IsRecordAttr():
		attrs = r.SpanAttributes
	case ref.IsResourceAttr():
		attrs = r.ResourceAttributes
	case ref.IsScopeAttr():
		attrs = r.ScopeAttributes
	case ref.IsEventAttr():
		// Return first event's attribute if available
		if len(r.EventAttributes) > 0 {
			attrs = r.EventAttributes[0]
		}
	case ref.IsLinkAttr():
		// Return first link's attribute if available
		if len(r.LinkAttributes) > 0 {
			attrs = r.LinkAttributes[0]
		}
	default:
		return nil
	}
	return traversePath(attrs, ref.AttrPath)
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
