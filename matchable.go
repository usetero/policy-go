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

// SimpleLogTransformer is a LogTransformFunc implementation for SimpleLogRecord.
// It applies transform operations by mutating the record in place.
func SimpleLogTransformer(r *SimpleLogRecord, op TransformOp) {
	switch op.Kind {
	case TransformRemove:
		simpleLogRemove(r, op.Ref)
	case TransformRedact:
		simpleLogRedact(r, op.Ref, op.Value)
	case TransformRename:
		simpleLogRename(r, op.Ref, op.To, op.Upsert)
	case TransformAdd:
		simpleLogAdd(r, op.Ref, op.Value, op.Upsert)
	}
}

func simpleLogRemove(r *SimpleLogRecord, ref LogFieldRef) {
	if ref.IsField() {
		switch ref.Field {
		case LogFieldBody:
			r.Body = nil
		case LogFieldSeverityText:
			r.SeverityText = nil
		case LogFieldTraceID:
			r.TraceID = nil
		case LogFieldSpanID:
			r.SpanID = nil
		case LogFieldEventName:
			r.EventName = nil
		}
		return
	}
	if attrs := simpleLogAttrs(r, ref); attrs != nil {
		deletePath(attrs, ref.AttrPath)
	}
}

func simpleLogRedact(r *SimpleLogRecord, ref LogFieldRef, replacement string) {
	val := []byte(replacement)
	if ref.IsField() {
		switch ref.Field {
		case LogFieldBody:
			r.Body = val
		case LogFieldSeverityText:
			r.SeverityText = val
		case LogFieldTraceID:
			r.TraceID = val
		case LogFieldSpanID:
			r.SpanID = val
		case LogFieldEventName:
			r.EventName = val
		}
		return
	}
	if attrs := simpleLogAttrs(r, ref); attrs != nil {
		setPath(attrs, ref.AttrPath, replacement)
	}
}

func simpleLogRename(r *SimpleLogRecord, ref LogFieldRef, to string, upsert bool) {
	if ref.IsField() {
		// Renaming a fixed field to an attribute: read value, remove field, set attr
		return
	}
	attrs := simpleLogAttrs(r, ref)
	if attrs == nil {
		return
	}
	val, ok := getPath(attrs, ref.AttrPath)
	if !ok {
		return
	}
	if !upsert {
		if _, exists := attrs[to]; exists {
			return
		}
	}
	deletePath(attrs, ref.AttrPath)
	attrs[to] = val
}

func simpleLogAdd(r *SimpleLogRecord, ref LogFieldRef, value string, upsert bool) {
	if ref.IsField() {
		val := []byte(value)
		if !upsert {
			switch ref.Field {
			case LogFieldBody:
				if r.Body != nil {
					return
				}
			case LogFieldSeverityText:
				if r.SeverityText != nil {
					return
				}
			case LogFieldTraceID:
				if r.TraceID != nil {
					return
				}
			case LogFieldSpanID:
				if r.SpanID != nil {
					return
				}
			case LogFieldEventName:
				if r.EventName != nil {
					return
				}
			}
		}
		switch ref.Field {
		case LogFieldBody:
			r.Body = val
		case LogFieldSeverityText:
			r.SeverityText = val
		case LogFieldTraceID:
			r.TraceID = val
		case LogFieldSpanID:
			r.SpanID = val
		case LogFieldEventName:
			r.EventName = val
		}
		return
	}
	attrs := simpleLogEnsureAttrs(r, ref)
	if attrs == nil {
		return
	}
	if !upsert {
		if _, exists := attrs[ref.AttrPath[0]]; exists {
			return
		}
	}
	setPath(attrs, ref.AttrPath, value)
}

// simpleLogAttrs returns the attribute map for the given ref scope, or nil.
func simpleLogAttrs(r *SimpleLogRecord, ref LogFieldRef) map[string]any {
	switch {
	case ref.IsRecordAttr():
		return r.LogAttributes
	case ref.IsResourceAttr():
		return r.ResourceAttributes
	case ref.IsScopeAttr():
		return r.ScopeAttributes
	default:
		return nil
	}
}

// simpleLogEnsureAttrs returns the attribute map, creating it if needed.
func simpleLogEnsureAttrs(r *SimpleLogRecord, ref LogFieldRef) map[string]any {
	switch {
	case ref.IsRecordAttr():
		if r.LogAttributes == nil {
			r.LogAttributes = make(map[string]any)
		}
		return r.LogAttributes
	case ref.IsResourceAttr():
		if r.ResourceAttributes == nil {
			r.ResourceAttributes = make(map[string]any)
		}
		return r.ResourceAttributes
	case ref.IsScopeAttr():
		if r.ScopeAttributes == nil {
			r.ScopeAttributes = make(map[string]any)
		}
		return r.ScopeAttributes
	default:
		return nil
	}
}

// deletePath removes a value at the given path in a nested map.
func deletePath(m map[string]any, path []string) {
	if len(path) == 0 || m == nil {
		return
	}
	if len(path) == 1 {
		delete(m, path[0])
		return
	}
	nested, ok := m[path[0]].(map[string]any)
	if !ok {
		return
	}
	deletePath(nested, path[1:])
}

// setPath sets a value at the given path in a nested map.
func setPath(m map[string]any, path []string, value string) {
	if len(path) == 0 || m == nil {
		return
	}
	if len(path) == 1 {
		m[path[0]] = value
		return
	}
	nested, ok := m[path[0]].(map[string]any)
	if !ok {
		nested = make(map[string]any)
		m[path[0]] = nested
	}
	setPath(nested, path[1:], value)
}

// getPath retrieves a value at the given path in a nested map.
func getPath(m map[string]any, path []string) (any, bool) {
	if len(path) == 0 || m == nil {
		return nil, false
	}
	val, ok := m[path[0]]
	if !ok {
		return nil, false
	}
	if len(path) == 1 {
		return val, true
	}
	nested, ok := val.(map[string]any)
	if !ok {
		return nil, false
	}
	return getPath(nested, path[1:])
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
