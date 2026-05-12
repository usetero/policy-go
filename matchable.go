package policy

// ============================================================================
// LOG RECORDS
// ============================================================================

// SimpleLogRecord is a reference log record used by the package's tests and
// examples. Attribute maps support nested structures via map[string]any values.
// Wire it up with NewSimpleLogAccessor or call the SimpleLog* accessor
// functions directly.
type SimpleLogRecord struct {
	Body               []byte
	SeverityText       []byte
	TraceID            []byte
	SpanID             []byte
	EventName          []byte
	ResourceSchemaURL  []byte
	ScopeSchemaURL     []byte
	LogAttributes      map[string]any
	ResourceAttributes map[string]any
	ScopeAttributes    map[string]any
}

// SimpleLogGetValue returns the field/attribute value as bytes, or nil if absent.
// Pass it as the WithLogValue option when wiring a LogAccessor for *SimpleLogRecord.
func SimpleLogGetValue(r *SimpleLogRecord, ref LogFieldRef) []byte {
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
		case LogFieldResourceSchemaURL:
			return r.ResourceSchemaURL
		case LogFieldScopeSchemaURL:
			return r.ScopeSchemaURL
		default:
			return nil
		}
	}
	return traversePath(simpleLogAttrs(r, ref), ref.AttrPath)
}

// SimpleLogHasValue reports whether the field/attribute is present.
func SimpleLogHasValue(r *SimpleLogRecord, ref LogFieldRef) bool {
	if ref.IsField() {
		switch ref.Field {
		case LogFieldBody:
			return r.Body != nil
		case LogFieldSeverityText:
			return r.SeverityText != nil
		case LogFieldTraceID:
			return r.TraceID != nil
		case LogFieldSpanID:
			return r.SpanID != nil
		case LogFieldEventName:
			return r.EventName != nil
		case LogFieldResourceSchemaURL:
			return r.ResourceSchemaURL != nil
		case LogFieldScopeSchemaURL:
			return r.ScopeSchemaURL != nil
		default:
			return false
		}
	}
	attrs := simpleLogAttrs(r, ref)
	if attrs == nil || len(ref.AttrPath) == 0 {
		return false
	}
	_, ok := getPath(attrs, ref.AttrPath)
	return ok
}

// SimpleLogSetValue writes value at ref, creating the attribute map if needed.
func SimpleLogSetValue(r *SimpleLogRecord, ref LogFieldRef, value string) {
	if ref.IsField() {
		switch ref.Field {
		case LogFieldBody:
			r.Body = []byte(value)
		case LogFieldSeverityText:
			r.SeverityText = []byte(value)
		case LogFieldTraceID:
			r.TraceID = []byte(value)
		case LogFieldSpanID:
			r.SpanID = []byte(value)
		case LogFieldEventName:
			r.EventName = []byte(value)
		case LogFieldResourceSchemaURL:
			r.ResourceSchemaURL = []byte(value)
		case LogFieldScopeSchemaURL:
			r.ScopeSchemaURL = []byte(value)
		}
		return
	}
	attrs := simpleLogEnsureAttrs(r, ref)
	if attrs != nil && len(ref.AttrPath) > 0 {
		setPath(attrs, ref.AttrPath, value)
	}
}

// SimpleLogDeleteValue removes the field/attribute. Returns true if it existed.
func SimpleLogDeleteValue(r *SimpleLogRecord, ref LogFieldRef) bool {
	if ref.IsField() {
		switch ref.Field {
		case LogFieldBody:
			existed := r.Body != nil
			r.Body = nil
			return existed
		case LogFieldSeverityText:
			existed := r.SeverityText != nil
			r.SeverityText = nil
			return existed
		case LogFieldTraceID:
			existed := r.TraceID != nil
			r.TraceID = nil
			return existed
		case LogFieldSpanID:
			existed := r.SpanID != nil
			r.SpanID = nil
			return existed
		case LogFieldEventName:
			existed := r.EventName != nil
			r.EventName = nil
			return existed
		}
		return false
	}
	attrs := simpleLogAttrs(r, ref)
	if attrs == nil || len(ref.AttrPath) == 0 {
		return false
	}
	if _, ok := getPath(attrs, ref.AttrPath); ok {
		deletePath(attrs, ref.AttrPath)
		return true
	}
	return false
}

// SimpleLogMoveValue transfers the value at from to to.
func SimpleLogMoveValue(r *SimpleLogRecord, from, to LogFieldRef) {
	fromAttrs := simpleLogAttrs(r, from)
	if fromAttrs == nil || len(from.AttrPath) == 0 {
		return
	}
	val, ok := getPath(fromAttrs, from.AttrPath)
	if !ok {
		return
	}
	deletePath(fromAttrs, from.AttrPath)
	toAttrs := simpleLogEnsureAttrs(r, to)
	if toAttrs == nil {
		return
	}
	if strVal, ok := val.(string); ok {
		setPath(toAttrs, to.AttrPath, strVal)
	}
}

// NewSimpleLogAccessor returns a LogAccessor for *SimpleLogRecord wired with
// the SimpleLog* accessor functions.
func NewSimpleLogAccessor() *LogAccessor[*SimpleLogRecord] {
	return NewLogAccessor[*SimpleLogRecord](
		WithLogValue(SimpleLogGetValue),
		WithLogExists(SimpleLogHasValue),
		WithLogSet(SimpleLogSetValue),
		WithLogDelete(SimpleLogDeleteValue),
		WithLogMove(SimpleLogMoveValue),
	)
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

// SimpleMetricRecord is a reference metric record used by the package's tests
// and examples. Wire it up with NewSimpleMetricAccessor.
type SimpleMetricRecord struct {
	Name                   []byte
	Description            []byte
	Unit                   []byte
	Type                   []byte // e.g., "gauge", "sum", "histogram"
	AggregationTemporality []byte // e.g., "delta", "cumulative"
	ScopeName              []byte
	ScopeVersion           []byte
	ResourceSchemaURL      []byte
	ScopeSchemaURL         []byte
	DatapointAttributes    map[string]any
	ResourceAttributes     map[string]any
	ScopeAttributes        map[string]any
}

// SimpleMetricGetValue returns the field/attribute value as bytes, or nil if absent.
func SimpleMetricGetValue(r *SimpleMetricRecord, ref MetricFieldRef) []byte {
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
		case MetricFieldScopeName:
			return r.ScopeName
		case MetricFieldScopeVersion:
			return r.ScopeVersion
		case MetricFieldResourceSchemaURL:
			return r.ResourceSchemaURL
		case MetricFieldScopeSchemaURL:
			return r.ScopeSchemaURL
		default:
			return nil
		}
	}
	return traversePath(simpleMetricAttrs(r, ref), ref.AttrPath)
}

// SimpleMetricHasValue reports whether the field/attribute is present.
func SimpleMetricHasValue(r *SimpleMetricRecord, ref MetricFieldRef) bool {
	if ref.IsField() {
		switch ref.Field {
		case MetricFieldName:
			return r.Name != nil
		case MetricFieldDescription:
			return r.Description != nil
		case MetricFieldUnit:
			return r.Unit != nil
		case MetricFieldType:
			return r.Type != nil
		case MetricFieldAggregationTemporality:
			return r.AggregationTemporality != nil
		case MetricFieldScopeName:
			return r.ScopeName != nil
		case MetricFieldScopeVersion:
			return r.ScopeVersion != nil
		case MetricFieldResourceSchemaURL:
			return r.ResourceSchemaURL != nil
		case MetricFieldScopeSchemaURL:
			return r.ScopeSchemaURL != nil
		default:
			return false
		}
	}
	attrs := simpleMetricAttrs(r, ref)
	if attrs == nil || len(ref.AttrPath) == 0 {
		return false
	}
	_, ok := getPath(attrs, ref.AttrPath)
	return ok
}

// simpleMetricAttrs returns the attribute map for the given ref scope, or nil.
func simpleMetricAttrs(r *SimpleMetricRecord, ref MetricFieldRef) map[string]any {
	switch {
	case ref.IsRecordAttr():
		return r.DatapointAttributes
	case ref.IsResourceAttr():
		return r.ResourceAttributes
	case ref.IsScopeAttr():
		return r.ScopeAttributes
	default:
		return nil
	}
}

// NewSimpleMetricAccessor returns a MetricAccessor for *SimpleMetricRecord
// wired with the SimpleMetric* accessor functions.
func NewSimpleMetricAccessor() *MetricAccessor[*SimpleMetricRecord] {
	return NewMetricAccessor[*SimpleMetricRecord](
		WithMetricValue(SimpleMetricGetValue),
		WithMetricExists(SimpleMetricHasValue),
	)
}

// ============================================================================
// TRACE/SPAN RECORDS
// ============================================================================

// SimpleSpanRecord is a reference span record used by the package's tests and
// examples. Wire it up with NewSimpleSpanAccessor.
type SimpleSpanRecord struct {
	Name               []byte
	TraceID            []byte
	SpanID             []byte
	ParentSpanID       []byte
	TraceState         []byte
	Kind               []byte // e.g., "server", "client", "internal"
	Status             []byte // e.g., "ok", "error", "unset"
	ScopeName          []byte
	ScopeVersion       []byte
	ResourceSchemaURL  []byte
	ScopeSchemaURL     []byte
	EventNames         [][]byte
	EventAttributes    []map[string]any
	LinkTraceIDs       [][]byte
	LinkAttributes     []map[string]any
	SpanAttributes     map[string]any
	ResourceAttributes map[string]any
	ScopeAttributes    map[string]any
}

// SimpleSpanGetValue returns the field/attribute value as bytes, or nil if absent.
func SimpleSpanGetValue(r *SimpleSpanRecord, ref TraceFieldRef) []byte {
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
		case TraceFieldScopeName:
			return r.ScopeName
		case TraceFieldScopeVersion:
			return r.ScopeVersion
		case TraceFieldResourceSchemaURL:
			return r.ResourceSchemaURL
		case TraceFieldScopeSchemaURL:
			return r.ScopeSchemaURL
		case TraceFieldEventName:
			if len(r.EventNames) > 0 {
				return r.EventNames[0]
			}
			return nil
		case TraceFieldLinkTraceID:
			if len(r.LinkTraceIDs) > 0 {
				return r.LinkTraceIDs[0]
			}
			return nil
		default:
			return nil
		}
	}
	return traversePath(simpleSpanAttrs(r, ref), ref.AttrPath)
}

// SimpleSpanHasValue reports whether the field/attribute is present.
func SimpleSpanHasValue(r *SimpleSpanRecord, ref TraceFieldRef) bool {
	if ref.IsField() {
		switch ref.Field {
		case TraceFieldName:
			return r.Name != nil
		case TraceFieldTraceID:
			return r.TraceID != nil
		case TraceFieldSpanID:
			return r.SpanID != nil
		case TraceFieldParentSpanID:
			return r.ParentSpanID != nil
		case TraceFieldTraceState:
			return r.TraceState != nil
		case TraceFieldKind:
			return r.Kind != nil
		case TraceFieldStatus:
			return r.Status != nil
		case TraceFieldScopeName:
			return r.ScopeName != nil
		case TraceFieldScopeVersion:
			return r.ScopeVersion != nil
		case TraceFieldResourceSchemaURL:
			return r.ResourceSchemaURL != nil
		case TraceFieldScopeSchemaURL:
			return r.ScopeSchemaURL != nil
		case TraceFieldEventName:
			return len(r.EventNames) > 0
		case TraceFieldLinkTraceID:
			return len(r.LinkTraceIDs) > 0
		default:
			return false
		}
	}
	attrs := simpleSpanAttrs(r, ref)
	if attrs == nil || len(ref.AttrPath) == 0 {
		return false
	}
	_, ok := getPath(attrs, ref.AttrPath)
	return ok
}

// SimpleSpanSetValue writes value at ref. The sampling-threshold virtual
// field is intentionally a no-op here — it lives in tracestate, which this
// simple span doesn't model separately. Consumers that care can wrap Set.
func SimpleSpanSetValue(r *SimpleSpanRecord, ref TraceFieldRef, value string) {
	if ref.IsField() {
		switch ref.Field {
		case TraceFieldName:
			r.Name = []byte(value)
		case TraceFieldTraceState:
			r.TraceState = []byte(value)
		case TraceFieldKind:
			r.Kind = []byte(value)
		case TraceFieldStatus:
			r.Status = []byte(value)
		}
		return
	}
	attrs := simpleSpanEnsureAttrs(r, ref)
	if attrs != nil && len(ref.AttrPath) > 0 {
		setPath(attrs, ref.AttrPath, value)
	}
}

// simpleSpanEnsureAttrs returns the attribute map for the given ref scope,
// creating it if needed.
func simpleSpanEnsureAttrs(r *SimpleSpanRecord, ref TraceFieldRef) map[string]any {
	switch {
	case ref.IsRecordAttr():
		if r.SpanAttributes == nil {
			r.SpanAttributes = make(map[string]any)
		}
		return r.SpanAttributes
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
	case ref.IsEventAttr():
		if len(r.EventAttributes) == 0 {
			return nil
		}
		if r.EventAttributes[0] == nil {
			r.EventAttributes[0] = make(map[string]any)
		}
		return r.EventAttributes[0]
	case ref.IsLinkAttr():
		if len(r.LinkAttributes) == 0 {
			return nil
		}
		if r.LinkAttributes[0] == nil {
			r.LinkAttributes[0] = make(map[string]any)
		}
		return r.LinkAttributes[0]
	default:
		return nil
	}
}

// NewSimpleSpanAccessor returns a TraceAccessor for *SimpleSpanRecord wired
// with the SimpleSpan* accessor functions.
func NewSimpleSpanAccessor() *TraceAccessor[*SimpleSpanRecord] {
	return NewTraceAccessor[*SimpleSpanRecord](
		WithTraceValue(SimpleSpanGetValue),
		WithTraceExists(SimpleSpanHasValue),
		WithTraceSet(SimpleSpanSetValue),
	)
}

// simpleSpanAttrs returns the attribute map for the given ref scope, or nil.
func simpleSpanAttrs(r *SimpleSpanRecord, ref TraceFieldRef) map[string]any {
	switch {
	case ref.IsRecordAttr():
		return r.SpanAttributes
	case ref.IsResourceAttr():
		return r.ResourceAttributes
	case ref.IsScopeAttr():
		return r.ScopeAttributes
	case ref.IsEventAttr():
		if len(r.EventAttributes) > 0 {
			return r.EventAttributes[0]
		}
		return nil
	case ref.IsLinkAttr():
		if len(r.LinkAttributes) > 0 {
			return r.LinkAttributes[0]
		}
		return nil
	default:
		return nil
	}
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

// toBytes converts a value to bytes for matching. Returns nil for
// non-string values — the engine treats absence-of-string as a no-op so that
// targeted-redact regex won't fire on opaque types.
func toBytes(val any) []byte {
	if s, ok := val.(string); ok {
		return []byte(s)
	}
	return nil
}
