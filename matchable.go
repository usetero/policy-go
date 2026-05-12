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
	ResourceSchemaURL  []byte
	ScopeSchemaURL     []byte
	LogAttributes      map[string]any
	ResourceAttributes map[string]any
	ScopeAttributes    map[string]any
}

// SimpleLogConsumer adapts *SimpleLogRecord to the policy engine. The
// Value/Exists/Set/Delete/Move methods can be invoked directly on a zero
// value; NewSimpleLogConsumer wires those same methods into the embedded
// LogAccessor for use with EvaluateLog.
type SimpleLogConsumer struct {
	*LogAccessor[*SimpleLogRecord]
}

// Value returns the field/attribute value as bytes, or nil if absent.
func (SimpleLogConsumer) Value(r *SimpleLogRecord, ref LogFieldRef) []byte {
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

// Exists reports whether the field/attribute is present.
func (SimpleLogConsumer) Exists(r *SimpleLogRecord, ref LogFieldRef) bool {
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

// Set writes value at ref, creating the attribute map if needed.
func (SimpleLogConsumer) Set(r *SimpleLogRecord, ref LogFieldRef, value string) {
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

// Delete removes the field/attribute. Returns true if it existed.
func (SimpleLogConsumer) Delete(r *SimpleLogRecord, ref LogFieldRef) bool {
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

// Move transfers the value at from to to.
func (SimpleLogConsumer) Move(r *SimpleLogRecord, from, to LogFieldRef) {
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

// NewSimpleLogConsumer creates a configured LogConsumer for *SimpleLogRecord.
func NewSimpleLogConsumer() *SimpleLogConsumer {
	s := SimpleLogConsumer{}
	s.LogAccessor = NewLogConsumer[*SimpleLogRecord](
		WithLogValue(s.Value),
		WithLogExists(s.Exists),
		WithLogSet(s.Set),
		WithLogDelete(s.Delete),
		WithLogMove(s.Move),
	)
	return &s
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
		case LogFieldResourceSchemaURL:
			return r.ResourceSchemaURL
		case LogFieldScopeSchemaURL:
			return r.ScopeSchemaURL
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
// Returns true if the targeted field was present (hit), false if absent (miss).
func SimpleLogTransformer(r *SimpleLogRecord, op TransformOp) bool {
	switch op.Kind {
	case TransformRemove:
		return simpleLogRemove(r, op.Ref)
	case TransformRedact:
		return simpleLogRedact(r, op)
	case TransformRename:
		return simpleLogRename(r, op.Ref, op.To, op.Upsert)
	case TransformAdd:
		return simpleLogAdd(r, op.Ref, op.Value, op.Upsert)
	}
	return false
}

func simpleLogRemove(r *SimpleLogRecord, ref LogFieldRef) bool {
	if ref.IsField() {
		switch ref.Field {
		case LogFieldBody:
			hit := r.Body != nil
			r.Body = nil
			return hit
		case LogFieldSeverityText:
			hit := r.SeverityText != nil
			r.SeverityText = nil
			return hit
		case LogFieldTraceID:
			hit := r.TraceID != nil
			r.TraceID = nil
			return hit
		case LogFieldSpanID:
			hit := r.SpanID != nil
			r.SpanID = nil
			return hit
		case LogFieldEventName:
			hit := r.EventName != nil
			r.EventName = nil
			return hit
		}
		return false
	}
	attrs := simpleLogAttrs(r, ref)
	if attrs == nil {
		return false
	}
	_, exists := getPath(attrs, ref.AttrPath)
	deletePath(attrs, ref.AttrPath)
	return exists
}

func simpleLogRedact(r *SimpleLogRecord, op TransformOp) bool {
	ref := op.Ref
	if ref.IsField() {
		return simpleLogRedactField(r, ref.Field, op)
	}
	attrs := simpleLogAttrs(r, ref)
	if attrs == nil {
		return false
	}
	cur, exists := getPath(attrs, ref.AttrPath)
	if !exists {
		return false
	}
	if op.Regex != nil {
		// Targeted redaction: requires a string value and a match.
		curStr, ok := cur.(string)
		if !ok {
			return false
		}
		if !op.Regex.MatchString(curStr) {
			return false
		}
		setPath(attrs, ref.AttrPath, op.Regex.ReplaceAllString(curStr, op.Value))
		return true
	}
	setPath(attrs, ref.AttrPath, op.Value)
	return true
}

// simpleLogRedactField redacts a fixed log field. Fixed fields are stored as
// []byte and treated as strings for regex redaction.
func simpleLogRedactField(r *SimpleLogRecord, field LogField, op TransformOp) bool {
	target := simpleLogFieldPtr(r, field)
	if target == nil {
		return false
	}
	if *target == nil {
		return false
	}
	if op.Regex != nil {
		curStr := string(*target)
		if !op.Regex.MatchString(curStr) {
			return false
		}
		*target = []byte(op.Regex.ReplaceAllString(curStr, op.Value))
		return true
	}
	*target = []byte(op.Value)
	return true
}

// simpleLogFieldPtr returns a pointer to the backing []byte for a fixed log
// field, or nil if the field is not redactable.
func simpleLogFieldPtr(r *SimpleLogRecord, field LogField) *[]byte {
	switch field {
	case LogFieldBody:
		return &r.Body
	case LogFieldSeverityText:
		return &r.SeverityText
	case LogFieldTraceID:
		return &r.TraceID
	case LogFieldSpanID:
		return &r.SpanID
	case LogFieldEventName:
		return &r.EventName
	}
	return nil
}

func simpleLogRename(r *SimpleLogRecord, ref LogFieldRef, to string, upsert bool) bool {
	if ref.IsField() {
		// Renaming a fixed field to an attribute: not supported in simple impl
		return false
	}
	attrs := simpleLogAttrs(r, ref)
	if attrs == nil {
		return false
	}
	val, ok := getPath(attrs, ref.AttrPath)
	if !ok {
		return false
	}
	if !upsert {
		if _, exists := attrs[to]; exists {
			return true // source existed but target blocked
		}
	}
	deletePath(attrs, ref.AttrPath)
	attrs[to] = val
	return true
}

func simpleLogAdd(r *SimpleLogRecord, ref LogFieldRef, value string, upsert bool) bool {
	if ref.IsField() {
		val := []byte(value)
		if !upsert {
			switch ref.Field {
			case LogFieldBody:
				if r.Body != nil {
					return true
				}
			case LogFieldSeverityText:
				if r.SeverityText != nil {
					return true
				}
			case LogFieldTraceID:
				if r.TraceID != nil {
					return true
				}
			case LogFieldSpanID:
				if r.SpanID != nil {
					return true
				}
			case LogFieldEventName:
				if r.EventName != nil {
					return true
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
		return true
	}
	attrs := simpleLogEnsureAttrs(r, ref)
	if attrs == nil {
		return false
	}
	if !upsert {
		if _, exists := attrs[ref.AttrPath[0]]; exists {
			return true
		}
	}
	setPath(attrs, ref.AttrPath, value)
	return true
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
	ScopeName              []byte
	ScopeVersion           []byte
	ResourceSchemaURL      []byte
	ScopeSchemaURL         []byte
	DatapointAttributes    map[string]any
	ResourceAttributes     map[string]any
	ScopeAttributes        map[string]any
}

// SimpleMetricConsumer adapts *SimpleMetricRecord to the policy engine.
// Value/Exists can be invoked directly on a zero value; NewSimpleMetricConsumer
// wires those methods into the embedded MetricAccessor.
type SimpleMetricConsumer struct {
	*MetricAccessor[*SimpleMetricRecord]
}

// Value returns the field/attribute value as bytes, or nil if absent.
func (SimpleMetricConsumer) Value(r *SimpleMetricRecord, ref MetricFieldRef) []byte {
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

// Exists reports whether the field/attribute is present.
func (SimpleMetricConsumer) Exists(r *SimpleMetricRecord, ref MetricFieldRef) bool {
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

// NewSimpleMetricConsumer creates a configured MetricConsumer for *SimpleMetricRecord.
func NewSimpleMetricConsumer() *SimpleMetricConsumer {
	s := SimpleMetricConsumer{}
	s.MetricAccessor = NewMetricConsumer[*SimpleMetricRecord](
		WithMetricValue(s.Value),
		WithMetricExists(s.Exists),
	)
	return &s
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

// SimpleSpanConsumer adapts *SimpleSpanRecord to the policy engine.
// Value/Exists/Set can be invoked directly on a zero value;
// NewSimpleSpanConsumer wires those methods into the embedded TraceAccessor.
type SimpleSpanConsumer struct {
	*TraceAccessor[*SimpleSpanRecord]
}

// Value returns the field/attribute value as bytes, or nil if absent.
func (SimpleSpanConsumer) Value(r *SimpleSpanRecord, ref TraceFieldRef) []byte {
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

// Exists reports whether the field/attribute is present.
func (SimpleSpanConsumer) Exists(r *SimpleSpanRecord, ref TraceFieldRef) bool {
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

// Set writes value at ref. The sampling-threshold virtual field is a no-op
// — it lives in tracestate, which this simple consumer doesn't model
// separately, and the test consumers can override Set themselves.
func (SimpleSpanConsumer) Set(r *SimpleSpanRecord, ref TraceFieldRef, value string) {
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

// NewSimpleSpanConsumer creates a configured TraceConsumer for *SimpleSpanRecord.
func NewSimpleSpanConsumer() *SimpleSpanConsumer {
	s := SimpleSpanConsumer{}
	s.TraceAccessor = NewTraceConsumer[*SimpleSpanRecord](
		WithTraceValue(s.Value),
		WithTraceExists(s.Exists),
		WithTraceSet(s.Set),
	)
	return &s
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
		case TraceFieldScopeName:
			return r.ScopeName
		case TraceFieldScopeVersion:
			return r.ScopeVersion
		case TraceFieldResourceSchemaURL:
			return r.ResourceSchemaURL
		case TraceFieldScopeSchemaURL:
			return r.ScopeSchemaURL
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

// toBytes converts a value to bytes for matching. Returns nil for
// non-string values — the engine treats absence-of-string as a no-op so that
// targeted-redact regex won't fire on opaque types.
func toBytes(val any) []byte {
	if s, ok := val.(string); ok {
		return []byte(s)
	}
	return nil
}
