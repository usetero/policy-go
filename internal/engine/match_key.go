// Package engine contains the policy evaluation engine implementation.
package engine

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

// LogField represents a log-specific field.
type LogField int

const (
	LogFieldUnspecified LogField = iota
	LogFieldBody
	LogFieldSeverityText
	LogFieldTraceID
	LogFieldSpanID
	LogFieldEventName
	LogFieldResourceSchemaURL
	LogFieldScopeSchemaURL
)

// MetricField represents a metric-specific field.
type MetricField int

const (
	MetricFieldUnspecified MetricField = iota
	MetricFieldName
	MetricFieldDescription
	MetricFieldUnit
	MetricFieldResourceSchemaURL
	MetricFieldScopeSchemaURL
	MetricFieldScopeName
	MetricFieldScopeVersion
	// Special fields for type matching
	MetricFieldType
	MetricFieldAggregationTemporality
)

// TraceField represents a trace/span-specific field.
type TraceField int

const (
	TraceFieldUnspecified TraceField = iota
	TraceFieldName
	TraceFieldTraceID
	TraceFieldSpanID
	TraceFieldParentSpanID
	TraceFieldTraceState
	TraceFieldResourceSchemaURL
	// Special fields for trace-specific matchers
	TraceFieldKind
	TraceFieldStatus
	TraceFieldEventName
	TraceFieldLinkTraceID
)

// FieldType is a constraint for field enum types.
type FieldType interface {
	LogField | MetricField | TraceField
}

// FieldRef represents a reference to a field or attribute for a specific telemetry type.
// It can represent either a specific field (by enum value) or an attribute lookup.
// This is the unified type used both internally for compilation and externally
// by consumers implementing match functions.
type FieldRef[T FieldType] struct {
	// Field is the field enum value.
	Field T
	// AttrScope specifies where to look for the attribute.
	AttrScope AttrScope
	// AttrPath is the attribute path for attribute lookups.
	// Supports nested access (e.g., ["http", "request", "method"]).
	AttrPath []string
}

// IsAttribute returns true if this is for an attribute lookup.
func (r FieldRef[T]) IsAttribute() bool {
	return len(r.AttrPath) > 0
}

// IsField returns true if this is a direct field reference (not an attribute).
func (r FieldRef[T]) IsField() bool {
	return !r.IsAttribute()
}

// IsResourceAttr returns true if this is a resource attribute reference.
func (r FieldRef[T]) IsResourceAttr() bool {
	return r.AttrScope == AttrScopeResource && len(r.AttrPath) > 0
}

// IsScopeAttr returns true if this is a scope attribute reference.
func (r FieldRef[T]) IsScopeAttr() bool {
	return r.AttrScope == AttrScopeScope && len(r.AttrPath) > 0
}

// IsRecordAttr returns true if this is a record-level attribute reference.
func (r FieldRef[T]) IsRecordAttr() bool {
	return r.AttrScope == AttrScopeRecord && len(r.AttrPath) > 0
}

// IsEventAttr returns true if this is an event attribute reference (traces only).
func (r FieldRef[T]) IsEventAttr() bool {
	return r.AttrScope == AttrScopeEvent && len(r.AttrPath) > 0
}

// Type aliases for convenience
type LogFieldRef = FieldRef[LogField]
type MetricFieldRef = FieldRef[MetricField]
type TraceFieldRef = FieldRef[TraceField]

// ============================================================================
// LOG FIELD CONSTRUCTORS
// ============================================================================

// LogBody creates a reference to the log body field.
func LogBody() LogFieldRef {
	return LogFieldRef{Field: LogFieldBody}
}

// LogSeverityText creates a reference to the log severity text field.
func LogSeverityText() LogFieldRef {
	return LogFieldRef{Field: LogFieldSeverityText}
}

// LogTraceID creates a reference to the log trace ID field.
func LogTraceID() LogFieldRef {
	return LogFieldRef{Field: LogFieldTraceID}
}

// LogSpanID creates a reference to the log span ID field.
func LogSpanID() LogFieldRef {
	return LogFieldRef{Field: LogFieldSpanID}
}

// LogAttr creates a reference to a log record attribute.
func LogAttr(path ...string) LogFieldRef {
	return LogFieldRef{AttrScope: AttrScopeRecord, AttrPath: path}
}

// LogResourceAttr creates a reference to a resource attribute on a log record.
func LogResourceAttr(path ...string) LogFieldRef {
	return LogFieldRef{AttrScope: AttrScopeResource, AttrPath: path}
}

// LogScopeAttr creates a reference to a scope attribute on a log record.
func LogScopeAttr(path ...string) LogFieldRef {
	return LogFieldRef{AttrScope: AttrScopeScope, AttrPath: path}
}

// ============================================================================
// METRIC FIELD CONSTRUCTORS
// ============================================================================

// MetricName creates a reference to the metric name field.
func MetricName() MetricFieldRef {
	return MetricFieldRef{Field: MetricFieldName}
}

// MetricDescription creates a reference to the metric description field.
func MetricDescription() MetricFieldRef {
	return MetricFieldRef{Field: MetricFieldDescription}
}

// MetricUnit creates a reference to the metric unit field.
func MetricUnit() MetricFieldRef {
	return MetricFieldRef{Field: MetricFieldUnit}
}

// MetricType creates a reference to the metric type field.
func MetricType() MetricFieldRef {
	return MetricFieldRef{Field: MetricFieldType}
}

// MetricAggregationTemporality creates a reference to the aggregation temporality field.
func MetricAggregationTemporality() MetricFieldRef {
	return MetricFieldRef{Field: MetricFieldAggregationTemporality}
}

// DatapointAttr creates a reference to a datapoint attribute.
func DatapointAttr(path ...string) MetricFieldRef {
	return MetricFieldRef{AttrScope: AttrScopeRecord, AttrPath: path}
}

// MetricResourceAttr creates a reference to a resource attribute on a metric.
func MetricResourceAttr(path ...string) MetricFieldRef {
	return MetricFieldRef{AttrScope: AttrScopeResource, AttrPath: path}
}

// MetricScopeAttr creates a reference to a scope attribute on a metric.
func MetricScopeAttr(path ...string) MetricFieldRef {
	return MetricFieldRef{AttrScope: AttrScopeScope, AttrPath: path}
}

// ============================================================================
// TRACE FIELD CONSTRUCTORS
// ============================================================================

// SpanName creates a reference to the span name field.
func SpanName() TraceFieldRef {
	return TraceFieldRef{Field: TraceFieldName}
}

// SpanTraceID creates a reference to the span trace ID field.
func SpanTraceID() TraceFieldRef {
	return TraceFieldRef{Field: TraceFieldTraceID}
}

// SpanSpanID creates a reference to the span ID field.
func SpanSpanID() TraceFieldRef {
	return TraceFieldRef{Field: TraceFieldSpanID}
}

// SpanParentSpanID creates a reference to the parent span ID field.
func SpanParentSpanID() TraceFieldRef {
	return TraceFieldRef{Field: TraceFieldParentSpanID}
}

// SpanTraceState creates a reference to the trace state field.
func SpanTraceState() TraceFieldRef {
	return TraceFieldRef{Field: TraceFieldTraceState}
}

// SpanKind creates a reference to the span kind field.
func SpanKind() TraceFieldRef {
	return TraceFieldRef{Field: TraceFieldKind}
}

// SpanStatus creates a reference to the span status field.
func SpanStatus() TraceFieldRef {
	return TraceFieldRef{Field: TraceFieldStatus}
}

// SpanEventName creates a reference to span event names.
func SpanEventName() TraceFieldRef {
	return TraceFieldRef{Field: TraceFieldEventName}
}

// SpanLinkTraceID creates a reference to span link trace IDs.
func SpanLinkTraceID() TraceFieldRef {
	return TraceFieldRef{Field: TraceFieldLinkTraceID}
}

// SpanAttr creates a reference to a span attribute.
func SpanAttr(path ...string) TraceFieldRef {
	return TraceFieldRef{AttrScope: AttrScopeRecord, AttrPath: path}
}

// TraceResourceAttr creates a reference to a resource attribute on a span.
func TraceResourceAttr(path ...string) TraceFieldRef {
	return TraceFieldRef{AttrScope: AttrScopeResource, AttrPath: path}
}

// TraceScopeAttr creates a reference to a scope attribute on a span.
func TraceScopeAttr(path ...string) TraceFieldRef {
	return TraceFieldRef{AttrScope: AttrScopeScope, AttrPath: path}
}

// SpanEventAttr creates a reference to a span event attribute.
func SpanEventAttr(path ...string) TraceFieldRef {
	return TraceFieldRef{AttrScope: AttrScopeEvent, AttrPath: path}
}

// ============================================================================
// PROTO CONVERSION (internal use)
// ============================================================================

// logFieldFromProto converts a proto LogField to our internal LogField.
func logFieldFromProto(f policyv1.LogField) LogField {
	switch f {
	case policyv1.LogField_LOG_FIELD_BODY:
		return LogFieldBody
	case policyv1.LogField_LOG_FIELD_SEVERITY_TEXT:
		return LogFieldSeverityText
	case policyv1.LogField_LOG_FIELD_TRACE_ID:
		return LogFieldTraceID
	case policyv1.LogField_LOG_FIELD_SPAN_ID:
		return LogFieldSpanID
	case policyv1.LogField_LOG_FIELD_EVENT_NAME:
		return LogFieldEventName
	case policyv1.LogField_LOG_FIELD_RESOURCE_SCHEMA_URL:
		return LogFieldResourceSchemaURL
	case policyv1.LogField_LOG_FIELD_SCOPE_SCHEMA_URL:
		return LogFieldScopeSchemaURL
	default:
		return LogFieldUnspecified
	}
}

// metricFieldFromProto converts a proto MetricField to our internal MetricField.
func metricFieldFromProto(f policyv1.MetricField) MetricField {
	switch f {
	case policyv1.MetricField_METRIC_FIELD_NAME:
		return MetricFieldName
	case policyv1.MetricField_METRIC_FIELD_DESCRIPTION:
		return MetricFieldDescription
	case policyv1.MetricField_METRIC_FIELD_UNIT:
		return MetricFieldUnit
	case policyv1.MetricField_METRIC_FIELD_RESOURCE_SCHEMA_URL:
		return MetricFieldResourceSchemaURL
	case policyv1.MetricField_METRIC_FIELD_SCOPE_SCHEMA_URL:
		return MetricFieldScopeSchemaURL
	case policyv1.MetricField_METRIC_FIELD_SCOPE_NAME:
		return MetricFieldScopeName
	case policyv1.MetricField_METRIC_FIELD_SCOPE_VERSION:
		return MetricFieldScopeVersion
	default:
		return MetricFieldUnspecified
	}
}

// traceFieldFromProto converts a proto TraceField to our internal TraceField.
func traceFieldFromProto(f policyv1.TraceField) TraceField {
	switch f {
	case policyv1.TraceField_TRACE_FIELD_NAME:
		return TraceFieldName
	case policyv1.TraceField_TRACE_FIELD_TRACE_ID:
		return TraceFieldTraceID
	case policyv1.TraceField_TRACE_FIELD_SPAN_ID:
		return TraceFieldSpanID
	case policyv1.TraceField_TRACE_FIELD_PARENT_SPAN_ID:
		return TraceFieldParentSpanID
	case policyv1.TraceField_TRACE_FIELD_TRACE_STATE:
		return TraceFieldTraceState
	case policyv1.TraceField_TRACE_FIELD_RESOURCE_SCHEMA_URL:
		return TraceFieldResourceSchemaURL
	default:
		return TraceFieldUnspecified
	}
}

// FieldRefFromLogMatcher extracts a FieldRef from a proto LogMatcher.
func FieldRefFromLogMatcher(m *policyv1.LogMatcher) LogFieldRef {
	switch f := m.GetField().(type) {
	case *policyv1.LogMatcher_LogField:
		return LogFieldRef{Field: logFieldFromProto(f.LogField)}
	case *policyv1.LogMatcher_LogAttribute:
		return LogFieldRef{AttrScope: AttrScopeRecord, AttrPath: f.LogAttribute.GetPath()}
	case *policyv1.LogMatcher_ResourceAttribute:
		return LogFieldRef{AttrScope: AttrScopeResource, AttrPath: f.ResourceAttribute.GetPath()}
	case *policyv1.LogMatcher_ScopeAttribute:
		return LogFieldRef{AttrScope: AttrScopeScope, AttrPath: f.ScopeAttribute.GetPath()}
	default:
		return LogFieldRef{}
	}
}

// FieldRefFromLogSampleKey extracts a FieldRef from a proto LogSampleKey.
func FieldRefFromLogSampleKey(sk *policyv1.LogSampleKey) LogFieldRef {
	switch f := sk.GetField().(type) {
	case *policyv1.LogSampleKey_LogField:
		return LogFieldRef{Field: logFieldFromProto(f.LogField)}
	case *policyv1.LogSampleKey_LogAttribute:
		return LogFieldRef{AttrScope: AttrScopeRecord, AttrPath: f.LogAttribute.GetPath()}
	case *policyv1.LogSampleKey_ResourceAttribute:
		return LogFieldRef{AttrScope: AttrScopeResource, AttrPath: f.ResourceAttribute.GetPath()}
	case *policyv1.LogSampleKey_ScopeAttribute:
		return LogFieldRef{AttrScope: AttrScopeScope, AttrPath: f.ScopeAttribute.GetPath()}
	default:
		return LogFieldRef{}
	}
}

// FieldRefFromMetricMatcher extracts a FieldRef from a proto MetricMatcher.
func FieldRefFromMetricMatcher(m *policyv1.MetricMatcher) MetricFieldRef {
	switch f := m.GetField().(type) {
	case *policyv1.MetricMatcher_MetricField:
		return MetricFieldRef{Field: metricFieldFromProto(f.MetricField)}
	case *policyv1.MetricMatcher_DatapointAttribute:
		return MetricFieldRef{AttrScope: AttrScopeRecord, AttrPath: f.DatapointAttribute.GetPath()}
	case *policyv1.MetricMatcher_ResourceAttribute:
		return MetricFieldRef{AttrScope: AttrScopeResource, AttrPath: f.ResourceAttribute.GetPath()}
	case *policyv1.MetricMatcher_ScopeAttribute:
		return MetricFieldRef{AttrScope: AttrScopeScope, AttrPath: f.ScopeAttribute.GetPath()}
	case *policyv1.MetricMatcher_MetricType:
		return MetricFieldRef{Field: MetricFieldType}
	case *policyv1.MetricMatcher_AggregationTemporality:
		return MetricFieldRef{Field: MetricFieldAggregationTemporality}
	default:
		return MetricFieldRef{}
	}
}

// FieldRefFromTraceMatcher extracts a FieldRef from a proto TraceMatcher.
func FieldRefFromTraceMatcher(m *policyv1.TraceMatcher) TraceFieldRef {
	switch f := m.GetField().(type) {
	case *policyv1.TraceMatcher_TraceField:
		return TraceFieldRef{Field: traceFieldFromProto(f.TraceField)}
	case *policyv1.TraceMatcher_SpanAttribute:
		return TraceFieldRef{AttrScope: AttrScopeRecord, AttrPath: f.SpanAttribute.GetPath()}
	case *policyv1.TraceMatcher_ResourceAttribute:
		return TraceFieldRef{AttrScope: AttrScopeResource, AttrPath: f.ResourceAttribute.GetPath()}
	case *policyv1.TraceMatcher_ScopeAttribute:
		return TraceFieldRef{AttrScope: AttrScopeScope, AttrPath: f.ScopeAttribute.GetPath()}
	case *policyv1.TraceMatcher_EventName:
		return TraceFieldRef{Field: TraceFieldEventName}
	case *policyv1.TraceMatcher_EventAttribute:
		return TraceFieldRef{AttrScope: AttrScopeEvent, AttrPath: f.EventAttribute.GetPath()}
	case *policyv1.TraceMatcher_LinkTraceId:
		return TraceFieldRef{Field: TraceFieldLinkTraceID}
	case *policyv1.TraceMatcher_SpanKind:
		return TraceFieldRef{Field: TraceFieldKind}
	case *policyv1.TraceMatcher_SpanStatus:
		return TraceFieldRef{Field: TraceFieldStatus}
	default:
		return TraceFieldRef{}
	}
}

// ============================================================================
// MATCH KEY (internal use for compilation)
// ============================================================================

// MatchKey identifies a group of patterns that share the same field ref, negation, and case sensitivity.
// Patterns are grouped by MatchKey for efficient Hyperscan compilation.
type MatchKey[T FieldType] struct {
	Ref             FieldRef[T]
	Negated         bool
	CaseInsensitive bool
}

// DatabaseEntry pairs a MatchKey with its compiled database.
type DatabaseEntry[T FieldType] struct {
	Key      MatchKey[T]
	Database *CompiledDatabase
}
