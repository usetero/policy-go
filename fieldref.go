package policy

import (
	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
)

// ============================================================================
// LOG FIELD REFERENCES
// ============================================================================

// logFieldRefKind identifies the type of log field reference.
type logFieldRefKind int

const (
	logFieldRefField logFieldRefKind = iota
	logFieldRefRecordAttr
	logFieldRefResourceAttr
	logFieldRefScopeAttr
)

// LogFieldRef represents a reference to a field or attribute in a log record.
// Use the constructor functions (LogField, LogAttr, LogResourceAttr, LogScopeAttr)
// to create valid references.
type LogFieldRef struct {
	kind     logFieldRefKind
	field    policyv1.LogField
	attrPath []string
}

// LogField creates a reference to a log field (body, severity_text, trace_id, etc.)
func LogField(f policyv1.LogField) LogFieldRef {
	return LogFieldRef{kind: logFieldRefField, field: f}
}

// LogAttr creates a reference to a log record attribute.
func LogAttr(path ...string) LogFieldRef {
	return LogFieldRef{kind: logFieldRefRecordAttr, attrPath: path}
}

// LogResourceAttr creates a reference to a resource attribute on a log record.
func LogResourceAttr(path ...string) LogFieldRef {
	return LogFieldRef{kind: logFieldRefResourceAttr, attrPath: path}
}

// LogScopeAttr creates a reference to a scope attribute on a log record.
func LogScopeAttr(path ...string) LogFieldRef {
	return LogFieldRef{kind: logFieldRefScopeAttr, attrPath: path}
}

// IsField returns true if this is a direct field reference (not an attribute).
func (r LogFieldRef) IsField() bool {
	return r.kind == logFieldRefField
}

// IsAttr returns true if this is an attribute reference.
func (r LogFieldRef) IsAttr() bool {
	return r.kind != logFieldRefField
}

// Field returns the log field enum value. Only valid when IsField() is true.
func (r LogFieldRef) Field() policyv1.LogField {
	return r.field
}

// Path returns the attribute path. Only valid when IsAttr() is true.
func (r LogFieldRef) Path() []string {
	return r.attrPath
}

// IsRecordAttr returns true if this is a log record attribute reference.
func (r LogFieldRef) IsRecordAttr() bool {
	return r.kind == logFieldRefRecordAttr
}

// IsResourceAttr returns true if this is a resource attribute reference.
func (r LogFieldRef) IsResourceAttr() bool {
	return r.kind == logFieldRefResourceAttr
}

// IsScopeAttr returns true if this is a scope attribute reference.
func (r LogFieldRef) IsScopeAttr() bool {
	return r.kind == logFieldRefScopeAttr
}

// ============================================================================
// METRIC FIELD REFERENCES
// ============================================================================

// metricFieldRefKind identifies the type of metric field reference.
type metricFieldRefKind int

const (
	metricFieldRefField metricFieldRefKind = iota
	metricFieldRefDatapointAttr
	metricFieldRefResourceAttr
	metricFieldRefScopeAttr
	metricFieldRefMetricType
	metricFieldRefAggTemporality
)

// MetricFieldRef represents a reference to a field or attribute in a metric.
// Use the constructor functions to create valid references.
type MetricFieldRef struct {
	kind     metricFieldRefKind
	field    policyv1.MetricField
	attrPath []string
	// Special fields for metric-specific matchers
	metricType policyv1.MetricType
	aggTemp    policyv1.AggregationTemporality
}

// MetricField creates a reference to a metric field (name, description, unit, etc.)
func MetricField(f policyv1.MetricField) MetricFieldRef {
	return MetricFieldRef{kind: metricFieldRefField, field: f}
}

// DatapointAttr creates a reference to a datapoint attribute.
func DatapointAttr(path ...string) MetricFieldRef {
	return MetricFieldRef{kind: metricFieldRefDatapointAttr, attrPath: path}
}

// MetricResourceAttr creates a reference to a resource attribute on a metric.
func MetricResourceAttr(path ...string) MetricFieldRef {
	return MetricFieldRef{kind: metricFieldRefResourceAttr, attrPath: path}
}

// MetricScopeAttr creates a reference to a scope attribute on a metric.
func MetricScopeAttr(path ...string) MetricFieldRef {
	return MetricFieldRef{kind: metricFieldRefScopeAttr, attrPath: path}
}

// MetricTypeRef creates a reference to match on metric type (gauge, sum, histogram, etc.)
func MetricTypeRef(t policyv1.MetricType) MetricFieldRef {
	return MetricFieldRef{kind: metricFieldRefMetricType, metricType: t}
}

// AggTemporalityRef creates a reference to match on aggregation temporality.
func AggTemporalityRef(t policyv1.AggregationTemporality) MetricFieldRef {
	return MetricFieldRef{kind: metricFieldRefAggTemporality, aggTemp: t}
}

// IsField returns true if this is a direct field reference (not an attribute or special field).
func (r MetricFieldRef) IsField() bool {
	return r.kind == metricFieldRefField
}

// IsAttr returns true if this is an attribute reference.
func (r MetricFieldRef) IsAttr() bool {
	return r.kind == metricFieldRefDatapointAttr ||
		r.kind == metricFieldRefResourceAttr ||
		r.kind == metricFieldRefScopeAttr
}

// Field returns the metric field enum value. Only valid when IsField() is true.
func (r MetricFieldRef) Field() policyv1.MetricField {
	return r.field
}

// Path returns the attribute path. Only valid when IsAttr() is true.
func (r MetricFieldRef) Path() []string {
	return r.attrPath
}

// IsDatapointAttr returns true if this is a datapoint attribute reference.
func (r MetricFieldRef) IsDatapointAttr() bool {
	return r.kind == metricFieldRefDatapointAttr
}

// IsResourceAttr returns true if this is a resource attribute reference.
func (r MetricFieldRef) IsResourceAttr() bool {
	return r.kind == metricFieldRefResourceAttr
}

// IsScopeAttr returns true if this is a scope attribute reference.
func (r MetricFieldRef) IsScopeAttr() bool {
	return r.kind == metricFieldRefScopeAttr
}

// IsMetricType returns true if this is a metric type reference.
func (r MetricFieldRef) IsMetricType() bool {
	return r.kind == metricFieldRefMetricType
}

// MetricType returns the metric type. Only valid when IsMetricType() is true.
func (r MetricFieldRef) MetricType() policyv1.MetricType {
	return r.metricType
}

// IsAggTemporality returns true if this is an aggregation temporality reference.
func (r MetricFieldRef) IsAggTemporality() bool {
	return r.kind == metricFieldRefAggTemporality
}

// AggTemporality returns the aggregation temporality. Only valid when IsAggTemporality() is true.
func (r MetricFieldRef) AggTemporality() policyv1.AggregationTemporality {
	return r.aggTemp
}

// ============================================================================
// TRACE FIELD REFERENCES
// ============================================================================

// traceFieldRefKind identifies the type of trace field reference.
type traceFieldRefKind int

const (
	traceFieldRefField traceFieldRefKind = iota
	traceFieldRefSpanAttr
	traceFieldRefResourceAttr
	traceFieldRefScopeAttr
	traceFieldRefEventName
	traceFieldRefEventAttr
	traceFieldRefLinkTraceID
	traceFieldRefSpanKind
	traceFieldRefSpanStatus
)

// TraceFieldRef represents a reference to a field or attribute in a span.
// Use the constructor functions to create valid references.
type TraceFieldRef struct {
	kind     traceFieldRefKind
	field    policyv1.TraceField
	attrPath []string
	// Special fields for trace-specific matchers
	spanKind   policyv1.SpanKind
	spanStatus policyv1.SpanStatusCode
}

// TraceField creates a reference to a trace field (name, trace_id, span_id, etc.)
func TraceField(f policyv1.TraceField) TraceFieldRef {
	return TraceFieldRef{kind: traceFieldRefField, field: f}
}

// SpanAttr creates a reference to a span attribute.
func SpanAttr(path ...string) TraceFieldRef {
	return TraceFieldRef{kind: traceFieldRefSpanAttr, attrPath: path}
}

// TraceResourceAttr creates a reference to a resource attribute on a span.
func TraceResourceAttr(path ...string) TraceFieldRef {
	return TraceFieldRef{kind: traceFieldRefResourceAttr, attrPath: path}
}

// TraceScopeAttr creates a reference to a scope attribute on a span.
func TraceScopeAttr(path ...string) TraceFieldRef {
	return TraceFieldRef{kind: traceFieldRefScopeAttr, attrPath: path}
}

// EventName creates a reference to a span event name.
func EventName() TraceFieldRef {
	return TraceFieldRef{kind: traceFieldRefEventName}
}

// EventAttr creates a reference to a span event attribute.
func EventAttr(path ...string) TraceFieldRef {
	return TraceFieldRef{kind: traceFieldRefEventAttr, attrPath: path}
}

// LinkTraceID creates a reference to a span link's trace ID.
func LinkTraceID() TraceFieldRef {
	return TraceFieldRef{kind: traceFieldRefLinkTraceID}
}

// SpanKindRef creates a reference to match on span kind.
func SpanKindRef(k policyv1.SpanKind) TraceFieldRef {
	return TraceFieldRef{kind: traceFieldRefSpanKind, spanKind: k}
}

// SpanStatusRef creates a reference to match on span status code.
func SpanStatusRef(s policyv1.SpanStatusCode) TraceFieldRef {
	return TraceFieldRef{kind: traceFieldRefSpanStatus, spanStatus: s}
}

// IsField returns true if this is a direct field reference (not an attribute or special field).
func (r TraceFieldRef) IsField() bool {
	return r.kind == traceFieldRefField
}

// IsAttr returns true if this is an attribute reference.
func (r TraceFieldRef) IsAttr() bool {
	return r.kind == traceFieldRefSpanAttr ||
		r.kind == traceFieldRefResourceAttr ||
		r.kind == traceFieldRefScopeAttr ||
		r.kind == traceFieldRefEventAttr
}

// Field returns the trace field enum value. Only valid when IsField() is true.
func (r TraceFieldRef) Field() policyv1.TraceField {
	return r.field
}

// Path returns the attribute path. Only valid when IsAttr() is true.
func (r TraceFieldRef) Path() []string {
	return r.attrPath
}

// IsSpanAttr returns true if this is a span attribute reference.
func (r TraceFieldRef) IsSpanAttr() bool {
	return r.kind == traceFieldRefSpanAttr
}

// IsResourceAttr returns true if this is a resource attribute reference.
func (r TraceFieldRef) IsResourceAttr() bool {
	return r.kind == traceFieldRefResourceAttr
}

// IsScopeAttr returns true if this is a scope attribute reference.
func (r TraceFieldRef) IsScopeAttr() bool {
	return r.kind == traceFieldRefScopeAttr
}

// IsEventName returns true if this is a span event name reference.
func (r TraceFieldRef) IsEventName() bool {
	return r.kind == traceFieldRefEventName
}

// IsEventAttr returns true if this is a span event attribute reference.
func (r TraceFieldRef) IsEventAttr() bool {
	return r.kind == traceFieldRefEventAttr
}

// IsLinkTraceID returns true if this is a span link trace ID reference.
func (r TraceFieldRef) IsLinkTraceID() bool {
	return r.kind == traceFieldRefLinkTraceID
}

// IsSpanKind returns true if this is a span kind reference.
func (r TraceFieldRef) IsSpanKind() bool {
	return r.kind == traceFieldRefSpanKind
}

// SpanKind returns the span kind. Only valid when IsSpanKind() is true.
func (r TraceFieldRef) SpanKind() policyv1.SpanKind {
	return r.spanKind
}

// IsSpanStatus returns true if this is a span status reference.
func (r TraceFieldRef) IsSpanStatus() bool {
	return r.kind == traceFieldRefSpanStatus
}

// SpanStatus returns the span status code. Only valid when IsSpanStatus() is true.
func (r TraceFieldRef) SpanStatus() policyv1.SpanStatusCode {
	return r.spanStatus
}

// ============================================================================
// MATCH FUNCTIONS
// ============================================================================

// LogMatchFunc extracts field values from a log record of type T.
// Consumers implement this function to bridge their record type to the policy engine.
type LogMatchFunc[T any] func(record T, ref LogFieldRef) []byte

// MetricMatchFunc extracts field values from a metric of type T.
// Consumers implement this function to bridge their record type to the policy engine.
type MetricMatchFunc[T any] func(record T, ref MetricFieldRef) []byte

// TraceMatchFunc extracts field values from a span of type T.
// Consumers implement this function to bridge their record type to the policy engine.
type TraceMatchFunc[T any] func(record T, ref TraceFieldRef) []byte
