package policy

import (
	"github.com/usetero/policy-go/internal/engine"
	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
)

// ============================================================================
// PROTO TYPE RE-EXPORTS
// ============================================================================

// Re-export proto types for convenience.
type (
	// Policy is the proto policy type.
	Policy = policyv1.Policy
	// LogTarget is the proto log target type.
	LogTarget = policyv1.LogTarget
	// LogMatcher is the proto log matcher type.
	LogMatcher = policyv1.LogMatcher
)

// ============================================================================
// KEEP ACTION TYPES
// ============================================================================

// Re-export engine types.
type (
	KeepAction = engine.KeepAction
	Keep       = engine.Keep
)

// KeepAction constants.
const (
	KeepAll           = engine.KeepAll
	KeepNone          = engine.KeepNone
	KeepSample        = engine.KeepSample
	KeepRatePerSecond = engine.KeepRatePerSecond
	KeepRatePerMinute = engine.KeepRatePerMinute
)

// ParseKeep parses a keep string into a Keep struct.
var ParseKeep = engine.ParseKeep

// ============================================================================
// FIELD REFERENCE TYPES
// ============================================================================

// Re-export field types from engine package for public use.
type (
	// AttrScope identifies the scope for attribute lookups.
	AttrScope = engine.AttrScope

	// LogField represents a log-specific field.
	LogField = engine.LogField

	// MetricField represents a metric-specific field.
	MetricField = engine.MetricField

	// TraceField represents a trace/span-specific field.
	TraceField = engine.TraceField

	// FieldRef represents a reference to a field or attribute.
	// Use the constructor functions to create references.
	FieldRef[T engine.FieldType] = engine.FieldRef[T]

	// LogFieldRef is a field reference for log records.
	LogFieldRef = engine.LogFieldRef

	// MetricFieldRef is a field reference for metrics.
	MetricFieldRef = engine.MetricFieldRef

	// TraceFieldRef is a field reference for traces/spans.
	TraceFieldRef = engine.TraceFieldRef
)

// AttrScope constants.
const (
	AttrScopeResource = engine.AttrScopeResource
	AttrScopeScope    = engine.AttrScopeScope
	AttrScopeRecord   = engine.AttrScopeRecord
	AttrScopeEvent    = engine.AttrScopeEvent
	AttrScopeLink     = engine.AttrScopeLink
)

// LogField constants.
const (
	LogFieldBody              = engine.LogFieldBody
	LogFieldSeverityText      = engine.LogFieldSeverityText
	LogFieldTraceID           = engine.LogFieldTraceID
	LogFieldSpanID            = engine.LogFieldSpanID
	LogFieldEventName         = engine.LogFieldEventName
	LogFieldResourceSchemaURL = engine.LogFieldResourceSchemaURL
	LogFieldScopeSchemaURL    = engine.LogFieldScopeSchemaURL
)

// MetricField constants.
const (
	MetricFieldName                   = engine.MetricFieldName
	MetricFieldDescription            = engine.MetricFieldDescription
	MetricFieldUnit                   = engine.MetricFieldUnit
	MetricFieldResourceSchemaURL      = engine.MetricFieldResourceSchemaURL
	MetricFieldScopeSchemaURL         = engine.MetricFieldScopeSchemaURL
	MetricFieldScopeName              = engine.MetricFieldScopeName
	MetricFieldScopeVersion           = engine.MetricFieldScopeVersion
	MetricFieldType                   = engine.MetricFieldType
	MetricFieldAggregationTemporality = engine.MetricFieldAggregationTemporality
)

// TraceField constants.
const (
	TraceFieldName              = engine.TraceFieldName
	TraceFieldTraceID           = engine.TraceFieldTraceID
	TraceFieldSpanID            = engine.TraceFieldSpanID
	TraceFieldParentSpanID      = engine.TraceFieldParentSpanID
	TraceFieldTraceState        = engine.TraceFieldTraceState
	TraceFieldResourceSchemaURL = engine.TraceFieldResourceSchemaURL
	TraceFieldScopeSchemaURL    = engine.TraceFieldScopeSchemaURL
	TraceFieldScopeName         = engine.TraceFieldScopeName
	TraceFieldScopeVersion      = engine.TraceFieldScopeVersion
	TraceFieldKind              = engine.TraceFieldKind
	TraceFieldStatus            = engine.TraceFieldStatus
	TraceFieldEventName         = engine.TraceFieldEventName
	TraceFieldLinkTraceID       = engine.TraceFieldLinkTraceID
)

// ============================================================================
// LOG FIELD CONSTRUCTORS
// ============================================================================

// LogBody creates a reference to the log body field.
var LogBody = engine.LogBody

// LogSeverityText creates a reference to the log severity text field.
var LogSeverityText = engine.LogSeverityText

// LogTraceID creates a reference to the log trace ID field.
var LogTraceID = engine.LogTraceID

// LogSpanID creates a reference to the log span ID field.
var LogSpanID = engine.LogSpanID

// LogEventName creates a reference to the log event name field.
var LogEventName = engine.LogEventName

// LogResourceSchemaURL creates a reference to the log resource schema URL field.
var LogResourceSchemaURL = engine.LogResourceSchemaURL

// LogScopeSchemaURL creates a reference to the log scope schema URL field.
var LogScopeSchemaURL = engine.LogScopeSchemaURL

// LogAttr creates a reference to a log record attribute.
var LogAttr = engine.LogAttr

// LogResourceAttr creates a reference to a resource attribute on a log record.
var LogResourceAttr = engine.LogResourceAttr

// LogScopeAttr creates a reference to a scope attribute on a log record.
var LogScopeAttr = engine.LogScopeAttr

// ============================================================================
// METRIC FIELD CONSTRUCTORS
// ============================================================================

// MetricName creates a reference to the metric name field.
var MetricName = engine.MetricName

// MetricDescription creates a reference to the metric description field.
var MetricDescription = engine.MetricDescription

// MetricUnit creates a reference to the metric unit field.
var MetricUnit = engine.MetricUnit

// MetricType creates a reference to the metric type field.
var MetricType = engine.MetricType

// MetricAggregationTemporality creates a reference to the aggregation temporality field.
var MetricAggregationTemporality = engine.MetricAggregationTemporality

// MetricScopeName creates a reference to the metric scope name field.
var MetricScopeName = engine.MetricScopeName

// MetricScopeVersion creates a reference to the metric scope version field.
var MetricScopeVersion = engine.MetricScopeVersion

// MetricResourceSchemaURL creates a reference to the metric resource schema URL field.
var MetricResourceSchemaURL = engine.MetricResourceSchemaURL

// MetricScopeSchemaURL creates a reference to the metric scope schema URL field.
var MetricScopeSchemaURL = engine.MetricScopeSchemaURL

// DatapointAttr creates a reference to a datapoint attribute.
var DatapointAttr = engine.DatapointAttr

// MetricResourceAttr creates a reference to a resource attribute on a metric.
var MetricResourceAttr = engine.MetricResourceAttr

// MetricScopeAttr creates a reference to a scope attribute on a metric.
var MetricScopeAttr = engine.MetricScopeAttr

// ============================================================================
// TRACE FIELD CONSTRUCTORS
// ============================================================================

// SpanName creates a reference to the span name field.
var SpanName = engine.SpanName

// SpanTraceID creates a reference to the span trace ID field.
var SpanTraceID = engine.SpanTraceID

// SpanSpanID creates a reference to the span ID field.
var SpanSpanID = engine.SpanSpanID

// SpanParentSpanID creates a reference to the parent span ID field.
var SpanParentSpanID = engine.SpanParentSpanID

// SpanTraceState creates a reference to the trace state field.
var SpanTraceState = engine.SpanTraceState

// SpanKind creates a reference to the span kind field.
var SpanKind = engine.SpanKind

// SpanStatus creates a reference to the span status field.
var SpanStatus = engine.SpanStatus

// SpanEventName creates a reference to span event names.
var SpanEventName = engine.SpanEventName

// SpanLinkTraceID creates a reference to span link trace IDs.
var SpanLinkTraceID = engine.SpanLinkTraceID

// SpanAttr creates a reference to a span attribute.
var SpanAttr = engine.SpanAttr

// TraceResourceAttr creates a reference to a resource attribute on a span.
var TraceResourceAttr = engine.TraceResourceAttr

// TraceScopeAttr creates a reference to a scope attribute on a span.
var TraceScopeAttr = engine.TraceScopeAttr

// SpanEventAttr creates a reference to a span event attribute.
var SpanEventAttr = engine.SpanEventAttr

// SpanLinkAttr creates a reference to a span link attribute.
var SpanLinkAttr = engine.SpanLinkAttr

// TraceResourceSchemaURL creates a reference to the trace resource schema URL field.
var TraceResourceSchemaURL = engine.TraceResourceSchemaURL

// TraceScopeSchemaURL creates a reference to the scope schema URL field.
var TraceScopeSchemaURL = engine.TraceScopeSchemaURL

// TraceScopeName creates a reference to the scope name field.
var TraceScopeName = engine.TraceScopeName

// TraceScopeVersion creates a reference to the scope version field.
var TraceScopeVersion = engine.TraceScopeVersion

// ============================================================================
// TRANSFORM TYPES
// ============================================================================

// Re-export transform types from engine package for public use.
type (
	// TransformKind identifies the type of transform operation.
	TransformKind = engine.TransformKind

	// TransformOp is a single compiled transform operation.
	TransformOp = engine.TransformOp
)

// TransformKind constants.
const (
	TransformRemove = engine.TransformRemove
	TransformRedact = engine.TransformRedact
	TransformRename = engine.TransformRename
	TransformAdd    = engine.TransformAdd
)

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

// ============================================================================
// TRANSFORM FUNCTIONS
// ============================================================================

// LogTransformFunc applies a single transform operation to a log record of type T.
// Consumers implement this function to bridge their record type to the policy engine.
// Returns true if the targeted field was present (hit), false if absent (miss).
type LogTransformFunc[T any] func(record T, op TransformOp) bool

// ============================================================================
// EVALUATION OPTIONS
// ============================================================================

// logOptions holds optional configuration for log evaluation.
type logOptions[T any] struct {
	transform LogTransformFunc[T]
}

// LogOption configures optional behavior for EvaluateLog.
type LogOption[T any] func(*logOptions[T])

// WithLogTransform sets a transform function that is called for each transform
// operation on the winning policy. The function is called once per TransformOp,
// in order: removes, redacts, renames, adds.
func WithLogTransform[T any](fn LogTransformFunc[T]) LogOption[T] {
	return func(o *logOptions[T]) {
		o.transform = fn
	}
}
