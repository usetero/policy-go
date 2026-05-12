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

// SamplingMode constants re-exported from proto.
const (
	SamplingModeUnspecified  = policyv1.SamplingMode_SAMPLING_MODE_UNSPECIFIED
	SamplingModeHashSeed     = policyv1.SamplingMode_SAMPLING_MODE_HASH_SEED
	SamplingModeProportional = policyv1.SamplingMode_SAMPLING_MODE_PROPORTIONAL
	SamplingModeEqualizing   = policyv1.SamplingMode_SAMPLING_MODE_EQUALIZING
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

// SpanSamplingThreshold creates a reference to the sampling threshold virtual field.
// Used for writing the effective th value back to tracestate after sampling.
var SpanSamplingThreshold = engine.SpanSamplingThreshold

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

// ApplyLogTransform applies a single TransformOp to a record via the
// LogConsumer primitives. The engine calls this for every op on a matched
// policy; it's exposed publicly so tests can exercise the spec semantics
// directly without going through the full evaluation path.
func ApplyLogTransform[T any](rec T, op TransformOp, c *LogAccessor[T]) bool {
	return engine.ApplyLogTransform(rec, op, c)
}

// ============================================================================
// CONSUMER ACCESSORS
// ============================================================================

// Consumers bridge a user record type T to the policy engine via accessor
// functions. Instead of implementing an interface, consumers simply configure
// the accessors they need using the constructor and option functions below.
// The engine builds every high-level behavior — pattern matching, existence
// checks, redact with regex templates, rename with upsert, add-or-overwrite —
// on top of these primitives. New spec features that extend TransformOp are
// absorbed by the library without touching consumers.
type (
	// LogAccessor provides accessor functions for log records.
	// Use NewLogConsumer to configure it with your Value/Exists/Set/ Delete/Move functions.
	LogAccessor[T any] = engine.LogAccessor[T]

	// MetricAccessor provides accessor functions for metric records.
	// Use NewMetricConsumer to configure it with your Value/Exists functions.
	MetricAccessor[T any] = engine.MetricAccessor[T]

	// TraceAccessor provides accessor functions for span records.
	// Use NewTraceConsumer to configure it with your Value/Exists/Set functions.
	TraceAccessor[T any] = engine.TraceAccessor[T]
)

// ============================================================================
// LOG CONSUMER ACCESSORS
// ============================================================================

// NewLogConsumer creates a LogAccessor configured with the provided accessor functions.
// All functions are optional; nil functions will cause panics if called.
// Example:
//
//	consumer := policy.NewLogConsumer(
//		policy.WithLogValue(func(r *MyLogRecord, ref policy.LogFieldRef) []byte {
//			// return field value
//		}),
//		policy.WithLogExists(func(r *MyLogRecord, ref policy.LogFieldRef) bool {
//			// return whether field exists
//		}),
//		policy.WithLogSet(func(r *MyLogRecord, ref policy.LogFieldRef, value string) {
//			// set field value
//		}),
//		policy.WithLogDelete(func(r *MyLogRecord, ref policy.LogFieldRef) bool {
//			// delete field
//			return true
//		}),
//		policy.WithLogMove(func(r *MyLogRecord, from, to policy.LogFieldRef) {
//			// move value from to
//		}),
//	)
func NewLogConsumer[T any](opts ...LogAccessorOption[T]) *LogAccessor[T] {
	a := &LogAccessor[T]{}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// LogAccessorOption configures a LogAccessor.
type LogAccessorOption[T any] func(*LogAccessor[T])

// WithLogValue sets the Value accessor function.
// The function should return nil when the field is absent OR when its
// underlying value is not a string — the engine relies on this for
// regex-redact's "non-string is a no-op" rule.
func WithLogValue[T any](f func(T, LogFieldRef) []byte) LogAccessorOption[T] {
	return func(a *LogAccessor[T]) {
		a.Value = f
	}
}

// WithLogExists sets the Exists accessor function.
func WithLogExists[T any](f func(T, LogFieldRef) bool) LogAccessorOption[T] {
	return func(a *LogAccessor[T]) {
		a.Exists = f
	}
}

// WithLogSet sets the Set accessor function.
func WithLogSet[T any](f func(T, LogFieldRef, string)) LogAccessorOption[T] {
	return func(a *LogAccessor[T]) {
		a.Set = f
	}
}

// WithLogDelete sets the Delete accessor function.
func WithLogDelete[T any](f func(T, LogFieldRef) bool) LogAccessorOption[T] {
	return func(a *LogAccessor[T]) {
		a.Delete = f
	}
}

// WithLogMove sets the Move accessor function.
func WithLogMove[T any](f func(T, LogFieldRef, LogFieldRef)) LogAccessorOption[T] {
	return func(a *LogAccessor[T]) {
		a.Move = f
	}
}

// ============================================================================
// METRIC CONSUMER ACCESSORS
// ============================================================================

// NewMetricConsumer creates a MetricAccessor configured with the provided
// accessor functions.
func NewMetricConsumer[T any](opts ...MetricAccessorOption[T]) *MetricAccessor[T] {
	a := &MetricAccessor[T]{}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// MetricAccessorOption configures a MetricAccessor.
type MetricAccessorOption[T any] func(*MetricAccessor[T])

// WithMetricValue sets the Value accessor function.
func WithMetricValue[T any](f func(T, MetricFieldRef) []byte) MetricAccessorOption[T] {
	return func(a *MetricAccessor[T]) {
		a.Value = f
	}
}

// WithMetricExists sets the Exists accessor function.
func WithMetricExists[T any](f func(T, MetricFieldRef) bool) MetricAccessorOption[T] {
	return func(a *MetricAccessor[T]) {
		a.Exists = f
	}
}

// ============================================================================
// TRACE CONSUMER ACCESSORS
// ============================================================================

// NewTraceConsumer creates a TraceAccessor configured with the provided
// accessor functions. Use this for span records where you need to write
// the sampling threshold back to tracestate after a sampling decision.
func NewTraceConsumer[T any](opts ...TraceAccessorOption[T]) *TraceAccessor[T] {
	a := &TraceAccessor[T]{}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// TraceAccessorOption configures a TraceAccessor.
type TraceAccessorOption[T any] func(*TraceAccessor[T])

// WithTraceValue sets the Value accessor function.
func WithTraceValue[T any](f func(T, TraceFieldRef) []byte) TraceAccessorOption[T] {
	return func(a *TraceAccessor[T]) {
		a.Value = f
	}
}

// WithTraceExists sets the Exists accessor function.
func WithTraceExists[T any](f func(T, TraceFieldRef) bool) TraceAccessorOption[T] {
	return func(a *TraceAccessor[T]) {
		a.Exists = f
	}
}

// WithTraceSet sets the Set accessor function.
func WithTraceSet[T any](f func(T, TraceFieldRef, string)) TraceAccessorOption[T] {
	return func(a *TraceAccessor[T]) {
		a.Set = f
	}
}

// ============================================================================
// LOG CONSUMER TYPE ALIASES
// ============================================================================

// LogConsumer is a type alias for LogAccessor for backward compatibility.
type LogConsumer[T any] = LogAccessor[T]

// MetricConsumer is a type alias for MetricAccessor for backward compatibility.
type MetricConsumer[T any] = MetricAccessor[T]

// TraceConsumer is a type alias for TraceAccessor for backward compatibility.
type TraceConsumer[T any] = TraceAccessor[T]
