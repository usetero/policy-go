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

// FieldSelector represents a field selector for a specific telemetry type.
// It can represent either a specific field (by enum value) or an attribute lookup.
type FieldSelector[T FieldType] struct {
	// Field is the field enum value.
	Field T
	// AttrScope specifies where to look for the attribute.
	AttrScope AttrScope
	// AttrPath is the attribute path for attribute lookups.
	// Supports nested access (e.g., ["http", "request", "method"]).
	AttrPath []string
}

// IsAttribute returns true if this selector is for an attribute lookup.
func (s FieldSelector[T]) IsAttribute() bool {
	return len(s.AttrPath) > 0
}

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

// FieldSelectorFromLogMatcher extracts a FieldSelector from a proto LogMatcher.
func FieldSelectorFromLogMatcher(m *policyv1.LogMatcher) FieldSelector[LogField] {
	switch f := m.GetField().(type) {
	case *policyv1.LogMatcher_LogField:
		return FieldSelector[LogField]{Field: logFieldFromProto(f.LogField)}
	case *policyv1.LogMatcher_LogAttribute:
		return FieldSelector[LogField]{AttrScope: AttrScopeRecord, AttrPath: f.LogAttribute.GetPath()}
	case *policyv1.LogMatcher_ResourceAttribute:
		return FieldSelector[LogField]{AttrScope: AttrScopeResource, AttrPath: f.ResourceAttribute.GetPath()}
	case *policyv1.LogMatcher_ScopeAttribute:
		return FieldSelector[LogField]{AttrScope: AttrScopeScope, AttrPath: f.ScopeAttribute.GetPath()}
	default:
		return FieldSelector[LogField]{}
	}
}

// FieldSelectorFromLogSampleKey extracts a FieldSelector from a proto LogSampleKey.
func FieldSelectorFromLogSampleKey(sk *policyv1.LogSampleKey) FieldSelector[LogField] {
	switch f := sk.GetField().(type) {
	case *policyv1.LogSampleKey_LogField:
		return FieldSelector[LogField]{Field: logFieldFromProto(f.LogField)}
	case *policyv1.LogSampleKey_LogAttribute:
		return FieldSelector[LogField]{AttrScope: AttrScopeRecord, AttrPath: f.LogAttribute.GetPath()}
	case *policyv1.LogSampleKey_ResourceAttribute:
		return FieldSelector[LogField]{AttrScope: AttrScopeResource, AttrPath: f.ResourceAttribute.GetPath()}
	case *policyv1.LogSampleKey_ScopeAttribute:
		return FieldSelector[LogField]{AttrScope: AttrScopeScope, AttrPath: f.ScopeAttribute.GetPath()}
	default:
		return FieldSelector[LogField]{}
	}
}

// FieldSelectorFromMetricMatcher extracts a FieldSelector from a proto MetricMatcher.
func FieldSelectorFromMetricMatcher(m *policyv1.MetricMatcher) FieldSelector[MetricField] {
	switch f := m.GetField().(type) {
	case *policyv1.MetricMatcher_MetricField:
		return FieldSelector[MetricField]{Field: metricFieldFromProto(f.MetricField)}
	case *policyv1.MetricMatcher_DatapointAttribute:
		return FieldSelector[MetricField]{AttrScope: AttrScopeRecord, AttrPath: f.DatapointAttribute.GetPath()}
	case *policyv1.MetricMatcher_ResourceAttribute:
		return FieldSelector[MetricField]{AttrScope: AttrScopeResource, AttrPath: f.ResourceAttribute.GetPath()}
	case *policyv1.MetricMatcher_ScopeAttribute:
		return FieldSelector[MetricField]{AttrScope: AttrScopeScope, AttrPath: f.ScopeAttribute.GetPath()}
	case *policyv1.MetricMatcher_MetricType:
		return FieldSelector[MetricField]{Field: MetricFieldType}
	case *policyv1.MetricMatcher_AggregationTemporality:
		return FieldSelector[MetricField]{Field: MetricFieldAggregationTemporality}
	default:
		return FieldSelector[MetricField]{}
	}
}

// FieldSelectorFromTraceMatcher extracts a FieldSelector from a proto TraceMatcher.
func FieldSelectorFromTraceMatcher(m *policyv1.TraceMatcher) FieldSelector[TraceField] {
	switch f := m.GetField().(type) {
	case *policyv1.TraceMatcher_TraceField:
		return FieldSelector[TraceField]{Field: traceFieldFromProto(f.TraceField)}
	case *policyv1.TraceMatcher_SpanAttribute:
		return FieldSelector[TraceField]{AttrScope: AttrScopeRecord, AttrPath: f.SpanAttribute.GetPath()}
	case *policyv1.TraceMatcher_ResourceAttribute:
		return FieldSelector[TraceField]{AttrScope: AttrScopeResource, AttrPath: f.ResourceAttribute.GetPath()}
	case *policyv1.TraceMatcher_ScopeAttribute:
		return FieldSelector[TraceField]{AttrScope: AttrScopeScope, AttrPath: f.ScopeAttribute.GetPath()}
	case *policyv1.TraceMatcher_EventName:
		return FieldSelector[TraceField]{Field: TraceFieldEventName}
	case *policyv1.TraceMatcher_EventAttribute:
		return FieldSelector[TraceField]{AttrScope: AttrScopeEvent, AttrPath: f.EventAttribute.GetPath()}
	case *policyv1.TraceMatcher_LinkTraceId:
		return FieldSelector[TraceField]{Field: TraceFieldLinkTraceID}
	case *policyv1.TraceMatcher_SpanKind:
		return FieldSelector[TraceField]{Field: TraceFieldKind}
	case *policyv1.TraceMatcher_SpanStatus:
		return FieldSelector[TraceField]{Field: TraceFieldStatus}
	default:
		return FieldSelector[TraceField]{}
	}
}

// MatchKey identifies a group of patterns that share the same field selector, negation, and case sensitivity.
// Patterns are grouped by MatchKey for efficient Hyperscan compilation.
type MatchKey[T FieldType] struct {
	Selector        FieldSelector[T]
	Negated         bool
	CaseInsensitive bool
}

// DatabaseEntry pairs a MatchKey with its compiled database.
type DatabaseEntry[T FieldType] struct {
	Key      MatchKey[T]
	Database *CompiledDatabase
}
