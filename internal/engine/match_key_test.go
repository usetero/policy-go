package engine

import (
	"testing"

	"github.com/stretchr/testify/assert"
	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
)

// ============================================================================
// FieldRef Tests
// ============================================================================

func TestLogFieldRef(t *testing.T) {
	tests := []struct {
		name           string
		ref            LogFieldRef
		isField        bool
		isAttribute    bool
		isResourceAttr bool
		isScopeAttr    bool
		isRecordAttr   bool
	}{
		{
			name:    "LogBody is a field",
			ref:     LogBody(),
			isField: true,
		},
		{
			name:    "LogSeverityText is a field",
			ref:     LogSeverityText(),
			isField: true,
		},
		{
			name:    "LogTraceID is a field",
			ref:     LogTraceID(),
			isField: true,
		},
		{
			name:    "LogSpanID is a field",
			ref:     LogSpanID(),
			isField: true,
		},
		{
			name:         "LogAttr is a record attribute",
			ref:          LogAttr("key"),
			isAttribute:  true,
			isRecordAttr: true,
		},
		{
			name:           "LogResourceAttr is a resource attribute",
			ref:            LogResourceAttr("service.name"),
			isAttribute:    true,
			isResourceAttr: true,
		},
		{
			name:        "LogScopeAttr is a scope attribute",
			ref:         LogScopeAttr("library.name"),
			isAttribute: true,
			isScopeAttr: true,
		},
		{
			name:         "Nested LogAttr path",
			ref:          LogAttr("http", "request", "method"),
			isAttribute:  true,
			isRecordAttr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.isField, tt.ref.IsField())
			assert.Equal(t, tt.isAttribute, tt.ref.IsAttribute())
			assert.Equal(t, tt.isResourceAttr, tt.ref.IsResourceAttr())
			assert.Equal(t, tt.isScopeAttr, tt.ref.IsScopeAttr())
			assert.Equal(t, tt.isRecordAttr, tt.ref.IsRecordAttr())
			// Log refs should never be event or link attrs
			assert.False(t, tt.ref.IsEventAttr())
			assert.False(t, tt.ref.IsLinkAttr())
		})
	}
}

func TestMetricFieldRef(t *testing.T) {
	tests := []struct {
		name           string
		ref            MetricFieldRef
		isField        bool
		isAttribute    bool
		isResourceAttr bool
		isScopeAttr    bool
		isRecordAttr   bool
		expectedField  MetricField
	}{
		{
			name:          "MetricName is a field",
			ref:           MetricName(),
			isField:       true,
			expectedField: MetricFieldName,
		},
		{
			name:          "MetricDescription is a field",
			ref:           MetricDescription(),
			isField:       true,
			expectedField: MetricFieldDescription,
		},
		{
			name:          "MetricUnit is a field",
			ref:           MetricUnit(),
			isField:       true,
			expectedField: MetricFieldUnit,
		},
		{
			name:          "MetricType is a field",
			ref:           MetricType(),
			isField:       true,
			expectedField: MetricFieldType,
		},
		{
			name:          "MetricAggregationTemporality is a field",
			ref:           MetricAggregationTemporality(),
			isField:       true,
			expectedField: MetricFieldAggregationTemporality,
		},
		{
			name:         "DatapointAttr is a record attribute",
			ref:          DatapointAttr("key"),
			isAttribute:  true,
			isRecordAttr: true,
		},
		{
			name:           "MetricResourceAttr is a resource attribute",
			ref:            MetricResourceAttr("service.name"),
			isAttribute:    true,
			isResourceAttr: true,
		},
		{
			name:        "MetricScopeAttr is a scope attribute",
			ref:         MetricScopeAttr("library.name"),
			isAttribute: true,
			isScopeAttr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.isField, tt.ref.IsField())
			assert.Equal(t, tt.isAttribute, tt.ref.IsAttribute())
			assert.Equal(t, tt.isResourceAttr, tt.ref.IsResourceAttr())
			assert.Equal(t, tt.isScopeAttr, tt.ref.IsScopeAttr())
			assert.Equal(t, tt.isRecordAttr, tt.ref.IsRecordAttr())
			if tt.isField {
				assert.Equal(t, tt.expectedField, tt.ref.Field)
			}
			// Metric refs should never be event or link attrs
			assert.False(t, tt.ref.IsEventAttr())
			assert.False(t, tt.ref.IsLinkAttr())
		})
	}
}

func TestTraceFieldRef(t *testing.T) {
	tests := []struct {
		name           string
		ref            TraceFieldRef
		isField        bool
		isAttribute    bool
		isResourceAttr bool
		isScopeAttr    bool
		isRecordAttr   bool
		isEventAttr    bool
		isLinkAttr     bool
		expectedField  TraceField
	}{
		{
			name:          "SpanName is a field",
			ref:           SpanName(),
			isField:       true,
			expectedField: TraceFieldName,
		},
		{
			name:          "SpanTraceID is a field",
			ref:           SpanTraceID(),
			isField:       true,
			expectedField: TraceFieldTraceID,
		},
		{
			name:          "SpanSpanID is a field",
			ref:           SpanSpanID(),
			isField:       true,
			expectedField: TraceFieldSpanID,
		},
		{
			name:          "SpanParentSpanID is a field",
			ref:           SpanParentSpanID(),
			isField:       true,
			expectedField: TraceFieldParentSpanID,
		},
		{
			name:          "SpanTraceState is a field",
			ref:           SpanTraceState(),
			isField:       true,
			expectedField: TraceFieldTraceState,
		},
		{
			name:          "SpanKind is a field",
			ref:           SpanKind(),
			isField:       true,
			expectedField: TraceFieldKind,
		},
		{
			name:          "SpanStatus is a field",
			ref:           SpanStatus(),
			isField:       true,
			expectedField: TraceFieldStatus,
		},
		{
			name:          "SpanEventName is a field",
			ref:           SpanEventName(),
			isField:       true,
			expectedField: TraceFieldEventName,
		},
		{
			name:          "SpanLinkTraceID is a field",
			ref:           SpanLinkTraceID(),
			isField:       true,
			expectedField: TraceFieldLinkTraceID,
		},
		{
			name:          "TraceScopeSchemaURL is a field",
			ref:           TraceScopeSchemaURL(),
			isField:       true,
			expectedField: TraceFieldScopeSchemaURL,
		},
		{
			name:          "TraceScopeName is a field",
			ref:           TraceScopeName(),
			isField:       true,
			expectedField: TraceFieldScopeName,
		},
		{
			name:          "TraceScopeVersion is a field",
			ref:           TraceScopeVersion(),
			isField:       true,
			expectedField: TraceFieldScopeVersion,
		},
		{
			name:         "SpanAttr is a record attribute",
			ref:          SpanAttr("http.method"),
			isAttribute:  true,
			isRecordAttr: true,
		},
		{
			name:           "TraceResourceAttr is a resource attribute",
			ref:            TraceResourceAttr("service.name"),
			isAttribute:    true,
			isResourceAttr: true,
		},
		{
			name:        "TraceScopeAttr is a scope attribute",
			ref:         TraceScopeAttr("library.name"),
			isAttribute: true,
			isScopeAttr: true,
		},
		{
			name:        "SpanEventAttr is an event attribute",
			ref:         SpanEventAttr("exception.message"),
			isAttribute: true,
			isEventAttr: true,
		},
		{
			name:        "SpanLinkAttr is a link attribute",
			ref:         SpanLinkAttr("link.context"),
			isAttribute: true,
			isLinkAttr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.isField, tt.ref.IsField())
			assert.Equal(t, tt.isAttribute, tt.ref.IsAttribute())
			assert.Equal(t, tt.isResourceAttr, tt.ref.IsResourceAttr())
			assert.Equal(t, tt.isScopeAttr, tt.ref.IsScopeAttr())
			assert.Equal(t, tt.isRecordAttr, tt.ref.IsRecordAttr())
			assert.Equal(t, tt.isEventAttr, tt.ref.IsEventAttr())
			assert.Equal(t, tt.isLinkAttr, tt.ref.IsLinkAttr())
			if tt.isField {
				assert.Equal(t, tt.expectedField, tt.ref.Field)
			}
		})
	}
}

func TestFieldRefAttrPath(t *testing.T) {
	tests := []struct {
		name         string
		ref          LogFieldRef
		expectedPath []string
	}{
		{
			name:         "single key",
			ref:          LogAttr("key"),
			expectedPath: []string{"key"},
		},
		{
			name:         "nested path",
			ref:          LogAttr("http", "request", "method"),
			expectedPath: []string{"http", "request", "method"},
		},
		{
			name:         "empty path for field",
			ref:          LogBody(),
			expectedPath: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectedPath, tt.ref.AttrPath)
		})
	}
}

// ============================================================================
// MatchKey Tests
// ============================================================================

func TestMatchKeyEquality(t *testing.T) {
	// Same field, same flags should produce same match key
	key1 := MatchKey[LogField]{
		Ref:             LogBody(),
		Negated:         false,
		CaseInsensitive: false,
	}
	key2 := MatchKey[LogField]{
		Ref:             LogBody(),
		Negated:         false,
		CaseInsensitive: false,
	}
	assert.Equal(t, key1, key2)

	// Different negation should produce different keys
	key3 := MatchKey[LogField]{
		Ref:             LogBody(),
		Negated:         true,
		CaseInsensitive: false,
	}
	assert.NotEqual(t, key1, key3)

	// Different case sensitivity should produce different keys
	key4 := MatchKey[LogField]{
		Ref:             LogBody(),
		Negated:         false,
		CaseInsensitive: true,
	}
	assert.NotEqual(t, key1, key4)

	// Different field should produce different keys
	key5 := MatchKey[LogField]{
		Ref:             LogSeverityText(),
		Negated:         false,
		CaseInsensitive: false,
	}
	assert.NotEqual(t, key1, key5)
}

func TestMatchKeyWithAttributes(t *testing.T) {
	// Same attribute path should be equal
	key1 := MatchKey[LogField]{
		Ref: LogAttr("http", "method"),
	}
	key2 := MatchKey[LogField]{
		Ref: LogAttr("http", "method"),
	}
	assert.Equal(t, key1, key2)

	// Different attribute path should be different
	key3 := MatchKey[LogField]{
		Ref: LogAttr("http", "status"),
	}
	assert.NotEqual(t, key1, key3)

	// Different scope should be different
	key4 := MatchKey[LogField]{
		Ref: LogResourceAttr("http", "method"),
	}
	assert.NotEqual(t, key1, key4)
}

// ============================================================================
// Proto Conversion Tests
// ============================================================================

func TestLogFieldFromProto(t *testing.T) {
	tests := []struct {
		proto    policyv1.LogField
		expected LogField
	}{
		{policyv1.LogField_LOG_FIELD_BODY, LogFieldBody},
		{policyv1.LogField_LOG_FIELD_SEVERITY_TEXT, LogFieldSeverityText},
		{policyv1.LogField_LOG_FIELD_TRACE_ID, LogFieldTraceID},
		{policyv1.LogField_LOG_FIELD_SPAN_ID, LogFieldSpanID},
		{policyv1.LogField_LOG_FIELD_EVENT_NAME, LogFieldEventName},
		{policyv1.LogField_LOG_FIELD_RESOURCE_SCHEMA_URL, LogFieldResourceSchemaURL},
		{policyv1.LogField_LOG_FIELD_SCOPE_SCHEMA_URL, LogFieldScopeSchemaURL},
		{policyv1.LogField_LOG_FIELD_UNSPECIFIED, LogFieldUnspecified},
	}

	for _, tt := range tests {
		t.Run(tt.proto.String(), func(t *testing.T) {
			result := logFieldFromProto(tt.proto)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMetricFieldFromProto(t *testing.T) {
	tests := []struct {
		proto    policyv1.MetricField
		expected MetricField
	}{
		{policyv1.MetricField_METRIC_FIELD_NAME, MetricFieldName},
		{policyv1.MetricField_METRIC_FIELD_DESCRIPTION, MetricFieldDescription},
		{policyv1.MetricField_METRIC_FIELD_UNIT, MetricFieldUnit},
		{policyv1.MetricField_METRIC_FIELD_RESOURCE_SCHEMA_URL, MetricFieldResourceSchemaURL},
		{policyv1.MetricField_METRIC_FIELD_SCOPE_SCHEMA_URL, MetricFieldScopeSchemaURL},
		{policyv1.MetricField_METRIC_FIELD_SCOPE_NAME, MetricFieldScopeName},
		{policyv1.MetricField_METRIC_FIELD_SCOPE_VERSION, MetricFieldScopeVersion},
		{policyv1.MetricField_METRIC_FIELD_UNSPECIFIED, MetricFieldUnspecified},
	}

	for _, tt := range tests {
		t.Run(tt.proto.String(), func(t *testing.T) {
			result := metricFieldFromProto(tt.proto)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTraceFieldFromProto(t *testing.T) {
	tests := []struct {
		proto    policyv1.TraceField
		expected TraceField
	}{
		{policyv1.TraceField_TRACE_FIELD_NAME, TraceFieldName},
		{policyv1.TraceField_TRACE_FIELD_TRACE_ID, TraceFieldTraceID},
		{policyv1.TraceField_TRACE_FIELD_SPAN_ID, TraceFieldSpanID},
		{policyv1.TraceField_TRACE_FIELD_PARENT_SPAN_ID, TraceFieldParentSpanID},
		{policyv1.TraceField_TRACE_FIELD_TRACE_STATE, TraceFieldTraceState},
		{policyv1.TraceField_TRACE_FIELD_RESOURCE_SCHEMA_URL, TraceFieldResourceSchemaURL},
		{policyv1.TraceField_TRACE_FIELD_SCOPE_SCHEMA_URL, TraceFieldScopeSchemaURL},
		{policyv1.TraceField_TRACE_FIELD_SCOPE_NAME, TraceFieldScopeName},
		{policyv1.TraceField_TRACE_FIELD_SCOPE_VERSION, TraceFieldScopeVersion},
		{policyv1.TraceField_TRACE_FIELD_UNSPECIFIED, TraceFieldUnspecified},
	}

	for _, tt := range tests {
		t.Run(tt.proto.String(), func(t *testing.T) {
			result := traceFieldFromProto(tt.proto)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFieldRefFromLogMatcher(t *testing.T) {
	tests := []struct {
		name     string
		matcher  *policyv1.LogMatcher
		expected LogFieldRef
	}{
		{
			name: "log field body",
			matcher: &policyv1.LogMatcher{
				Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
			},
			expected: LogFieldRef{Field: LogFieldBody},
		},
		{
			name: "log attribute",
			matcher: &policyv1.LogMatcher{
				Field: &policyv1.LogMatcher_LogAttribute{LogAttribute: &policyv1.AttributePath{Path: []string{"key"}}},
			},
			expected: LogFieldRef{AttrScope: AttrScopeRecord, AttrPath: []string{"key"}},
		},
		{
			name: "resource attribute",
			matcher: &policyv1.LogMatcher{
				Field: &policyv1.LogMatcher_ResourceAttribute{ResourceAttribute: &policyv1.AttributePath{Path: []string{"service.name"}}},
			},
			expected: LogFieldRef{AttrScope: AttrScopeResource, AttrPath: []string{"service.name"}},
		},
		{
			name: "scope attribute",
			matcher: &policyv1.LogMatcher{
				Field: &policyv1.LogMatcher_ScopeAttribute{ScopeAttribute: &policyv1.AttributePath{Path: []string{"library"}}},
			},
			expected: LogFieldRef{AttrScope: AttrScopeScope, AttrPath: []string{"library"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FieldRefFromLogMatcher(tt.matcher)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFieldRefFromMetricMatcher(t *testing.T) {
	tests := []struct {
		name     string
		matcher  *policyv1.MetricMatcher
		expected MetricFieldRef
	}{
		{
			name: "metric field name",
			matcher: &policyv1.MetricMatcher{
				Field: &policyv1.MetricMatcher_MetricField{MetricField: policyv1.MetricField_METRIC_FIELD_NAME},
			},
			expected: MetricFieldRef{Field: MetricFieldName},
		},
		{
			name: "datapoint attribute",
			matcher: &policyv1.MetricMatcher{
				Field: &policyv1.MetricMatcher_DatapointAttribute{DatapointAttribute: &policyv1.AttributePath{Path: []string{"host"}}},
			},
			expected: MetricFieldRef{AttrScope: AttrScopeRecord, AttrPath: []string{"host"}},
		},
		{
			name: "resource attribute",
			matcher: &policyv1.MetricMatcher{
				Field: &policyv1.MetricMatcher_ResourceAttribute{ResourceAttribute: &policyv1.AttributePath{Path: []string{"cloud.region"}}},
			},
			expected: MetricFieldRef{AttrScope: AttrScopeResource, AttrPath: []string{"cloud.region"}},
		},
		{
			name: "scope attribute",
			matcher: &policyv1.MetricMatcher{
				Field: &policyv1.MetricMatcher_ScopeAttribute{ScopeAttribute: &policyv1.AttributePath{Path: []string{"meter"}}},
			},
			expected: MetricFieldRef{AttrScope: AttrScopeScope, AttrPath: []string{"meter"}},
		},
		{
			name: "metric type",
			matcher: &policyv1.MetricMatcher{
				Field: &policyv1.MetricMatcher_MetricType{MetricType: policyv1.MetricType_METRIC_TYPE_GAUGE},
			},
			expected: MetricFieldRef{Field: MetricFieldType},
		},
		{
			name: "aggregation temporality",
			matcher: &policyv1.MetricMatcher{
				Field: &policyv1.MetricMatcher_AggregationTemporality{AggregationTemporality: policyv1.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA},
			},
			expected: MetricFieldRef{Field: MetricFieldAggregationTemporality},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FieldRefFromMetricMatcher(tt.matcher)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFieldRefFromTraceMatcher(t *testing.T) {
	tests := []struct {
		name     string
		matcher  *policyv1.TraceMatcher
		expected TraceFieldRef
	}{
		{
			name: "trace field name",
			matcher: &policyv1.TraceMatcher{
				Field: &policyv1.TraceMatcher_TraceField{TraceField: policyv1.TraceField_TRACE_FIELD_NAME},
			},
			expected: TraceFieldRef{Field: TraceFieldName},
		},
		{
			name: "span attribute",
			matcher: &policyv1.TraceMatcher{
				Field: &policyv1.TraceMatcher_SpanAttribute{SpanAttribute: &policyv1.AttributePath{Path: []string{"http.method"}}},
			},
			expected: TraceFieldRef{AttrScope: AttrScopeRecord, AttrPath: []string{"http.method"}},
		},
		{
			name: "resource attribute",
			matcher: &policyv1.TraceMatcher{
				Field: &policyv1.TraceMatcher_ResourceAttribute{ResourceAttribute: &policyv1.AttributePath{Path: []string{"service.name"}}},
			},
			expected: TraceFieldRef{AttrScope: AttrScopeResource, AttrPath: []string{"service.name"}},
		},
		{
			name: "scope attribute",
			matcher: &policyv1.TraceMatcher{
				Field: &policyv1.TraceMatcher_ScopeAttribute{ScopeAttribute: &policyv1.AttributePath{Path: []string{"tracer"}}},
			},
			expected: TraceFieldRef{AttrScope: AttrScopeScope, AttrPath: []string{"tracer"}},
		},
		{
			name: "event name",
			matcher: &policyv1.TraceMatcher{
				Field: &policyv1.TraceMatcher_EventName{EventName: "exception"},
			},
			expected: TraceFieldRef{Field: TraceFieldEventName},
		},
		{
			name: "event attribute",
			matcher: &policyv1.TraceMatcher{
				Field: &policyv1.TraceMatcher_EventAttribute{EventAttribute: &policyv1.AttributePath{Path: []string{"exception.message"}}},
			},
			expected: TraceFieldRef{AttrScope: AttrScopeEvent, AttrPath: []string{"exception.message"}},
		},
		{
			name: "link trace id",
			matcher: &policyv1.TraceMatcher{
				Field: &policyv1.TraceMatcher_LinkTraceId{LinkTraceId: "abc123"},
			},
			expected: TraceFieldRef{Field: TraceFieldLinkTraceID},
		},
		{
			name: "span kind",
			matcher: &policyv1.TraceMatcher{
				Field: &policyv1.TraceMatcher_SpanKind{SpanKind: policyv1.SpanKind_SPAN_KIND_SERVER},
			},
			expected: TraceFieldRef{Field: TraceFieldKind},
		},
		{
			name: "span status",
			matcher: &policyv1.TraceMatcher{
				Field: &policyv1.TraceMatcher_SpanStatus{SpanStatus: policyv1.SpanStatusCode_SPAN_STATUS_CODE_ERROR},
			},
			expected: TraceFieldRef{Field: TraceFieldStatus},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FieldRefFromTraceMatcher(tt.matcher)
			assert.Equal(t, tt.expected, result)
		})
	}
}
