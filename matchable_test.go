package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSimpleLogMatcherAllFields(t *testing.T) {
	record := &SimpleLogRecord{
		Body:         []byte("log body"),
		SeverityText: []byte("INFO"),
		TraceID:      []byte("trace-123"),
		SpanID:       []byte("span-456"),
		EventName:    []byte("user.login"),
		LogAttributes: map[string]any{
			"user.id": "12345",
		},
		ResourceAttributes: map[string]any{
			"service.name": "auth-service",
		},
		ScopeAttributes: map[string]any{
			"scope.name": "auth",
		},
	}

	// Test all log fields
	assert.Equal(t, []byte("log body"), SimpleLogMatcher(record, LogFieldRef{Field: LogFieldBody}))
	assert.Equal(t, []byte("INFO"), SimpleLogMatcher(record, LogFieldRef{Field: LogFieldSeverityText}))
	assert.Equal(t, []byte("trace-123"), SimpleLogMatcher(record, LogFieldRef{Field: LogFieldTraceID}))
	assert.Equal(t, []byte("span-456"), SimpleLogMatcher(record, LogFieldRef{Field: LogFieldSpanID}))
	assert.Equal(t, []byte("user.login"), SimpleLogMatcher(record, LogFieldRef{Field: LogFieldEventName}))

	// Test unknown field returns nil
	assert.Nil(t, SimpleLogMatcher(record, LogFieldRef{Field: LogField(999)}))

	// Test attribute lookups using constructor functions
	assert.Equal(t, []byte("12345"), SimpleLogMatcher(record, LogAttr("user.id")))
	assert.Equal(t, []byte("auth-service"), SimpleLogMatcher(record, LogResourceAttr("service.name")))
	assert.Equal(t, []byte("auth"), SimpleLogMatcher(record, LogScopeAttr("scope.name")))
}

func TestSimpleMetricMatcherAllFields(t *testing.T) {
	record := &SimpleMetricRecord{
		Name:                   []byte("http.request.duration"),
		Description:            []byte("Duration of HTTP requests"),
		Unit:                   []byte("ms"),
		Type:                   []byte("histogram"),
		AggregationTemporality: []byte("cumulative"),
		DatapointAttributes: map[string]any{
			"http.method": "GET",
		},
		ResourceAttributes: map[string]any{
			"service.name": "api-gateway",
		},
		ScopeAttributes: map[string]any{
			"scope.version": "1.0.0",
		},
	}

	// Test all metric fields
	assert.Equal(t, []byte("http.request.duration"), SimpleMetricMatcher(record, MetricFieldRef{Field: MetricFieldName}))
	assert.Equal(t, []byte("Duration of HTTP requests"), SimpleMetricMatcher(record, MetricFieldRef{Field: MetricFieldDescription}))
	assert.Equal(t, []byte("ms"), SimpleMetricMatcher(record, MetricFieldRef{Field: MetricFieldUnit}))
	assert.Equal(t, []byte("histogram"), SimpleMetricMatcher(record, MetricFieldRef{Field: MetricFieldType}))
	assert.Equal(t, []byte("cumulative"), SimpleMetricMatcher(record, MetricFieldRef{Field: MetricFieldAggregationTemporality}))

	// Test unknown field returns nil
	assert.Nil(t, SimpleMetricMatcher(record, MetricFieldRef{Field: MetricField(999)}))

	// Test attribute lookups using constructor functions
	assert.Equal(t, []byte("GET"), SimpleMetricMatcher(record, DatapointAttr("http.method")))
	assert.Equal(t, []byte("api-gateway"), SimpleMetricMatcher(record, MetricResourceAttr("service.name")))
	assert.Equal(t, []byte("1.0.0"), SimpleMetricMatcher(record, MetricScopeAttr("scope.version")))
}

func TestSimpleSpanMatcherAllFields(t *testing.T) {
	record := &SimpleSpanRecord{
		Name:         []byte("GET /api/users"),
		TraceID:      []byte("trace-abc123"),
		SpanID:       []byte("span-def456"),
		ParentSpanID: []byte("span-parent"),
		TraceState:   []byte("vendor=value"),
		Kind:         []byte("server"),
		Status:       []byte("ok"),
		EventNames:   [][]byte{[]byte("exception"), []byte("log")},
		EventAttributes: []map[string]any{
			{"exception.type": "NullPointerException"},
			{"log.message": "Request received"},
		},
		LinkTraceIDs: [][]byte{[]byte("linked-trace-1"), []byte("linked-trace-2")},
		LinkAttributes: []map[string]any{
			{"link.reason": "caused_by"},
		},
		SpanAttributes: map[string]any{
			"http.method": "GET",
		},
		ResourceAttributes: map[string]any{
			"service.name": "user-service",
		},
		ScopeAttributes: map[string]any{
			"scope.name": "http",
		},
	}

	// Test all span fields
	assert.Equal(t, []byte("GET /api/users"), SimpleSpanMatcher(record, TraceFieldRef{Field: TraceFieldName}))
	assert.Equal(t, []byte("trace-abc123"), SimpleSpanMatcher(record, TraceFieldRef{Field: TraceFieldTraceID}))
	assert.Equal(t, []byte("span-def456"), SimpleSpanMatcher(record, TraceFieldRef{Field: TraceFieldSpanID}))
	assert.Equal(t, []byte("span-parent"), SimpleSpanMatcher(record, TraceFieldRef{Field: TraceFieldParentSpanID}))
	assert.Equal(t, []byte("vendor=value"), SimpleSpanMatcher(record, TraceFieldRef{Field: TraceFieldTraceState}))
	assert.Equal(t, []byte("server"), SimpleSpanMatcher(record, TraceFieldRef{Field: TraceFieldKind}))
	assert.Equal(t, []byte("ok"), SimpleSpanMatcher(record, TraceFieldRef{Field: TraceFieldStatus}))

	// Test event name returns first event
	assert.Equal(t, []byte("exception"), SimpleSpanMatcher(record, TraceFieldRef{Field: TraceFieldEventName}))

	// Test link trace ID returns first link
	assert.Equal(t, []byte("linked-trace-1"), SimpleSpanMatcher(record, TraceFieldRef{Field: TraceFieldLinkTraceID}))

	// Test unknown field returns nil
	assert.Nil(t, SimpleSpanMatcher(record, TraceFieldRef{Field: TraceField(999)}))

	// Test attribute lookups using constructor functions
	assert.Equal(t, []byte("GET"), SimpleSpanMatcher(record, SpanAttr("http.method")))
	assert.Equal(t, []byte("user-service"), SimpleSpanMatcher(record, TraceResourceAttr("service.name")))
	assert.Equal(t, []byte("http"), SimpleSpanMatcher(record, TraceScopeAttr("scope.name")))

	// Test event attribute lookup (returns first event's attribute)
	assert.Equal(t, []byte("NullPointerException"), SimpleSpanMatcher(record, SpanEventAttr("exception.type")))

	// Test link attribute lookup (returns first link's attribute)
	assert.Equal(t, []byte("caused_by"), SimpleSpanMatcher(record, SpanLinkAttr("link.reason")))
}

func TestSimpleSpanMatcherEmptyEvents(t *testing.T) {
	// Test span with no events
	record := &SimpleSpanRecord{
		Name: []byte("test span"),
	}

	// Event name should return nil when no events
	assert.Nil(t, SimpleSpanMatcher(record, TraceFieldRef{Field: TraceFieldEventName}))

	// Link trace ID should return nil when no links
	assert.Nil(t, SimpleSpanMatcher(record, TraceFieldRef{Field: TraceFieldLinkTraceID}))

	// Event attribute should return nil when no events
	assert.Nil(t, SimpleSpanMatcher(record, SpanEventAttr("exception.type")))

	// Link attribute should return nil when no links
	assert.Nil(t, SimpleSpanMatcher(record, SpanLinkAttr("link.reason")))
}

func TestTraversePathNested(t *testing.T) {
	record := &SimpleLogRecord{
		LogAttributes: map[string]any{
			"http": map[string]any{
				"request": map[string]any{
					"headers": map[string]any{
						"content-type": "application/json",
					},
				},
			},
		},
	}

	// Test deeply nested path
	ref := LogAttr("http", "request", "headers", "content-type")
	assert.Equal(t, []byte("application/json"), SimpleLogMatcher(record, ref))

	// Test partial path returns nil (not a leaf value)
	refPartial := LogAttr("http", "request")
	assert.Nil(t, SimpleLogMatcher(record, refPartial))

	// Test non-existent nested path
	refMissing := LogAttr("http", "response", "status")
	assert.Nil(t, SimpleLogMatcher(record, refMissing))
}

func TestTraversePathWithByteValues(t *testing.T) {
	record := &SimpleLogRecord{
		LogAttributes: map[string]any{
			"binary_data": []byte{0x01, 0x02, 0x03},
		},
	}

	ref := LogAttr("binary_data")
	assert.Equal(t, []byte{0x01, 0x02, 0x03}, SimpleLogMatcher(record, ref))
}

func TestTraversePathEmptyPath(t *testing.T) {
	record := &SimpleLogRecord{
		LogAttributes: map[string]any{
			"key": "value",
		},
	}

	// Empty path should return nil - use struct literal for empty path
	ref := LogFieldRef{AttrScope: AttrScopeRecord, AttrPath: []string{}}
	assert.Nil(t, SimpleLogMatcher(record, ref))
}

func TestTraversePathNilMap(t *testing.T) {
	record := &SimpleLogRecord{
		// LogAttributes is nil
	}

	ref := LogAttr("key")
	assert.Nil(t, SimpleLogMatcher(record, ref))
}
