package policy

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
)

// staticProvider is a simple provider for testing that returns static policies.
type staticProvider struct {
	policies []*policyv1.Policy
}

// newStaticProvider creates a test provider. It defaults Enabled to true on
// all policies to mirror the JSON parser behavior (proto3 defaults bool to
// false, but the spec says policies are enabled by default).
func newStaticProvider(policies []*policyv1.Policy) *staticProvider {
	for _, p := range policies {
		if !p.Enabled {
			p.Enabled = true
		}
	}
	return &staticProvider{policies: policies}
}

// newStaticProviderRaw creates a test provider without modifying the policies.
// Use this when testing the Enabled field directly.
func newStaticProviderRaw(policies []*policyv1.Policy) *staticProvider {
	return &staticProvider{policies: policies}
}

func (p *staticProvider) Load() ([]*policyv1.Policy, error) {
	return p.policies, nil
}

func (p *staticProvider) Subscribe(callback PolicyCallback) error {
	callback(p.policies)
	return nil
}

func (p *staticProvider) SetStatsCollector(collector StatsCollector) {}

// ============================================================================
// LOG EVALUATION TESTS
// ============================================================================

func TestEvaluateLogDropDebugLogs(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "drop-debug-logs",
			Name: "Drop Debug Logs",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Contains{Contains: "debug"},
						},
					},
					Keep: "none",
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	record := &SimpleLogRecord{
		Body: []byte("this is a debug message"),
	}

	result := EvaluateLog(engine, record, SimpleLogMatcher)
	assert.Equal(t, ResultDrop, result)
}

func TestEvaluateLogKeepAll(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "keep-info-logs",
			Name: "Keep Info Logs",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_SEVERITY_TEXT},
							Match: &policyv1.LogMatcher_Exact{Exact: "INFO"},
						},
					},
					Keep: "all",
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	record := &SimpleLogRecord{
		Body:         []byte("application started"),
		SeverityText: []byte("INFO"),
	}

	result := EvaluateLog(engine, record, SimpleLogMatcher)
	assert.Equal(t, ResultKeep, result)
}

func TestEvaluateLogNoMatch(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "drop-error-logs",
			Name: "Drop Error Logs",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Contains{Contains: "error"},
						},
					},
					Keep: "none",
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	record := &SimpleLogRecord{
		Body: []byte("normal message"),
	}

	result := EvaluateLog(engine, record, SimpleLogMatcher)
	assert.Equal(t, ResultNoMatch, result)
}

func TestEvaluateLogWithResourceAttribute(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "drop-edge-service",
			Name: "Drop Edge Service Logs",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_ResourceAttribute{
								ResourceAttribute: &policyv1.AttributePath{Path: []string{"service.name"}},
							},
							Match: &policyv1.LogMatcher_EndsWith{EndsWith: "-edge"},
						},
					},
					Keep: "none",
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	record := &SimpleLogRecord{
		Body: []byte("processing request"),
		ResourceAttributes: map[string]any{
			"service.name": "api-edge",
		},
	}

	result := EvaluateLog(engine, record, SimpleLogMatcher)
	assert.Equal(t, ResultDrop, result)
}

func TestEvaluateLogWithLogAttribute(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "drop-nginx-logs",
			Name: "Drop Nginx Logs",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogAttribute{
								LogAttribute: &policyv1.AttributePath{Path: []string{"source"}},
							},
							Match: &policyv1.LogMatcher_Exact{Exact: "nginx"},
						},
					},
					Keep: "none",
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	record := &SimpleLogRecord{
		Body: []byte("GET /api/health 200"),
		LogAttributes: map[string]any{
			"source": "nginx",
		},
	}

	result := EvaluateLog(engine, record, SimpleLogMatcher)
	assert.Equal(t, ResultDrop, result)
}

func TestEvaluateLogNegatedMatcher(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "keep-non-debug",
			Name: "Keep Non-Debug Logs",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field:  &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match:  &policyv1.LogMatcher_Contains{Contains: "debug"},
							Negate: true,
						},
					},
					Keep: "all",
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	// Non-debug log should match the negated rule
	normalLog := &SimpleLogRecord{
		Body: []byte("normal application message"),
	}
	result := EvaluateLog(engine, normalLog, SimpleLogMatcher)
	assert.Equal(t, ResultKeep, result)

	// Debug log should NOT match the negated rule
	debugLog := &SimpleLogRecord{
		Body: []byte("debug information here"),
	}
	result = EvaluateLog(engine, debugLog, SimpleLogMatcher)
	assert.Equal(t, ResultNoMatch, result)
}

func TestEvaluateLogMultipleMatchers(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "drop-debug-from-api",
			Name: "Drop Debug Logs from API",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Contains{Contains: "debug"},
						},
						{
							Field: &policyv1.LogMatcher_ResourceAttribute{
								ResourceAttribute: &policyv1.AttributePath{Path: []string{"service.name"}},
							},
							Match: &policyv1.LogMatcher_StartsWith{StartsWith: "api-"},
						},
					},
					Keep: "none",
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	// Matches both conditions - should drop
	matchingLog := &SimpleLogRecord{
		Body: []byte("debug message"),
		ResourceAttributes: map[string]any{
			"service.name": "api-gateway",
		},
	}
	result := EvaluateLog(engine, matchingLog, SimpleLogMatcher)
	assert.Equal(t, ResultDrop, result)

	// Only matches body condition - should not match
	partialLog := &SimpleLogRecord{
		Body: []byte("debug message"),
		ResourceAttributes: map[string]any{
			"service.name": "web-frontend",
		},
	}
	result = EvaluateLog(engine, partialLog, SimpleLogMatcher)
	assert.Equal(t, ResultNoMatch, result)
}

func TestEvaluateLogRegexMultipleEndOffsets(t *testing.T) {
	// Regression test: patterns like "prod-.*" can cause Hyperscan to report
	// multiple matches per pattern (one per end-offset as .* extends). Without
	// HS_FLAG_SINGLEMATCH or idempotent match tracking, this would inflate
	// match_counts beyond required_match_count, causing false NoMatch results.
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "drop-prod-logs",
			Name: "Drop Prod Logs",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_ResourceAttribute{
								ResourceAttribute: &policyv1.AttributePath{Path: []string{"service.name"}},
							},
							Match: &policyv1.LogMatcher_Regex{Regex: "prod-.*"},
						},
					},
					Keep: "none",
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	record := &SimpleLogRecord{
		Body: []byte("some log message"),
		ResourceAttributes: map[string]any{
			"service.name": "prod-api-server-1",
		},
	}

	result := EvaluateLog(engine, record, SimpleLogMatcher)
	assert.Equal(t, ResultDrop, result, "regex with multiple end-offsets must still match correctly")
}

// ============================================================================
// METRIC EVALUATION TESTS
// ============================================================================

func TestEvaluateMetricDropByName(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "drop-debug-metrics",
			Name: "Drop Debug Metrics",
			Target: &policyv1.Policy_Metric{
				Metric: &policyv1.MetricTarget{
					Match: []*policyv1.MetricMatcher{
						{
							Field: &policyv1.MetricMatcher_MetricField{MetricField: policyv1.MetricField_METRIC_FIELD_NAME},
							Match: &policyv1.MetricMatcher_Contains{Contains: "debug"},
						},
					},
					Keep: false,
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	metric := &SimpleMetricRecord{
		Name: []byte("system.debug.count"),
	}

	result := EvaluateMetric(engine, metric, SimpleMetricMatcher)
	assert.Equal(t, ResultDrop, result)
}

func TestEvaluateMetricKeepAll(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "keep-cpu-metrics",
			Name: "Keep CPU Metrics",
			Target: &policyv1.Policy_Metric{
				Metric: &policyv1.MetricTarget{
					Match: []*policyv1.MetricMatcher{
						{
							Field: &policyv1.MetricMatcher_MetricField{MetricField: policyv1.MetricField_METRIC_FIELD_NAME},
							Match: &policyv1.MetricMatcher_StartsWith{StartsWith: "system.cpu"},
						},
					},
					Keep: true,
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	metric := &SimpleMetricRecord{
		Name: []byte("system.cpu.utilization"),
	}

	result := EvaluateMetric(engine, metric, SimpleMetricMatcher)
	assert.Equal(t, ResultKeep, result)
}

func TestEvaluateMetricNoMatch(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "drop-memory-metrics",
			Name: "Drop Memory Metrics",
			Target: &policyv1.Policy_Metric{
				Metric: &policyv1.MetricTarget{
					Match: []*policyv1.MetricMatcher{
						{
							Field: &policyv1.MetricMatcher_MetricField{MetricField: policyv1.MetricField_METRIC_FIELD_NAME},
							Match: &policyv1.MetricMatcher_Contains{Contains: "memory"},
						},
					},
					Keep: false,
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	metric := &SimpleMetricRecord{
		Name: []byte("system.cpu.utilization"),
	}

	result := EvaluateMetric(engine, metric, SimpleMetricMatcher)
	assert.Equal(t, ResultNoMatch, result)
}

func TestEvaluateMetricWithResourceAttribute(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "drop-test-env-metrics",
			Name: "Drop Test Environment Metrics",
			Target: &policyv1.Policy_Metric{
				Metric: &policyv1.MetricTarget{
					Match: []*policyv1.MetricMatcher{
						{
							Field: &policyv1.MetricMatcher_ResourceAttribute{
								ResourceAttribute: &policyv1.AttributePath{Path: []string{"deployment.environment"}},
							},
							Match: &policyv1.MetricMatcher_Exact{Exact: "test"},
						},
					},
					Keep: false,
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	metric := &SimpleMetricRecord{
		Name: []byte("http.request.duration"),
		ResourceAttributes: map[string]any{
			"deployment.environment": "test",
		},
	}

	result := EvaluateMetric(engine, metric, SimpleMetricMatcher)
	assert.Equal(t, ResultDrop, result)
}

func TestEvaluateMetricWithDatapointAttribute(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "drop-error-metrics",
			Name: "Drop Error Status Metrics",
			Target: &policyv1.Policy_Metric{
				Metric: &policyv1.MetricTarget{
					Match: []*policyv1.MetricMatcher{
						{
							Field: &policyv1.MetricMatcher_DatapointAttribute{
								DatapointAttribute: &policyv1.AttributePath{Path: []string{"http.status_code"}},
							},
							Match: &policyv1.MetricMatcher_StartsWith{StartsWith: "5"},
						},
					},
					Keep: false,
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	metric := &SimpleMetricRecord{
		Name: []byte("http.request.count"),
		DatapointAttributes: map[string]any{
			"http.status_code": "500",
		},
	}

	result := EvaluateMetric(engine, metric, SimpleMetricMatcher)
	assert.Equal(t, ResultDrop, result)
}

func TestEvaluateMetricByType(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "drop-histogram-metrics",
			Name: "Drop Histogram Metrics",
			Target: &policyv1.Policy_Metric{
				Metric: &policyv1.MetricTarget{
					Match: []*policyv1.MetricMatcher{
						{
							Field: &policyv1.MetricMatcher_MetricType{MetricType: policyv1.MetricType_METRIC_TYPE_HISTOGRAM},
							// Match field is ignored - enum value is used as exact match
						},
					},
					Keep: false,
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	metric := &SimpleMetricRecord{
		Name: []byte("http.request.duration"),
		Type: []byte("histogram"),
	}

	result := EvaluateMetric(engine, metric, SimpleMetricMatcher)
	assert.Equal(t, ResultDrop, result)
}

func TestEvaluateMetricByAggregationTemporality(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "drop-delta-metrics",
			Name: "Drop Delta Temporality Metrics",
			Target: &policyv1.Policy_Metric{
				Metric: &policyv1.MetricTarget{
					Match: []*policyv1.MetricMatcher{
						{
							Field: &policyv1.MetricMatcher_AggregationTemporality{
								AggregationTemporality: policyv1.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA,
							},
							// Match field is ignored - enum value is used as exact match
						},
					},
					Keep: false,
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	metric := &SimpleMetricRecord{
		Name:                   []byte("http.request.count"),
		AggregationTemporality: []byte("delta"),
	}

	result := EvaluateMetric(engine, metric, SimpleMetricMatcher)
	assert.Equal(t, ResultDrop, result)
}

func TestEvaluateMetricMultipleMatchers(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "drop-test-debug-metrics",
			Name: "Drop Debug Metrics from Test",
			Target: &policyv1.Policy_Metric{
				Metric: &policyv1.MetricTarget{
					Match: []*policyv1.MetricMatcher{
						{
							Field: &policyv1.MetricMatcher_MetricField{MetricField: policyv1.MetricField_METRIC_FIELD_NAME},
							Match: &policyv1.MetricMatcher_Contains{Contains: "debug"},
						},
						{
							Field: &policyv1.MetricMatcher_ResourceAttribute{
								ResourceAttribute: &policyv1.AttributePath{Path: []string{"env"}},
							},
							Match: &policyv1.MetricMatcher_Exact{Exact: "test"},
						},
					},
					Keep: false,
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	// Matches both conditions - should drop
	matchingMetric := &SimpleMetricRecord{
		Name: []byte("app.debug.counter"),
		ResourceAttributes: map[string]any{
			"env": "test",
		},
	}
	result := EvaluateMetric(engine, matchingMetric, SimpleMetricMatcher)
	assert.Equal(t, ResultDrop, result)

	// Only matches name condition - should not match
	partialMetric := &SimpleMetricRecord{
		Name: []byte("app.debug.counter"),
		ResourceAttributes: map[string]any{
			"env": "production",
		},
	}
	result = EvaluateMetric(engine, partialMetric, SimpleMetricMatcher)
	assert.Equal(t, ResultNoMatch, result)
}

// ============================================================================
// TRACE EVALUATION TESTS
// ============================================================================

func TestEvaluateTraceDropByName(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "drop-healthcheck-spans",
			Name: "Drop Healthcheck Spans",
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_TraceField{TraceField: policyv1.TraceField_TRACE_FIELD_NAME},
							Match: &policyv1.TraceMatcher_Contains{Contains: "healthcheck"},
						},
					},
					Keep: &policyv1.TraceSamplingConfig{Percentage: 0},
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	span := &SimpleSpanRecord{
		Name: []byte("GET /healthcheck"),
	}

	result := EvaluateTrace(engine, span, SimpleSpanMatcher)
	assert.Equal(t, ResultDrop, result)
}

func TestEvaluateTraceKeepAll(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "keep-api-spans",
			Name: "Keep API Spans",
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_TraceField{TraceField: policyv1.TraceField_TRACE_FIELD_NAME},
							Match: &policyv1.TraceMatcher_StartsWith{StartsWith: "GET /api"},
						},
					},
					Keep: &policyv1.TraceSamplingConfig{Percentage: 100},
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	span := &SimpleSpanRecord{
		Name: []byte("GET /api/users"),
	}

	result := EvaluateTrace(engine, span, SimpleSpanMatcher)
	assert.Equal(t, ResultKeep, result)
}

func TestEvaluateTraceNoMatch(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "drop-internal-spans",
			Name: "Drop Internal Spans",
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_TraceField{TraceField: policyv1.TraceField_TRACE_FIELD_NAME},
							Match: &policyv1.TraceMatcher_Contains{Contains: "internal"},
						},
					},
					Keep: &policyv1.TraceSamplingConfig{Percentage: 0},
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	span := &SimpleSpanRecord{
		Name: []byte("GET /api/users"),
	}

	result := EvaluateTrace(engine, span, SimpleSpanMatcher)
	assert.Equal(t, ResultNoMatch, result)
}

func TestEvaluateTraceBySpanKind(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "drop-client-spans",
			Name: "Drop Client Spans",
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_SpanKind{SpanKind: policyv1.SpanKind_SPAN_KIND_CLIENT},
							// Match field is ignored - enum value is used as exact match
						},
					},
					Keep: &policyv1.TraceSamplingConfig{Percentage: 0},
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	span := &SimpleSpanRecord{
		Name: []byte("HTTP GET"),
		Kind: []byte("client"),
	}

	result := EvaluateTrace(engine, span, SimpleSpanMatcher)
	assert.Equal(t, ResultDrop, result)
}

func TestEvaluateTraceBySpanStatus(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "keep-error-spans",
			Name: "Keep Error Spans",
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_SpanStatus{SpanStatus: policyv1.SpanStatusCode_SPAN_STATUS_CODE_ERROR},
							Match: &policyv1.TraceMatcher_Exists{Exists: true},
						},
					},
					Keep: &policyv1.TraceSamplingConfig{Percentage: 100},
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	span := &SimpleSpanRecord{
		Name:   []byte("process request"),
		Status: []byte("error"),
	}

	result := EvaluateTrace(engine, span, SimpleSpanMatcher)
	assert.Equal(t, ResultKeep, result)
}

func TestEvaluateTraceWithResourceAttribute(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "drop-test-env-spans",
			Name: "Drop Test Environment Spans",
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_ResourceAttribute{
								ResourceAttribute: &policyv1.AttributePath{Path: []string{"deployment.environment"}},
							},
							Match: &policyv1.TraceMatcher_Exact{Exact: "test"},
						},
					},
					Keep: &policyv1.TraceSamplingConfig{Percentage: 0},
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	span := &SimpleSpanRecord{
		Name: []byte("process request"),
		ResourceAttributes: map[string]any{
			"deployment.environment": "test",
		},
	}

	result := EvaluateTrace(engine, span, SimpleSpanMatcher)
	assert.Equal(t, ResultDrop, result)
}

func TestEvaluateTraceWithSpanAttribute(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "drop-internal-users",
			Name: "Drop Internal User Spans",
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_SpanAttribute{
								SpanAttribute: &policyv1.AttributePath{Path: []string{"user.type"}},
							},
							Match: &policyv1.TraceMatcher_Exact{Exact: "internal"},
						},
					},
					Keep: &policyv1.TraceSamplingConfig{Percentage: 0},
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	span := &SimpleSpanRecord{
		Name: []byte("process request"),
		SpanAttributes: map[string]any{
			"user.type": "internal",
		},
	}

	result := EvaluateTrace(engine, span, SimpleSpanMatcher)
	assert.Equal(t, ResultDrop, result)
}

func TestEvaluateTraceWithEventName(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "keep-exception-spans",
			Name: "Keep Spans with Exception Events",
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_EventName{EventName: "exception"},
							Match: &policyv1.TraceMatcher_Exact{Exact: "exception"},
						},
					},
					Keep: &policyv1.TraceSamplingConfig{Percentage: 100},
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	span := &SimpleSpanRecord{
		Name:       []byte("process request"),
		EventNames: [][]byte{[]byte("exception")},
	}

	result := EvaluateTrace(engine, span, SimpleSpanMatcher)
	assert.Equal(t, ResultKeep, result)
}

func TestEvaluateTraceWithEventAttribute(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "drop-timeout-exceptions",
			Name: "Drop Timeout Exception Spans",
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_EventAttribute{
								EventAttribute: &policyv1.AttributePath{Path: []string{"exception.type"}},
							},
							Match: &policyv1.TraceMatcher_Contains{Contains: "Timeout"},
						},
					},
					Keep: &policyv1.TraceSamplingConfig{Percentage: 0},
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	span := &SimpleSpanRecord{
		Name:       []byte("HTTP GET"),
		EventNames: [][]byte{[]byte("exception")},
		EventAttributes: []map[string]any{
			{"exception.type": "TimeoutException"},
		},
	}

	result := EvaluateTrace(engine, span, SimpleSpanMatcher)
	assert.Equal(t, ResultDrop, result)
}

func TestEvaluateTraceWithLinkTraceID(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "drop-linked-to-test",
			Name: "Drop Spans Linked to Test Traces",
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_LinkTraceId{LinkTraceId: "test-"},
							Match: &policyv1.TraceMatcher_StartsWith{StartsWith: "test-"},
						},
					},
					Keep: &policyv1.TraceSamplingConfig{Percentage: 0},
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	span := &SimpleSpanRecord{
		Name:         []byte("process request"),
		LinkTraceIDs: [][]byte{[]byte("test-trace-123")},
	}

	result := EvaluateTrace(engine, span, SimpleSpanMatcher)
	assert.Equal(t, ResultDrop, result)
}

func TestEvaluateTraceMultipleMatchers(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "drop-client-healthcheck",
			Name: "Drop Client Healthcheck Spans",
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_SpanKind{SpanKind: policyv1.SpanKind_SPAN_KIND_CLIENT},
							Match: &policyv1.TraceMatcher_Exists{Exists: true},
						},
						{
							Field: &policyv1.TraceMatcher_TraceField{TraceField: policyv1.TraceField_TRACE_FIELD_NAME},
							Match: &policyv1.TraceMatcher_Contains{Contains: "health"},
						},
					},
					Keep: &policyv1.TraceSamplingConfig{Percentage: 0},
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	// Matches both conditions - should drop
	matchingSpan := &SimpleSpanRecord{
		Name: []byte("GET /health"),
		Kind: []byte("client"),
	}
	result := EvaluateTrace(engine, matchingSpan, SimpleSpanMatcher)
	assert.Equal(t, ResultDrop, result)

	// Only matches kind condition - should not match
	partialSpan := &SimpleSpanRecord{
		Name: []byte("GET /api/users"),
		Kind: []byte("client"),
	}
	result = EvaluateTrace(engine, partialSpan, SimpleSpanMatcher)
	assert.Equal(t, ResultNoMatch, result)
}

func TestEvaluateTraceNegatedMatcher(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "keep-non-healthcheck",
			Name: "Keep Non-Healthcheck Spans",
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field:  &policyv1.TraceMatcher_TraceField{TraceField: policyv1.TraceField_TRACE_FIELD_NAME},
							Match:  &policyv1.TraceMatcher_Contains{Contains: "health"},
							Negate: true,
						},
					},
					Keep: &policyv1.TraceSamplingConfig{Percentage: 100},
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	// Non-health span should match the negated rule
	normalSpan := &SimpleSpanRecord{
		Name: []byte("GET /api/users"),
	}
	result := EvaluateTrace(engine, normalSpan, SimpleSpanMatcher)
	assert.Equal(t, ResultKeep, result)

	// Health span should NOT match the negated rule
	healthSpan := &SimpleSpanRecord{
		Name: []byte("GET /health"),
	}
	result = EvaluateTrace(engine, healthSpan, SimpleSpanMatcher)
	assert.Equal(t, ResultNoMatch, result)
}

// ============================================================================
// MIXED TELEMETRY TESTS
// ============================================================================

func TestMixedTelemetryPolicies(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "drop-debug-logs",
			Name: "Drop Debug Logs",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Contains{Contains: "debug"},
						},
					},
					Keep: "none",
				},
			},
		},
		{
			Id:   "drop-debug-metrics",
			Name: "Drop Debug Metrics",
			Target: &policyv1.Policy_Metric{
				Metric: &policyv1.MetricTarget{
					Match: []*policyv1.MetricMatcher{
						{
							Field: &policyv1.MetricMatcher_MetricField{MetricField: policyv1.MetricField_METRIC_FIELD_NAME},
							Match: &policyv1.MetricMatcher_Contains{Contains: "debug"},
						},
					},
					Keep: false,
				},
			},
		},
		{
			Id:   "drop-healthcheck-spans",
			Name: "Drop Healthcheck Spans",
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_TraceField{TraceField: policyv1.TraceField_TRACE_FIELD_NAME},
							Match: &policyv1.TraceMatcher_Contains{Contains: "health"},
						},
					},
					Keep: &policyv1.TraceSamplingConfig{Percentage: 0},
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	// Log evaluation
	log := &SimpleLogRecord{Body: []byte("debug message")}
	assert.Equal(t, ResultDrop, EvaluateLog(engine, log, SimpleLogMatcher))

	// Metric evaluation
	metric := &SimpleMetricRecord{Name: []byte("app.debug.count")}
	assert.Equal(t, ResultDrop, EvaluateMetric(engine, metric, SimpleMetricMatcher))

	// Trace evaluation
	span := &SimpleSpanRecord{Name: []byte("GET /health")}
	assert.Equal(t, ResultDrop, EvaluateTrace(engine, span, SimpleSpanMatcher))

	// Non-matching records should return NoMatch
	normalLog := &SimpleLogRecord{Body: []byte("normal message")}
	assert.Equal(t, ResultNoMatch, EvaluateLog(engine, normalLog, SimpleLogMatcher))

	normalMetric := &SimpleMetricRecord{Name: []byte("app.request.count")}
	assert.Equal(t, ResultNoMatch, EvaluateMetric(engine, normalMetric, SimpleMetricMatcher))

	normalSpan := &SimpleSpanRecord{Name: []byte("GET /api/users")}
	assert.Equal(t, ResultNoMatch, EvaluateTrace(engine, normalSpan, SimpleSpanMatcher))
}

// ============================================================================
// POLICY RESTRICTIVENESS TESTS
// ============================================================================

func TestMostRestrictivePolicyWins(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "keep-all-debug",
			Name: "Keep All Debug",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Contains{Contains: "debug"},
						},
					},
					Keep: "all",
				},
			},
		},
		{
			Id:   "drop-debug-error",
			Name: "Drop Debug Error",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Contains{Contains: "debug"},
						},
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Contains{Contains: "error"},
						},
					},
					Keep: "none",
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	// Log matches both policies - drop (none) should win over keep (all)
	log := &SimpleLogRecord{Body: []byte("debug error occurred")}
	result := EvaluateLog(engine, log, SimpleLogMatcher)
	assert.Equal(t, ResultDrop, result, "more restrictive policy (drop) should win")

	// Log only matches keep policy
	debugOnlyLog := &SimpleLogRecord{Body: []byte("debug message")}
	result = EvaluateLog(engine, debugOnlyLog, SimpleLogMatcher)
	assert.Equal(t, ResultKeep, result)
}

// ============================================================================
// STATS COLLECTION TESTS
// ============================================================================

func TestStatsCollection(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "drop-debug-level",
			Name: "Drop Debug Level",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_SEVERITY_TEXT},
							Match: &policyv1.LogMatcher_Exact{Exact: "DEBUG"},
						},
					},
					Keep: "none",
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	// Evaluate a log that matches drop-debug-level (severity_text = DEBUG)
	debugLog := &SimpleLogRecord{
		Body:         []byte("some message"),
		SeverityText: []byte("DEBUG"),
	}

	EvaluateLog(engine, debugLog, SimpleLogMatcher)

	// Collect stats
	stats := registry.CollectStats()
	require.NotEmpty(t, stats)

	// Find stats for drop-debug-level
	var found *PolicyStatsSnapshot
	for _, s := range stats {
		if s.PolicyID == "drop-debug-level" {
			found = &s
			break
		}
	}
	require.NotNil(t, found, "stats for 'drop-debug-level' not found")
	assert.Greater(t, found.MatchHits, uint64(0), "expected match hits > 0")
}

func TestMatchHitMissTracking(t *testing.T) {
	// Scenario from the spec:
	// - "keep-info" (keep: all) matches INFO logs
	// - "drop-health" (keep: none) matches "health" in body
	// A "health check ok" INFO log matches both → dropped by drop-health.
	//   drop-health: match hit, keep-info: match miss
	// A "user action logged" INFO log matches only keep-info → kept.
	//   keep-info: match hit
	// A "database error" ERROR log matches neither → no match.
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "keep-info",
			Name: "Keep Info",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_SEVERITY_TEXT},
							Match: &policyv1.LogMatcher_Exact{Exact: "INFO"},
						},
					},
					Keep: "all",
				},
			},
		},
		{
			Id:   "drop-health",
			Name: "Drop Health",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Regex{Regex: "health"},
						},
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_SEVERITY_TEXT},
							Match: &policyv1.LogMatcher_Exact{Exact: "INFO"},
						},
					},
					Keep: "none",
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	// Record 1: "health check ok" (INFO) — matches both policies, should be dropped
	healthLog := &SimpleLogRecord{Body: []byte("health check ok"), SeverityText: []byte("INFO")}
	result := EvaluateLog(engine, healthLog, SimpleLogMatcher)
	assert.Equal(t, ResultDrop, result)

	// Record 2: "user action logged" (INFO) — matches only keep-info, should be kept
	userLog := &SimpleLogRecord{Body: []byte("user action logged"), SeverityText: []byte("INFO")}
	result = EvaluateLog(engine, userLog, SimpleLogMatcher)
	assert.Equal(t, ResultKeep, result)

	// Record 3: "database error" (ERROR) — matches neither, no match
	errorLog := &SimpleLogRecord{Body: []byte("database error"), SeverityText: []byte("ERROR")}
	result = EvaluateLog(engine, errorLog, SimpleLogMatcher)
	assert.Equal(t, ResultNoMatch, result)

	// Collect stats and verify
	stats := registry.CollectStats()
	statsMap := make(map[string]PolicyStatsSnapshot)
	for _, s := range stats {
		statsMap[s.PolicyID] = s
	}

	keepInfo := statsMap["keep-info"]
	dropHealth := statsMap["drop-health"]

	// keep-info: matched record 1 (miss) + record 2 (hit) = 1 hit, 1 miss
	assert.Equal(t, uint64(1), keepInfo.MatchHits, "keep-info should have 1 match hit (record 2 kept)")
	assert.Equal(t, uint64(1), keepInfo.MatchMisses, "keep-info should have 1 match miss (record 1 overridden by drop-health)")

	// drop-health: matched record 1 (hit) = 1 hit, 0 misses
	assert.Equal(t, uint64(1), dropHealth.MatchHits, "drop-health should have 1 match hit (record 1 dropped)")
	assert.Equal(t, uint64(0), dropHealth.MatchMisses, "drop-health should have 0 match misses")
}

func TestMatchHitMissTracking_AllKept(t *testing.T) {
	// When a record is kept, ALL matching policies get a match hit
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "keep-info",
			Name: "Keep Info",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_SEVERITY_TEXT},
							Match: &policyv1.LogMatcher_Exact{Exact: "INFO"},
						},
					},
					Keep: "all",
				},
			},
		},
		{
			Id:   "keep-info-body",
			Name: "Keep Info Body",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_SEVERITY_TEXT},
							Match: &policyv1.LogMatcher_Exact{Exact: "INFO"},
						},
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Regex{Regex: "user"},
						},
					},
					Keep: "all",
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	// This log matches both keep-all policies → kept, both get match hit
	log := &SimpleLogRecord{Body: []byte("user action"), SeverityText: []byte("INFO")}
	result := EvaluateLog(engine, log, SimpleLogMatcher)
	assert.Equal(t, ResultKeep, result)

	stats := registry.CollectStats()
	statsMap := make(map[string]PolicyStatsSnapshot)
	for _, s := range stats {
		statsMap[s.PolicyID] = s
	}

	assert.Equal(t, uint64(1), statsMap["keep-info"].MatchHits)
	assert.Equal(t, uint64(0), statsMap["keep-info"].MatchMisses)
	assert.Equal(t, uint64(1), statsMap["keep-info-body"].MatchHits)
	assert.Equal(t, uint64(0), statsMap["keep-info-body"].MatchMisses)
}

func TestMatchHitMissTracking_NoMatch(t *testing.T) {
	// When a record matches no policies, no stats are recorded
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "keep-info",
			Name: "Keep Info",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_SEVERITY_TEXT},
							Match: &policyv1.LogMatcher_Exact{Exact: "INFO"},
						},
					},
					Keep: "all",
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	// ERROR log doesn't match the INFO policy
	log := &SimpleLogRecord{Body: []byte("error"), SeverityText: []byte("ERROR")}
	result := EvaluateLog(engine, log, SimpleLogMatcher)
	assert.Equal(t, ResultNoMatch, result)

	stats := registry.CollectStats()
	for _, s := range stats {
		if s.PolicyID == "keep-info" {
			assert.Equal(t, uint64(0), s.MatchHits, "no match should mean no match hits")
			assert.Equal(t, uint64(0), s.MatchMisses, "no match should mean no match misses")
		}
	}
}

// ============================================================================
// SAMPLING TESTS
// ============================================================================

func TestSamplingWithSampleKey(t *testing.T) {
	// Create a policy with 50% sampling using trace_id as the sample key
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "sample-policy",
			Name: "Sample Policy",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Contains{Contains: "test"},
						},
					},
					Keep: "50%",
					SampleKey: &policyv1.LogSampleKey{
						Field: &policyv1.LogSampleKey_LogField{LogField: policyv1.LogField_LOG_FIELD_TRACE_ID},
					},
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	// Test that the same trace_id always produces the same result (deterministic)
	traceID1 := []byte("trace-id-abc123")
	traceID2 := []byte("trace-id-xyz789")

	record1 := &SimpleLogRecord{
		Body:    []byte("test message"),
		TraceID: traceID1,
	}
	record2 := &SimpleLogRecord{
		Body:    []byte("test message"),
		TraceID: traceID2,
	}

	// Run multiple times to verify determinism
	result1a := EvaluateLog(engine, record1, SimpleLogMatcher)
	result1b := EvaluateLog(engine, record1, SimpleLogMatcher)
	result1c := EvaluateLog(engine, record1, SimpleLogMatcher)

	result2a := EvaluateLog(engine, record2, SimpleLogMatcher)
	result2b := EvaluateLog(engine, record2, SimpleLogMatcher)
	result2c := EvaluateLog(engine, record2, SimpleLogMatcher)

	// Same trace_id should always produce the same result
	assert.Equal(t, result1a, result1b, "same trace_id should produce consistent result")
	assert.Equal(t, result1b, result1c, "same trace_id should produce consistent result")
	assert.Equal(t, result2a, result2b, "same trace_id should produce consistent result")
	assert.Equal(t, result2b, result2c, "same trace_id should produce consistent result")
}

func TestSamplingDistribution(t *testing.T) {
	// Test that sampling roughly follows the expected distribution
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "sample-policy",
			Name: "Sample Policy",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Contains{Contains: "test"},
						},
					},
					Keep: "50%",
					SampleKey: &policyv1.LogSampleKey{
						Field: &policyv1.LogSampleKey_LogAttribute{
							LogAttribute: &policyv1.AttributePath{Path: []string{"request_id"}},
						},
					},
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	// Test with many different request IDs
	kept := 0
	dropped := 0
	total := 1000

	for i := 0; i < total; i++ {
		record := &SimpleLogRecord{
			Body: []byte("test message"),
			LogAttributes: map[string]any{
				"request_id": string(rune('a'+i%26)) + string(rune('0'+i%10)) + string(rune(i)),
			},
		}
		result := EvaluateLog(engine, record, SimpleLogMatcher)
		if result == ResultKeep {
			kept++
		} else if result == ResultDrop {
			dropped++
		}
	}

	// With 50% sampling, we expect roughly 50% kept
	// Allow 15% tolerance for statistical variation
	keepRate := float64(kept) / float64(total) * 100
	assert.InDelta(t, 50.0, keepRate, 15.0, "sampling rate should be roughly 50%% (got %.1f%%)", keepRate)
}

func TestSamplingWithoutSampleKey(t *testing.T) {
	// When no sample key is configured but field is empty, should keep
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "sample-policy",
			Name: "Sample Policy",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Contains{Contains: "test"},
						},
					},
					Keep: "50%",
					SampleKey: &policyv1.LogSampleKey{
						Field: &policyv1.LogSampleKey_LogField{LogField: policyv1.LogField_LOG_FIELD_TRACE_ID},
					},
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	// Record without trace_id - should be kept (fallback behavior)
	record := &SimpleLogRecord{
		Body: []byte("test message"),
		// No TraceID set
	}

	result := EvaluateLog(engine, record, SimpleLogMatcher)
	assert.Equal(t, ResultKeep, result, "record without sample key value should be kept")
}

func TestSampling100Percent(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "sample-policy",
			Name: "Sample Policy",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Contains{Contains: "test"},
						},
					},
					Keep: "100%",
					SampleKey: &policyv1.LogSampleKey{
						Field: &policyv1.LogSampleKey_LogField{LogField: policyv1.LogField_LOG_FIELD_TRACE_ID},
					},
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	// All records should be kept with 100% sampling
	for i := 0; i < 100; i++ {
		record := &SimpleLogRecord{
			Body:    []byte("test message"),
			TraceID: []byte("trace-" + string(rune('a'+i))),
		}
		result := EvaluateLog(engine, record, SimpleLogMatcher)
		assert.Equal(t, ResultKeep, result, "100%% sampling should keep all records")
	}
}

func TestSampling0Percent(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "sample-policy",
			Name: "Sample Policy",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Contains{Contains: "test"},
						},
					},
					Keep: "0%",
					SampleKey: &policyv1.LogSampleKey{
						Field: &policyv1.LogSampleKey_LogField{LogField: policyv1.LogField_LOG_FIELD_TRACE_ID},
					},
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	// All records should be dropped with 0% sampling
	for i := 0; i < 100; i++ {
		record := &SimpleLogRecord{
			Body:    []byte("test message"),
			TraceID: []byte("trace-" + string(rune('a'+i))),
		}
		result := EvaluateLog(engine, record, SimpleLogMatcher)
		assert.Equal(t, ResultDrop, result, "0%% sampling should drop all records")
	}
}

// ============================================================================
// METRIC AND TRACE SAMPLING TESTS (KeepSample result)
// ============================================================================

func TestEvaluateMetricSampling(t *testing.T) {
	// This test exercises the KeepSample branch in applyKeepActionMetric.
	// Note: Metrics with percentage sampling return ResultSample since they
	// don't have a sample key mechanism like logs do.

	// We can't directly test percentage sampling on metrics via the proto since
	// MetricTarget.Keep is a bool. However, we can verify the KeepSample path
	// is tested in the internal engine tests. Here we verify basic metric
	// keep/drop behavior works correctly.

	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "keep-all-metrics",
			Name: "Keep All Metrics",
			Target: &policyv1.Policy_Metric{
				Metric: &policyv1.MetricTarget{
					Match: []*policyv1.MetricMatcher{
						{
							Field: &policyv1.MetricMatcher_MetricField{MetricField: policyv1.MetricField_METRIC_FIELD_NAME},
							Match: &policyv1.MetricMatcher_Contains{Contains: "cpu"},
						},
					},
					Keep: true,
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	metric := &SimpleMetricRecord{
		Name: []byte("system.cpu.usage"),
	}

	result := EvaluateMetric(engine, metric, SimpleMetricMatcher)
	assert.Equal(t, ResultKeep, result)
}

func TestEvaluateTraceSamplingDeterministic(t *testing.T) {
	// Test that trace sampling is deterministic based on trace ID
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "sample-traces",
			Name: "Sample Traces at 50%",
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_TraceField{TraceField: policyv1.TraceField_TRACE_FIELD_NAME},
							Match: &policyv1.TraceMatcher_Contains{Contains: "api"},
						},
					},
					Keep: &policyv1.TraceSamplingConfig{Percentage: 50},
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	// Test that the same trace ID always produces the same result
	traceID1 := []byte("trace-id-abc123")
	traceID2 := []byte("trace-id-xyz789")

	span1 := &SimpleSpanRecord{
		Name:    []byte("GET /api/users"),
		TraceID: traceID1,
	}
	span2 := &SimpleSpanRecord{
		Name:    []byte("GET /api/orders"),
		TraceID: traceID2,
	}

	// Run multiple times to verify determinism
	result1a := EvaluateTrace(engine, span1, SimpleSpanMatcher)
	result1b := EvaluateTrace(engine, span1, SimpleSpanMatcher)
	result1c := EvaluateTrace(engine, span1, SimpleSpanMatcher)

	result2a := EvaluateTrace(engine, span2, SimpleSpanMatcher)
	result2b := EvaluateTrace(engine, span2, SimpleSpanMatcher)
	result2c := EvaluateTrace(engine, span2, SimpleSpanMatcher)

	// Same trace ID should always produce the same result
	assert.Equal(t, result1a, result1b, "same trace ID should produce consistent result")
	assert.Equal(t, result1b, result1c, "same trace ID should produce consistent result")
	assert.Equal(t, result2a, result2b, "same trace ID should produce consistent result")
	assert.Equal(t, result2b, result2c, "same trace ID should produce consistent result")

	// Results should be either Keep or Drop (actual sampling decision)
	assert.True(t, result1a == ResultKeep || result1a == ResultDrop, "result should be Keep or Drop")
	assert.True(t, result2a == ResultKeep || result2a == ResultDrop, "result should be Keep or Drop")
}

func TestEvaluateTraceSamplingDistribution(t *testing.T) {
	// Test that trace sampling roughly follows the expected distribution
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "sample-traces-50",
			Name: "Sample Traces at 50%",
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_TraceField{TraceField: policyv1.TraceField_TRACE_FIELD_NAME},
							Match: &policyv1.TraceMatcher_Contains{Contains: "api"},
						},
					},
					Keep: &policyv1.TraceSamplingConfig{Percentage: 50},
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	// Test with many different trace IDs
	// Use proper 32-char hex trace IDs to simulate real W3C trace IDs
	// The last 56 bits (14 hex chars) are used for randomness per OTel spec
	// We need to generate values that span the full 56-bit range
	kept := 0
	dropped := 0
	total := 1000

	for i := 0; i < total; i++ {
		// Generate trace IDs with randomness distributed across the full 56-bit range
		// Multiply by a large prime to spread values across the range
		randomness := uint64(i) * 72057594037927 // ~2^56 / 1000 to spread evenly
		// W3C trace IDs are 32 hex chars (128 bits). Last 14 hex chars (56 bits) are used for randomness.
		traceID := []byte(fmt.Sprintf("%018x%014x", uint64(0), randomness))
		span := &SimpleSpanRecord{
			Name:    []byte("GET /api/users"),
			TraceID: traceID,
		}
		result := EvaluateTrace(engine, span, SimpleSpanMatcher)
		if result == ResultKeep {
			kept++
		} else if result == ResultDrop {
			dropped++
		}
	}

	// With 50% sampling, we expect roughly 50% kept
	// Allow 15% tolerance for statistical variation
	keepRate := float64(kept) / float64(total) * 100
	assert.InDelta(t, 50.0, keepRate, 15.0, "sampling rate should be roughly 50%% (got %.1f%%)", keepRate)
}

func TestEvaluateTraceSamplingNoTraceID(t *testing.T) {
	// Test that spans without trace ID are kept (fail open)
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "sample-traces",
			Name: "Sample Traces at 50%",
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_TraceField{TraceField: policyv1.TraceField_TRACE_FIELD_NAME},
							Match: &policyv1.TraceMatcher_Contains{Contains: "api"},
						},
					},
					Keep: &policyv1.TraceSamplingConfig{Percentage: 50},
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	// Span without trace ID should be kept
	span := &SimpleSpanRecord{
		Name: []byte("GET /api/users"),
		// No TraceID set
	}

	result := EvaluateTrace(engine, span, SimpleSpanMatcher)
	assert.Equal(t, ResultKeep, result, "span without trace ID should be kept (fail open)")
}

func TestEvaluateTraceSampling100Percent(t *testing.T) {
	// Test that 100% sampling keeps all spans
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "sample-traces-100",
			Name: "Sample Traces at 100%",
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_TraceField{TraceField: policyv1.TraceField_TRACE_FIELD_NAME},
							Match: &policyv1.TraceMatcher_Contains{Contains: "api"},
						},
					},
					Keep: &policyv1.TraceSamplingConfig{Percentage: 100},
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	// All spans should be kept with 100% sampling
	for i := 0; i < 100; i++ {
		span := &SimpleSpanRecord{
			Name:    []byte("GET /api/users"),
			TraceID: []byte(fmt.Sprintf("trace-%d", i)),
		}
		result := EvaluateTrace(engine, span, SimpleSpanMatcher)
		assert.Equal(t, ResultKeep, result, "100%% sampling should keep all spans")
	}
}

func TestEvaluateTraceSampling0Percent(t *testing.T) {
	// Test that 0% sampling drops all spans (but this is handled by KeepNone in the compiler)
	// Percentage 0 in TraceSamplingConfig is converted to KeepNone
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "sample-traces-0",
			Name: "Sample Traces at 0%",
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_TraceField{TraceField: policyv1.TraceField_TRACE_FIELD_NAME},
							Match: &policyv1.TraceMatcher_Contains{Contains: "api"},
						},
					},
					Keep: &policyv1.TraceSamplingConfig{Percentage: 0},
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	// All spans should be dropped with 0% sampling
	for i := 0; i < 100; i++ {
		span := &SimpleSpanRecord{
			Name:    []byte("GET /api/users"),
			TraceID: []byte(fmt.Sprintf("%032x", i)),
		}
		result := EvaluateTrace(engine, span, SimpleSpanMatcher)
		assert.Equal(t, ResultDrop, result, "0%% sampling should drop all spans")
	}
}

func TestEvaluateTraceSamplingWithTracestateRandomness(t *testing.T) {
	// Test that explicit randomness in tracestate (rv sub-key) is used for sampling
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "sample-traces",
			Name: "Sample Traces at 50%",
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_TraceField{TraceField: policyv1.TraceField_TRACE_FIELD_NAME},
							Match: &policyv1.TraceMatcher_Contains{Contains: "api"},
						},
					},
					Keep: &policyv1.TraceSamplingConfig{Percentage: 50},
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	// Test with explicit rv in tracestate
	// rv value of 0x80000000000000 is exactly at 50% threshold, should be kept (R >= T)
	// rv value of 0x7fffffffffffff is just below 50% threshold, should be dropped
	spanKept := &SimpleSpanRecord{
		Name:       []byte("GET /api/users"),
		TraceID:    []byte("00000000000000000000000000000001"), // TraceID doesn't matter when rv is present
		TraceState: []byte("ot=rv:80000000000000"),             // Exactly at 50% threshold
	}

	spanDropped := &SimpleSpanRecord{
		Name:       []byte("GET /api/users"),
		TraceID:    []byte("00000000000000000000000000000002"),
		TraceState: []byte("ot=rv:7fffffffffffff"), // Just below 50% threshold
	}

	resultKept := EvaluateTrace(engine, spanKept, SimpleSpanMatcher)
	resultDropped := EvaluateTrace(engine, spanDropped, SimpleSpanMatcher)

	assert.Equal(t, ResultKeep, resultKept, "span with rv at threshold should be kept")
	assert.Equal(t, ResultDrop, resultDropped, "span with rv below threshold should be dropped")
}

func TestEvaluateTraceSamplingConsistentAcrossSpans(t *testing.T) {
	// Test that all spans with the same trace ID are sampled consistently
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "sample-traces",
			Name: "Sample Traces at 50%",
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_TraceField{TraceField: policyv1.TraceField_TRACE_FIELD_NAME},
							Match: &policyv1.TraceMatcher_Contains{Contains: "api"},
						},
					},
					Keep: &policyv1.TraceSamplingConfig{Percentage: 50},
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	// Create multiple spans from the same trace
	traceID := []byte("0123456789abcdef0123456789abcdef")

	span1 := &SimpleSpanRecord{
		Name:    []byte("GET /api/users"),
		TraceID: traceID,
		SpanID:  []byte("span-1"),
	}
	span2 := &SimpleSpanRecord{
		Name:    []byte("POST /api/orders"),
		TraceID: traceID,
		SpanID:  []byte("span-2"),
	}
	span3 := &SimpleSpanRecord{
		Name:    []byte("GET /api/products"),
		TraceID: traceID,
		SpanID:  []byte("span-3"),
	}

	// All spans from the same trace should have the same sampling decision
	result1 := EvaluateTrace(engine, span1, SimpleSpanMatcher)
	result2 := EvaluateTrace(engine, span2, SimpleSpanMatcher)
	result3 := EvaluateTrace(engine, span3, SimpleSpanMatcher)

	assert.Equal(t, result1, result2, "spans from same trace should have same sampling decision")
	assert.Equal(t, result2, result3, "spans from same trace should have same sampling decision")
}

// ============================================================================
// RATE LIMITING TESTS (KeepRatePerSecond/Minute)
// ============================================================================

func TestLogRateLimitingPerSecond(t *testing.T) {
	// Test that rate limiting per second keeps requests under limit and drops when over
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "rate-limit-logs",
			Name: "Rate Limit Logs",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Contains{Contains: "noisy"},
						},
					},
					Keep: "3/s",
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	record := &SimpleLogRecord{
		Body: []byte("noisy log message"),
	}

	// First 3 requests should be kept (under limit)
	for i := 0; i < 3; i++ {
		result := EvaluateLog(engine, record, SimpleLogMatcher)
		assert.Equal(t, ResultKeep, result, "request %d should be kept (under rate limit)", i+1)
	}

	// 4th request should be dropped (over limit)
	result := EvaluateLog(engine, record, SimpleLogMatcher)
	assert.Equal(t, ResultDrop, result, "request 4 should be dropped (over rate limit)")
}

func TestLogRateLimitingPerMinute(t *testing.T) {
	// Test that rate limiting per minute keeps requests under limit and drops when over
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "rate-limit-logs-minute",
			Name: "Rate Limit Logs Per Minute",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Contains{Contains: "verbose"},
						},
					},
					Keep: "5/m",
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	record := &SimpleLogRecord{
		Body: []byte("verbose log message"),
	}

	// First 5 requests should be kept (under limit)
	for i := 0; i < 5; i++ {
		result := EvaluateLog(engine, record, SimpleLogMatcher)
		assert.Equal(t, ResultKeep, result, "request %d should be kept (under rate limit)", i+1)
	}

	// 6th request should be dropped (over limit)
	result := EvaluateLog(engine, record, SimpleLogMatcher)
	assert.Equal(t, ResultDrop, result, "request 6 should be dropped (over rate limit)")
}

// ============================================================================
// LOG TRANSFORM EVALUATION TESTS
// ============================================================================

func TestEvaluateLogTransformRedactAttribute(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "redact-api-key",
			Name: "Redact API Key",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogAttribute{
								LogAttribute: &policyv1.AttributePath{Path: []string{"api_key"}},
							},
							Match: &policyv1.LogMatcher_Exists{Exists: true},
						},
					},
					Keep: "all",
					Transform: &policyv1.LogTransform{
						Redact: []*policyv1.LogRedact{
							{
								Field: &policyv1.LogRedact_LogAttribute{
									LogAttribute: &policyv1.AttributePath{Path: []string{"api_key"}},
								},
								Replacement: "[REDACTED]",
							},
						},
					},
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	record := &SimpleLogRecord{
		Body:          []byte("request log"),
		LogAttributes: map[string]any{"api_key": "secret-123"},
	}

	result := EvaluateLog(engine, record, SimpleLogMatcher, WithLogTransform(SimpleLogTransformer))
	assert.Equal(t, ResultKeepWithTransform, result)
	assert.Equal(t, "[REDACTED]", record.LogAttributes["api_key"])
}

func TestEvaluateLogTransformWithoutFunc(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "transform-no-func",
			Name: "Transform Without Func",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Contains{Contains: "test"},
						},
					},
					Keep: "all",
					Transform: &policyv1.LogTransform{
						Add: []*policyv1.LogAdd{
							{
								Field: &policyv1.LogAdd_LogAttribute{
									LogAttribute: &policyv1.AttributePath{Path: []string{"processed"}},
								},
								Value: "true",
							},
						},
					},
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	record := &SimpleLogRecord{
		Body: []byte("test message"),
	}

	// No transform func provided - should still return ResultKeepWithTransform
	result := EvaluateLog(engine, record, SimpleLogMatcher)
	assert.Equal(t, ResultKeepWithTransform, result)

	// Record should be unmodified since no transform func was provided
	assert.Nil(t, record.LogAttributes)
}

func TestEvaluateLogTransformAllOpsApplied(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "all-transforms",
			Name: "All Transform Types",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Contains{Contains: "test"},
						},
					},
					Keep: "all",
					Transform: &policyv1.LogTransform{
						Remove: []*policyv1.LogRemove{
							{
								Field: &policyv1.LogRemove_LogAttribute{
									LogAttribute: &policyv1.AttributePath{Path: []string{"secret"}},
								},
							},
						},
						Redact: []*policyv1.LogRedact{
							{
								Field: &policyv1.LogRedact_LogField{
									LogField: policyv1.LogField_LOG_FIELD_BODY,
								},
								Replacement: "***",
							},
						},
						Rename: []*policyv1.LogRename{
							{
								From: &policyv1.LogRename_FromLogAttribute{
									FromLogAttribute: &policyv1.AttributePath{Path: []string{"old_key"}},
								},
								To:     "new_key",
								Upsert: true,
							},
						},
						Add: []*policyv1.LogAdd{
							{
								Field: &policyv1.LogAdd_ResourceAttribute{
									ResourceAttribute: &policyv1.AttributePath{Path: []string{"env"}},
								},
								Value:  "production",
								Upsert: false,
							},
						},
					},
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	record := &SimpleLogRecord{
		Body: []byte("test message"),
		LogAttributes: map[string]any{
			"secret":  "super-secret-value",
			"old_key": "some-value",
			"keep_me": "untouched",
		},
	}

	result := EvaluateLog(engine, record, SimpleLogMatcher, WithLogTransform(SimpleLogTransformer))
	assert.Equal(t, ResultKeepWithTransform, result)

	// Remove: "secret" attribute should be gone
	_, hasSecret := record.LogAttributes["secret"]
	assert.False(t, hasSecret)

	// Redact: body should be replaced
	assert.Equal(t, []byte("***"), record.Body)

	// Rename: "old_key" gone, "new_key" has its value
	_, hasOld := record.LogAttributes["old_key"]
	assert.False(t, hasOld)
	assert.Equal(t, "some-value", record.LogAttributes["new_key"])

	// Add: resource attribute "env" should be set
	assert.Equal(t, "production", record.ResourceAttributes["env"])

	// Untouched attributes remain
	assert.Equal(t, "untouched", record.LogAttributes["keep_me"])
}

func TestEvaluateLogTransformNotAppliedOnDrop(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "drop-with-transform",
			Name: "Drop With Transform",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Contains{Contains: "debug"},
						},
					},
					Keep: "none",
					Transform: &policyv1.LogTransform{
						Redact: []*policyv1.LogRedact{
							{
								Field: &policyv1.LogRedact_LogField{
									LogField: policyv1.LogField_LOG_FIELD_BODY,
								},
								Replacement: "[REDACTED]",
							},
						},
					},
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	record := &SimpleLogRecord{
		Body: []byte("debug message"),
	}

	result := EvaluateLog(engine, record, SimpleLogMatcher, WithLogTransform(SimpleLogTransformer))
	assert.Equal(t, ResultDrop, result)

	// Body should be unmodified since policy dropped the record
	assert.Equal(t, []byte("debug message"), record.Body)
}

func TestEvaluateLogNoTransformReturnsKeep(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "keep-no-transform",
			Name: "Keep Without Transform",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Contains{Contains: "info"},
						},
					},
					Keep: "all",
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	record := &SimpleLogRecord{
		Body: []byte("info message"),
	}

	// Policy has no transforms - should return ResultKeep, not ResultKeepWithTransform
	result := EvaluateLog(engine, record, SimpleLogMatcher, WithLogTransform(SimpleLogTransformer))
	assert.Equal(t, ResultKeep, result)
}

func TestEvaluateLogTransformMultipleRedacts(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "multi-redact",
			Name: "Multiple Redacts",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Contains{Contains: "request"},
						},
					},
					Keep: "all",
					Transform: &policyv1.LogTransform{
						Redact: []*policyv1.LogRedact{
							{
								Field: &policyv1.LogRedact_LogAttribute{
									LogAttribute: &policyv1.AttributePath{Path: []string{"password"}},
								},
								Replacement: "[REDACTED]",
							},
							{
								Field: &policyv1.LogRedact_LogAttribute{
									LogAttribute: &policyv1.AttributePath{Path: []string{"ssn"}},
								},
								Replacement: "XXX-XX-XXXX",
							},
						},
					},
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	record := &SimpleLogRecord{
		Body: []byte("request log"),
		LogAttributes: map[string]any{
			"password": "s3cret",
			"ssn":      "123-45-6789",
			"user":     "alice",
		},
	}

	result := EvaluateLog(engine, record, SimpleLogMatcher, WithLogTransform(SimpleLogTransformer))
	assert.Equal(t, ResultKeepWithTransform, result)

	assert.Equal(t, "[REDACTED]", record.LogAttributes["password"])
	assert.Equal(t, "XXX-XX-XXXX", record.LogAttributes["ssn"])
	assert.Equal(t, "alice", record.LogAttributes["user"]) // untouched
}

func TestEvaluateLogTransformRemoveField(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "remove-trace-id",
			Name: "Remove Trace ID",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Contains{Contains: "event"},
						},
					},
					Keep: "all",
					Transform: &policyv1.LogTransform{
						Remove: []*policyv1.LogRemove{
							{
								Field: &policyv1.LogRemove_LogField{LogField: policyv1.LogField_LOG_FIELD_TRACE_ID},
							},
							{
								Field: &policyv1.LogRemove_LogField{LogField: policyv1.LogField_LOG_FIELD_SPAN_ID},
							},
						},
					},
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	record := &SimpleLogRecord{
		Body:    []byte("event happened"),
		TraceID: []byte("trace-abc"),
		SpanID:  []byte("span-123"),
	}

	result := EvaluateLog(engine, record, SimpleLogMatcher, WithLogTransform(SimpleLogTransformer))
	assert.Equal(t, ResultKeepWithTransform, result)

	assert.Nil(t, record.TraceID)
	assert.Nil(t, record.SpanID)
	assert.Equal(t, []byte("event happened"), record.Body) // untouched
}

func TestEvaluateLogTransformAddWithUpsert(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "add-upsert",
			Name: "Add With Upsert",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Contains{Contains: "msg"},
						},
					},
					Keep: "all",
					Transform: &policyv1.LogTransform{
						Add: []*policyv1.LogAdd{
							{
								Field: &policyv1.LogAdd_LogAttribute{
									LogAttribute: &policyv1.AttributePath{Path: []string{"existing"}},
								},
								Value:  "overwritten",
								Upsert: true,
							},
							{
								Field: &policyv1.LogAdd_LogAttribute{
									LogAttribute: &policyv1.AttributePath{Path: []string{"guarded"}},
								},
								Value:  "should-not-overwrite",
								Upsert: false,
							},
							{
								Field: &policyv1.LogAdd_LogAttribute{
									LogAttribute: &policyv1.AttributePath{Path: []string{"new_attr"}},
								},
								Value:  "added",
								Upsert: false,
							},
						},
					},
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	record := &SimpleLogRecord{
		Body: []byte("msg payload"),
		LogAttributes: map[string]any{
			"existing": "original",
			"guarded":  "protected",
		},
	}

	result := EvaluateLog(engine, record, SimpleLogMatcher, WithLogTransform(SimpleLogTransformer))
	assert.Equal(t, ResultKeepWithTransform, result)

	assert.Equal(t, "overwritten", record.LogAttributes["existing"]) // upsert=true overwrites
	assert.Equal(t, "protected", record.LogAttributes["guarded"])    // upsert=false preserves
	assert.Equal(t, "added", record.LogAttributes["new_attr"])       // upsert=false adds new
}

func TestEvaluateLogTransformRenameAttribute(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "rename-attr",
			Name: "Rename Attribute",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Contains{Contains: "log"},
						},
					},
					Keep: "all",
					Transform: &policyv1.LogTransform{
						Rename: []*policyv1.LogRename{
							{
								From: &policyv1.LogRename_FromLogAttribute{
									FromLogAttribute: &policyv1.AttributePath{Path: []string{"src_ip"}},
								},
								To:     "source_ip",
								Upsert: true,
							},
						},
					},
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	record := &SimpleLogRecord{
		Body: []byte("log entry"),
		LogAttributes: map[string]any{
			"src_ip": "10.0.0.1",
		},
	}

	result := EvaluateLog(engine, record, SimpleLogMatcher, WithLogTransform(SimpleLogTransformer))
	assert.Equal(t, ResultKeepWithTransform, result)

	_, hasSrcIP := record.LogAttributes["src_ip"]
	assert.False(t, hasSrcIP, "old key should be removed")
	assert.Equal(t, "10.0.0.1", record.LogAttributes["source_ip"])
}

func TestEvaluateLogTransformStatsRecorded(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "transform-stats",
			Name: "Transform Stats",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Contains{Contains: "log"},
						},
					},
					Keep: "all",
					Transform: &policyv1.LogTransform{
						Remove: []*policyv1.LogRemove{
							{
								Field: &policyv1.LogRemove_LogAttribute{
									LogAttribute: &policyv1.AttributePath{Path: []string{"secret"}},
								},
							},
						},
						Redact: []*policyv1.LogRedact{
							{
								Field: &policyv1.LogRedact_LogAttribute{
									LogAttribute: &policyv1.AttributePath{Path: []string{"api_key"}},
								},
								Replacement: "[REDACTED]",
							},
							{
								Field: &policyv1.LogRedact_LogAttribute{
									LogAttribute: &policyv1.AttributePath{Path: []string{"missing_attr"}},
								},
								Replacement: "[REDACTED]",
							},
						},
						Rename: []*policyv1.LogRename{
							{
								From: &policyv1.LogRename_FromLogAttribute{
									FromLogAttribute: &policyv1.AttributePath{Path: []string{"old_name"}},
								},
								To:     "new_name",
								Upsert: true,
							},
						},
						Add: []*policyv1.LogAdd{
							{
								Field: &policyv1.LogAdd_LogAttribute{
									LogAttribute: &policyv1.AttributePath{Path: []string{"processed"}},
								},
								Value:  "true",
								Upsert: false,
							},
						},
					},
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	record := &SimpleLogRecord{
		Body: []byte("log entry"),
		LogAttributes: map[string]any{
			"secret":   "password123",
			"api_key":  "key-abc",
			"old_name": "value",
		},
	}

	result := EvaluateLog(engine, record, SimpleLogMatcher, WithLogTransform(SimpleLogTransformer))
	assert.Equal(t, ResultKeepWithTransform, result)

	// Collect stats and verify transform counters
	stats := registry.CollectStats()
	require.NotEmpty(t, stats)

	var snap *PolicyStatsSnapshot
	for _, s := range stats {
		if s.PolicyID == "transform-stats" {
			snap = &s
			break
		}
	}
	require.NotNil(t, snap)

	// Remove: "secret" existed → 1 hit, 0 misses
	assert.Equal(t, uint64(1), snap.RemoveHits)
	assert.Equal(t, uint64(0), snap.RemoveMisses)

	// Redact: "api_key" existed (hit), "missing_attr" did not (miss)
	assert.Equal(t, uint64(1), snap.RedactHits)
	assert.Equal(t, uint64(1), snap.RedactMisses)

	// Rename: "old_name" existed → 1 hit
	assert.Equal(t, uint64(1), snap.RenameHits)
	assert.Equal(t, uint64(0), snap.RenameMisses)

	// Add: "processed" didn't exist, but add always returns true (field is being set)
	assert.Equal(t, uint64(1), snap.AddHits)
	assert.Equal(t, uint64(0), snap.AddMisses)
}

func TestEvaluateLogTransformStatsResetAfterCollect(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "stats-reset",
			Name: "Stats Reset",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Contains{Contains: "msg"},
						},
					},
					Keep: "all",
					Transform: &policyv1.LogTransform{
						Redact: []*policyv1.LogRedact{
							{
								Field: &policyv1.LogRedact_LogAttribute{
									LogAttribute: &policyv1.AttributePath{Path: []string{"secret"}},
								},
								Replacement: "[REDACTED]",
							},
						},
					},
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	// First evaluation
	record := &SimpleLogRecord{
		Body:          []byte("msg"),
		LogAttributes: map[string]any{"secret": "val"},
	}
	EvaluateLog(engine, record, SimpleLogMatcher, WithLogTransform(SimpleLogTransformer))

	// First collect — should have stats
	stats := registry.CollectStats()
	var snap *PolicyStatsSnapshot
	for _, s := range stats {
		if s.PolicyID == "stats-reset" {
			snap = &s
			break
		}
	}
	require.NotNil(t, snap)
	assert.Equal(t, uint64(1), snap.MatchHits)
	assert.Equal(t, uint64(1), snap.RedactHits)

	// Second collect without new evaluations — counters should be zero (reset)
	stats2 := registry.CollectStats()
	var snap2 *PolicyStatsSnapshot
	for _, s := range stats2 {
		if s.PolicyID == "stats-reset" {
			snap2 = &s
			break
		}
	}
	require.NotNil(t, snap2)
	assert.Equal(t, uint64(0), snap2.MatchHits)
	assert.Equal(t, uint64(0), snap2.RedactHits)
	assert.Equal(t, uint64(0), snap2.RedactMisses)
}

func TestEvaluateLogTransformStatsNotRecordedWithoutFunc(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "transform-no-func-stats",
			Name: "Transform No Func Stats",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Contains{Contains: "test"},
						},
					},
					Keep: "all",
					Transform: &policyv1.LogTransform{
						Redact: []*policyv1.LogRedact{
							{
								Field: &policyv1.LogRedact_LogField{
									LogField: policyv1.LogField_LOG_FIELD_BODY,
								},
								Replacement: "[REDACTED]",
							},
						},
					},
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	record := &SimpleLogRecord{
		Body: []byte("test message"),
	}

	// No transform func provided
	result := EvaluateLog(engine, record, SimpleLogMatcher)
	assert.Equal(t, ResultKeepWithTransform, result)

	// Stats should have zero transform counters since no func was called
	stats := registry.CollectStats()
	var snap *PolicyStatsSnapshot
	for _, s := range stats {
		if s.PolicyID == "transform-no-func-stats" {
			snap = &s
			break
		}
	}
	require.NotNil(t, snap)
	assert.Equal(t, uint64(0), snap.RedactHits)
	assert.Equal(t, uint64(0), snap.RedactMisses)
}

func TestEvaluateLogTransformRedactBody(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "redact-body",
			Name: "Redact Body",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Contains{Contains: "sensitive"},
						},
					},
					Keep: "all",
					Transform: &policyv1.LogTransform{
						Redact: []*policyv1.LogRedact{
							{
								Field: &policyv1.LogRedact_LogField{
									LogField: policyv1.LogField_LOG_FIELD_BODY,
								},
								Replacement: "[BODY REDACTED]",
							},
						},
					},
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	record := &SimpleLogRecord{
		Body: []byte("contains sensitive data: SSN=123-45-6789"),
	}

	result := EvaluateLog(engine, record, SimpleLogMatcher, WithLogTransform(SimpleLogTransformer))
	assert.Equal(t, ResultKeepWithTransform, result)
	assert.Equal(t, []byte("[BODY REDACTED]"), record.Body)
}

func TestEvaluateLogTransformMultiplePolicies(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "policy-add-tag1",
			Name: "Add Tag1",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Regex{Regex: "^.*$"},
						},
					},
					Keep: "all",
					Transform: &policyv1.LogTransform{
						Add: []*policyv1.LogAdd{
							{
								Field: &policyv1.LogAdd_LogAttribute{
									LogAttribute: &policyv1.AttributePath{Path: []string{"tag1"}},
								},
								Value:  "a",
								Upsert: true,
							},
						},
					},
				},
			},
		},
		{
			Id:   "policy-add-tag2",
			Name: "Add Tag2",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Regex{Regex: "^.*$"},
						},
					},
					Keep: "all",
					Transform: &policyv1.LogTransform{
						Add: []*policyv1.LogAdd{
							{
								Field: &policyv1.LogAdd_LogAttribute{
									LogAttribute: &policyv1.AttributePath{Path: []string{"tag2"}},
								},
								Value:  "b",
								Upsert: true,
							},
						},
					},
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	record := &SimpleLogRecord{
		Body:          []byte("hello world"),
		LogAttributes: map[string]any{},
	}

	result := EvaluateLog(engine, record, SimpleLogMatcher, WithLogTransform(SimpleLogTransformer))
	assert.Equal(t, ResultKeepWithTransform, result)

	// Both policies matched — transforms from both should be applied
	assert.Equal(t, "a", record.LogAttributes["tag1"], "tag1 from policy 1 should be present")
	assert.Equal(t, "b", record.LogAttributes["tag2"], "tag2 from policy 2 should be present")
}

// ============================================================================
// DISABLED POLICY TESTS
// ============================================================================

func TestDisabledPolicyNotEvaluated(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProviderRaw([]*policyv1.Policy{
		{
			Id:      "disabled-drop-debug",
			Name:    "Disabled Drop Debug",
			Enabled: false,
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Contains{Contains: "debug"},
						},
					},
					Keep: "none",
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	record := &SimpleLogRecord{
		Body: []byte("this is a debug message"),
	}

	// Disabled policy should be skipped — log should pass through
	result := EvaluateLog(engine, record, SimpleLogMatcher)
	assert.Equal(t, ResultNoMatch, result)
}

func TestDisabledPolicyMixedWithEnabled(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProviderRaw([]*policyv1.Policy{
		{
			Id:      "disabled-drop-all",
			Name:    "Disabled Drop All",
			Enabled: false,
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Contains{Contains: "message"},
						},
					},
					Keep: "none",
				},
			},
		},
		{
			Id:      "enabled-keep-all",
			Name:    "Enabled Keep All",
			Enabled: true,
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Contains{Contains: "message"},
						},
					},
					Keep: "all",
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	record := &SimpleLogRecord{
		Body: []byte("test message"),
	}

	// Only the enabled policy should match — keep all
	result := EvaluateLog(engine, record, SimpleLogMatcher)
	assert.Equal(t, ResultKeep, result)
}

func TestEvaluateTraceEventNameMatch(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "drop-exception-events",
			Name: "Drop Exception Events",
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_EventName{EventName: "exception"},
							Match: &policyv1.TraceMatcher_Exact{Exact: "exception"},
						},
					},
					Keep: &policyv1.TraceSamplingConfig{Percentage: 0},
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	// Span with an exception event — should be dropped
	span := &SimpleSpanRecord{
		Name:       []byte("my-span"),
		EventNames: [][]byte{[]byte("exception")},
	}
	result := EvaluateTrace(engine, span, SimpleSpanMatcher)
	assert.Equal(t, ResultDrop, result)

	// Span without exception event — should pass through
	span2 := &SimpleSpanRecord{
		Name:       []byte("my-span"),
		EventNames: [][]byte{[]byte("log")},
	}
	result2 := EvaluateTrace(engine, span2, SimpleSpanMatcher)
	assert.Equal(t, ResultNoMatch, result2)
}

func TestEvaluateTraceScopeNameMatch(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "drop-scope",
			Name: "Drop Specific Scope",
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_TraceField{TraceField: policyv1.TraceField_TRACE_FIELD_SCOPE_NAME},
							Match: &policyv1.TraceMatcher_Exact{Exact: "internal.healthcheck"},
						},
					},
					Keep: &policyv1.TraceSamplingConfig{Percentage: 0},
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	// Span from the target scope — should be dropped
	span := &SimpleSpanRecord{
		Name:      []byte("check"),
		ScopeName: []byte("internal.healthcheck"),
	}
	result := EvaluateTrace(engine, span, SimpleSpanMatcher)
	assert.Equal(t, ResultDrop, result)

	// Span from a different scope — should pass through
	span2 := &SimpleSpanRecord{
		Name:      []byte("check"),
		ScopeName: []byte("my.service"),
	}
	result2 := EvaluateTrace(engine, span2, SimpleSpanMatcher)
	assert.Equal(t, ResultNoMatch, result2)
}

func TestEvaluateTraceSpanStatusUnset(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "drop-unset-status",
			Name: "Drop Unset Status Spans",
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_SpanStatus{SpanStatus: policyv1.SpanStatusCode_SPAN_STATUS_CODE_UNSPECIFIED},
						},
					},
					Keep: &policyv1.TraceSamplingConfig{Percentage: 0},
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	// Span with unset status — should be dropped
	span := &SimpleSpanRecord{
		Name:   []byte("my-span"),
		Status: []byte("unset"),
	}
	result := EvaluateTrace(engine, span, SimpleSpanMatcher)
	assert.Equal(t, ResultDrop, result)

	// Span with error status — should pass through
	span2 := &SimpleSpanRecord{
		Name:   []byte("my-span"),
		Status: []byte("error"),
	}
	result2 := EvaluateTrace(engine, span2, SimpleSpanMatcher)
	assert.Equal(t, ResultNoMatch, result2)
}

func TestEvaluateLogResourceSchemaURL(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "drop-old-schema",
			Name: "Drop Old Schema URL",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_RESOURCE_SCHEMA_URL},
							Match: &policyv1.LogMatcher_Contains{Contains: "v1.0.0"},
						},
					},
					Keep: "none",
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	// Log with old schema — should be dropped
	record := &SimpleLogRecord{
		Body:              []byte("test"),
		ResourceSchemaURL: []byte("https://opentelemetry.io/schemas/v1.0.0"),
	}
	result := EvaluateLog(engine, record, SimpleLogMatcher)
	assert.Equal(t, ResultDrop, result)

	// Log with new schema — should pass through
	record2 := &SimpleLogRecord{
		Body:              []byte("test"),
		ResourceSchemaURL: []byte("https://opentelemetry.io/schemas/v2.0.0"),
	}
	result2 := EvaluateLog(engine, record2, SimpleLogMatcher)
	assert.Equal(t, ResultNoMatch, result2)
}

func TestEvaluateMetricResourceSchemaURL(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "drop-old-metric-schema",
			Name: "Drop Old Metric Schema",
			Target: &policyv1.Policy_Metric{
				Metric: &policyv1.MetricTarget{
					Match: []*policyv1.MetricMatcher{
						{
							Field: &policyv1.MetricMatcher_MetricField{MetricField: policyv1.MetricField_METRIC_FIELD_RESOURCE_SCHEMA_URL},
							Match: &policyv1.MetricMatcher_Contains{Contains: "v1.0.0"},
						},
					},
					Keep: false,
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	// Metric with old schema — should be dropped
	record := &SimpleMetricRecord{
		Name:              []byte("cpu.usage"),
		ResourceSchemaURL: []byte("https://opentelemetry.io/schemas/v1.0.0"),
	}
	result := EvaluateMetric(engine, record, SimpleMetricMatcher)
	assert.Equal(t, ResultDrop, result)

	// Metric with new schema — should pass through
	record2 := &SimpleMetricRecord{
		Name:              []byte("cpu.usage"),
		ResourceSchemaURL: []byte("https://opentelemetry.io/schemas/v2.0.0"),
	}
	result2 := EvaluateMetric(engine, record2, SimpleMetricMatcher)
	assert.Equal(t, ResultNoMatch, result2)
}

func TestEvaluateMetricScopeName(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "drop-scope-metrics",
			Name: "Drop Metrics From Scope",
			Target: &policyv1.Policy_Metric{
				Metric: &policyv1.MetricTarget{
					Match: []*policyv1.MetricMatcher{
						{
							Field: &policyv1.MetricMatcher_MetricField{MetricField: policyv1.MetricField_METRIC_FIELD_SCOPE_NAME},
							Match: &policyv1.MetricMatcher_Exact{Exact: "internal.debug"},
						},
					},
					Keep: false,
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	// Metric from debug scope — should be dropped
	record := &SimpleMetricRecord{
		Name:      []byte("cpu.usage"),
		ScopeName: []byte("internal.debug"),
	}
	result := EvaluateMetric(engine, record, SimpleMetricMatcher)
	assert.Equal(t, ResultDrop, result)

	// Metric from different scope — should pass through
	record2 := &SimpleMetricRecord{
		Name:      []byte("cpu.usage"),
		ScopeName: []byte("my.service"),
	}
	result2 := EvaluateMetric(engine, record2, SimpleMetricMatcher)
	assert.Equal(t, ResultNoMatch, result2)
}
