package engine

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
)

func TestCompilerMetricPolicyWithMetricType(t *testing.T) {
	compiler := NewCompiler()
	stats := map[string]*PolicyStats{
		"metric-type-policy": {},
	}

	policies := []*policyv1.Policy{
		{
			Id:   "metric-type-policy",
			Name: "Metric Type Policy",
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
	}

	compiled, err := compiler.Compile(policies, stats)
	require.NoError(t, err)
	defer compiled.Close()

	policy, ok := compiled.Metrics.GetPolicy("metric-type-policy")
	require.True(t, ok)
	assert.Equal(t, 1, policy.MatcherCount)

	// MetricType should generate a pattern match (exact match on enum string), not existence check
	require.Equal(t, 1, len(compiled.Metrics.Databases()))
	entry := compiled.Metrics.Databases()[0]
	assert.Equal(t, MetricFieldType, entry.Key.Ref.Field)
	assert.Empty(t, compiled.Metrics.ExistenceChecks())
}

func TestCompilerMetricPolicyWithAggregationTemporality(t *testing.T) {
	compiler := NewCompiler()
	stats := map[string]*PolicyStats{
		"agg-temp-policy": {},
	}

	policies := []*policyv1.Policy{
		{
			Id:   "agg-temp-policy",
			Name: "Aggregation Temporality Policy",
			Target: &policyv1.Policy_Metric{
				Metric: &policyv1.MetricTarget{
					Match: []*policyv1.MetricMatcher{
						{
							Field: &policyv1.MetricMatcher_AggregationTemporality{AggregationTemporality: policyv1.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA},
							// Match field is ignored - enum value is used as exact match
						},
					},
					Keep: true,
				},
			},
		},
	}

	compiled, err := compiler.Compile(policies, stats)
	require.NoError(t, err)
	defer compiled.Close()

	policy, ok := compiled.Metrics.GetPolicy("agg-temp-policy")
	require.True(t, ok)
	assert.Equal(t, 1, policy.MatcherCount)

	// AggregationTemporality should generate a pattern match (exact match on enum string), not existence check
	require.Equal(t, 1, len(compiled.Metrics.Databases()))
	entry := compiled.Metrics.Databases()[0]
	assert.Equal(t, MetricFieldAggregationTemporality, entry.Key.Ref.Field)
	assert.Empty(t, compiled.Metrics.ExistenceChecks())
}

func TestCompilerMetricPolicyWithDatapointAttribute(t *testing.T) {
	compiler := NewCompiler()
	stats := map[string]*PolicyStats{
		"datapoint-attr-policy": {},
	}

	policies := []*policyv1.Policy{
		{
			Id:   "datapoint-attr-policy",
			Name: "Datapoint Attribute Policy",
			Target: &policyv1.Policy_Metric{
				Metric: &policyv1.MetricTarget{
					Match: []*policyv1.MetricMatcher{
						{
							Field: &policyv1.MetricMatcher_DatapointAttribute{DatapointAttribute: &policyv1.AttributePath{Path: []string{"host"}}},
							Match: &policyv1.MetricMatcher_StartsWith{StartsWith: "prod-"},
						},
					},
					Keep: true,
				},
			},
		},
	}

	compiled, err := compiler.Compile(policies, stats)
	require.NoError(t, err)
	defer compiled.Close()

	require.Equal(t, 1, len(compiled.Metrics.Databases()))
	entry := compiled.Metrics.Databases()[0]
	assert.Equal(t, AttrScopeRecord, entry.Key.Ref.AttrScope)
	assert.Equal(t, []string{"host"}, entry.Key.Ref.AttrPath)
}

func TestCompilerMetricPolicyWithResourceAttribute(t *testing.T) {
	compiler := NewCompiler()
	stats := map[string]*PolicyStats{
		"metric-resource-attr": {},
	}

	policies := []*policyv1.Policy{
		{
			Id:   "metric-resource-attr",
			Name: "Metric Resource Attribute Policy",
			Target: &policyv1.Policy_Metric{
				Metric: &policyv1.MetricTarget{
					Match: []*policyv1.MetricMatcher{
						{
							Field: &policyv1.MetricMatcher_ResourceAttribute{ResourceAttribute: &policyv1.AttributePath{Path: []string{"cloud.provider"}}},
							Match: &policyv1.MetricMatcher_Exact{Exact: "aws"},
						},
					},
					Keep: true,
				},
			},
		},
	}

	compiled, err := compiler.Compile(policies, stats)
	require.NoError(t, err)
	defer compiled.Close()

	require.Equal(t, 1, len(compiled.Metrics.Databases()))
	entry := compiled.Metrics.Databases()[0]
	assert.Equal(t, AttrScopeResource, entry.Key.Ref.AttrScope)
	assert.Equal(t, []string{"cloud.provider"}, entry.Key.Ref.AttrPath)
}

func TestCompilerMetricPolicyWithScopeAttribute(t *testing.T) {
	compiler := NewCompiler()
	stats := map[string]*PolicyStats{
		"metric-scope-attr": {},
	}

	policies := []*policyv1.Policy{
		{
			Id:   "metric-scope-attr",
			Name: "Metric Scope Attribute Policy",
			Target: &policyv1.Policy_Metric{
				Metric: &policyv1.MetricTarget{
					Match: []*policyv1.MetricMatcher{
						{
							Field: &policyv1.MetricMatcher_ScopeAttribute{ScopeAttribute: &policyv1.AttributePath{Path: []string{"instrumentation.version"}}},
							Match: &policyv1.MetricMatcher_Contains{Contains: "beta"},
						},
					},
					Keep: false,
				},
			},
		},
	}

	compiled, err := compiler.Compile(policies, stats)
	require.NoError(t, err)
	defer compiled.Close()

	require.Equal(t, 1, len(compiled.Metrics.Databases()))
	entry := compiled.Metrics.Databases()[0]
	assert.Equal(t, AttrScopeScope, entry.Key.Ref.AttrScope)
	assert.Equal(t, []string{"instrumentation.version"}, entry.Key.Ref.AttrPath)
}

func TestCompilerMetricPolicyWithDescription(t *testing.T) {
	compiler := NewCompiler()
	stats := map[string]*PolicyStats{
		"metric-description": {},
	}

	policies := []*policyv1.Policy{
		{
			Id:   "metric-description",
			Name: "Metric Description Policy",
			Target: &policyv1.Policy_Metric{
				Metric: &policyv1.MetricTarget{
					Match: []*policyv1.MetricMatcher{
						{
							Field: &policyv1.MetricMatcher_MetricField{MetricField: policyv1.MetricField_METRIC_FIELD_DESCRIPTION},
							Match: &policyv1.MetricMatcher_Contains{Contains: "internal"},
						},
					},
					Keep: false,
				},
			},
		},
	}

	compiled, err := compiler.Compile(policies, stats)
	require.NoError(t, err)
	defer compiled.Close()

	require.Equal(t, 1, len(compiled.Metrics.Databases()))
	entry := compiled.Metrics.Databases()[0]
	assert.Equal(t, MetricFieldDescription, entry.Key.Ref.Field)
}

func TestCompilerMetricPolicyWithUnit(t *testing.T) {
	compiler := NewCompiler()
	stats := map[string]*PolicyStats{
		"metric-unit": {},
	}

	policies := []*policyv1.Policy{
		{
			Id:   "metric-unit",
			Name: "Metric Unit Policy",
			Target: &policyv1.Policy_Metric{
				Metric: &policyv1.MetricTarget{
					Match: []*policyv1.MetricMatcher{
						{
							Field: &policyv1.MetricMatcher_MetricField{MetricField: policyv1.MetricField_METRIC_FIELD_UNIT},
							Match: &policyv1.MetricMatcher_Exact{Exact: "ms"},
						},
					},
					Keep: true,
				},
			},
		},
	}

	compiled, err := compiler.Compile(policies, stats)
	require.NoError(t, err)
	defer compiled.Close()

	require.Equal(t, 1, len(compiled.Metrics.Databases()))
	entry := compiled.Metrics.Databases()[0]
	assert.Equal(t, MetricFieldUnit, entry.Key.Ref.Field)
}

func TestCompilerMetricPolicyMultipleMatchers(t *testing.T) {
	compiler := NewCompiler()
	stats := map[string]*PolicyStats{
		"multi-metric-matcher": {},
	}

	policies := []*policyv1.Policy{
		{
			Id:   "multi-metric-matcher",
			Name: "Multiple Metric Matchers",
			Target: &policyv1.Policy_Metric{
				Metric: &policyv1.MetricTarget{
					Match: []*policyv1.MetricMatcher{
						{
							Field: &policyv1.MetricMatcher_MetricField{MetricField: policyv1.MetricField_METRIC_FIELD_NAME},
							Match: &policyv1.MetricMatcher_StartsWith{StartsWith: "system."},
						},
						{
							Field: &policyv1.MetricMatcher_MetricType{MetricType: policyv1.MetricType_METRIC_TYPE_GAUGE},
							// Match field is ignored - enum value is used as exact match
						},
						{
							Field: &policyv1.MetricMatcher_ResourceAttribute{ResourceAttribute: &policyv1.AttributePath{Path: []string{"host.name"}}},
							Match: &policyv1.MetricMatcher_Exists{Exists: true},
						},
					},
					Keep: false,
				},
			},
		},
	}

	compiled, err := compiler.Compile(policies, stats)
	require.NoError(t, err)
	defer compiled.Close()

	policy, ok := compiled.Metrics.GetPolicy("multi-metric-matcher")
	require.True(t, ok)
	assert.Equal(t, 3, policy.MatcherCount)

	// Should have 2 databases (metric name and metric type) and 1 existence check (resource attr)
	assert.Equal(t, 2, len(compiled.Metrics.Databases()))
	assert.Len(t, compiled.Metrics.ExistenceChecks(), 1)
}

// ============================================================================
// Mixed Telemetry Type Tests
// ============================================================================

func TestCompilerMixedTelemetryTypes(t *testing.T) {
	compiler := NewCompiler()
	stats := map[string]*PolicyStats{
		"log-policy":    {},
		"metric-policy": {},
		"trace-policy":  {},
	}

	policies := []*policyv1.Policy{
		{
			Id:   "log-policy",
			Name: "Log Policy",
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
		{
			Id:   "metric-policy",
			Name: "Metric Policy",
			Target: &policyv1.Policy_Metric{
				Metric: &policyv1.MetricTarget{
					Match: []*policyv1.MetricMatcher{
						{
							Field: &policyv1.MetricMatcher_MetricField{MetricField: policyv1.MetricField_METRIC_FIELD_NAME},
							Match: &policyv1.MetricMatcher_StartsWith{StartsWith: "internal."},
						},
					},
					Keep: false,
				},
			},
		},
		{
			Id:   "trace-policy",
			Name: "Trace Policy",
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_TraceField{TraceField: policyv1.TraceField_TRACE_FIELD_NAME},
							Match: &policyv1.TraceMatcher_EndsWith{EndsWith: "/health"},
						},
					},
					Keep: &policyv1.TraceSamplingConfig{Percentage: 1},
				},
			},
		},
	}

	compiled, err := compiler.Compile(policies, stats)
	require.NoError(t, err)
	defer compiled.Close()

	// Verify each policy type is in the correct compiled section
	logPolicy, ok := compiled.Logs.GetPolicy("log-policy")
	require.True(t, ok)
	assert.Equal(t, 1, logPolicy.MatcherCount)

	metricPolicy, ok := compiled.Metrics.GetPolicy("metric-policy")
	require.True(t, ok)
	assert.Equal(t, 1, metricPolicy.MatcherCount)

	tracePolicy, ok := compiled.Traces.GetPolicy("trace-policy")
	require.True(t, ok)
	assert.Equal(t, 1, tracePolicy.MatcherCount)

	// Verify counts
	assert.Equal(t, 1, compiled.Logs.PolicyCount())
	assert.Equal(t, 1, compiled.Metrics.PolicyCount())
	assert.Equal(t, 1, compiled.Traces.PolicyCount())
}
