package engine

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
)

func TestCompilerCompilesTracePolicies(t *testing.T) {
	compiler := NewCompiler()
	stats := map[string]*PolicyStats{
		"trace-policy": {},
	}

	policies := []*policyv1.Policy{
		{
			Id:   "trace-policy",
			Name: "Trace Policy",
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_TraceField{TraceField: policyv1.TraceField_TRACE_FIELD_NAME},
							Match: &policyv1.TraceMatcher_Regex{Regex: "GET /api/.*"},
						},
					},
					Keep: &policyv1.TraceSamplingConfig{Percentage: 100},
				},
			},
		},
	}

	compiled, err := compiler.Compile(policies, stats)
	require.NoError(t, err)
	defer compiled.Close()

	// Log and metric policies should be empty
	assert.Empty(t, compiled.Logs.Policies())
	assert.Empty(t, compiled.Metrics.Policies())

	// Trace policies should have the policy
	policy, ok := compiled.Traces.GetPolicy("trace-policy")
	require.True(t, ok, "expected to find trace-policy")
	assert.Equal(t, 1, policy.MatcherCount)
}

func TestCompilerTracePolicyWithSpanKind(t *testing.T) {
	compiler := NewCompiler()
	stats := map[string]*PolicyStats{
		"span-kind-policy": {},
	}

	policies := []*policyv1.Policy{
		{
			Id:   "span-kind-policy",
			Name: "Span Kind Policy",
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_SpanKind{SpanKind: policyv1.SpanKind_SPAN_KIND_SERVER},
							// Match field is ignored - enum value is used as exact match
						},
					},
					Keep: &policyv1.TraceSamplingConfig{Percentage: 50},
				},
			},
		},
	}

	compiled, err := compiler.Compile(policies, stats)
	require.NoError(t, err)
	defer compiled.Close()

	policy, ok := compiled.Traces.GetPolicy("span-kind-policy")
	require.True(t, ok)
	assert.Equal(t, 1, policy.MatcherCount)

	// SpanKind should generate a pattern match (exact match on enum string), not existence check
	require.Equal(t, 1, len(compiled.Traces.Databases()))
	entry := compiled.Traces.Databases()[0]
	assert.Equal(t, TraceFieldKind, entry.Key.Ref.Field)
	assert.Empty(t, compiled.Traces.ExistenceChecks())
}

func TestCompilerTracePolicyWithSpanStatus(t *testing.T) {
	compiler := NewCompiler()
	stats := map[string]*PolicyStats{
		"span-status-policy": {},
	}

	policies := []*policyv1.Policy{
		{
			Id:   "span-status-policy",
			Name: "Span Status Policy",
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_SpanStatus{SpanStatus: policyv1.SpanStatusCode_SPAN_STATUS_CODE_ERROR},
							// Match field is ignored - enum value is used as exact match
						},
					},
					Keep: &policyv1.TraceSamplingConfig{Percentage: 100},
				},
			},
		},
	}

	compiled, err := compiler.Compile(policies, stats)
	require.NoError(t, err)
	defer compiled.Close()

	policy, ok := compiled.Traces.GetPolicy("span-status-policy")
	require.True(t, ok)
	assert.Equal(t, 1, policy.MatcherCount)

	// SpanStatus should generate a pattern match (exact match on enum string), not existence check
	require.Equal(t, 1, len(compiled.Traces.Databases()))
	entry := compiled.Traces.Databases()[0]
	assert.Equal(t, TraceFieldStatus, entry.Key.Ref.Field)
	assert.Empty(t, compiled.Traces.ExistenceChecks())
}

func TestCompilerTracePolicyWithSpanStatusUnset(t *testing.T) {
	compiler := NewCompiler()
	stats := map[string]*PolicyStats{
		"span-status-unset": {},
	}

	policies := []*policyv1.Policy{
		{
			Id:   "span-status-unset",
			Name: "Span Status Unset Policy",
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_SpanStatus{SpanStatus: policyv1.SpanStatusCode_SPAN_STATUS_CODE_UNSPECIFIED},
						},
					},
					Keep: &policyv1.TraceSamplingConfig{Percentage: 100},
				},
			},
		},
	}

	compiled, err := compiler.Compile(policies, stats)
	require.NoError(t, err)
	defer compiled.Close()

	policy, ok := compiled.Traces.GetPolicy("span-status-unset")
	require.True(t, ok)
	assert.Equal(t, 1, policy.MatcherCount)

	// SpanStatus UNSET should generate a pattern match, not be skipped
	require.Equal(t, 1, len(compiled.Traces.Databases()))
	entry := compiled.Traces.Databases()[0]
	assert.Equal(t, TraceFieldStatus, entry.Key.Ref.Field)
	assert.Empty(t, compiled.Traces.ExistenceChecks())
}

func TestCompilerTracePolicyWithEventName(t *testing.T) {
	compiler := NewCompiler()
	stats := map[string]*PolicyStats{
		"event-name-policy": {},
	}

	policies := []*policyv1.Policy{
		{
			Id:   "event-name-policy",
			Name: "Event Name Policy",
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
	}

	compiled, err := compiler.Compile(policies, stats)
	require.NoError(t, err)
	defer compiled.Close()

	policy, ok := compiled.Traces.GetPolicy("event-name-policy")
	require.True(t, ok)
	assert.Equal(t, 1, policy.MatcherCount)

	// Event name should create a database
	require.Equal(t, 1, len(compiled.Traces.Databases()))
	entry := compiled.Traces.Databases()[0]
	assert.Equal(t, TraceFieldEventName, entry.Key.Ref.Field)
}

func TestCompilerTracePolicyWithEventAttribute(t *testing.T) {
	compiler := NewCompiler()
	stats := map[string]*PolicyStats{
		"event-attr-policy": {},
	}

	policies := []*policyv1.Policy{
		{
			Id:   "event-attr-policy",
			Name: "Event Attribute Policy",
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_EventAttribute{EventAttribute: &policyv1.AttributePath{Path: []string{"exception", "message"}}},
							Match: &policyv1.TraceMatcher_Contains{Contains: "NullPointerException"},
						},
					},
					Keep: &policyv1.TraceSamplingConfig{Percentage: 100},
				},
			},
		},
	}

	compiled, err := compiler.Compile(policies, stats)
	require.NoError(t, err)
	defer compiled.Close()

	policy, ok := compiled.Traces.GetPolicy("event-attr-policy")
	require.True(t, ok)
	assert.Equal(t, 1, policy.MatcherCount)

	require.Equal(t, 1, len(compiled.Traces.Databases()))
	entry := compiled.Traces.Databases()[0]
	assert.Equal(t, AttrScopeEvent, entry.Key.Ref.AttrScope)
	assert.Equal(t, []string{"exception", "message"}, entry.Key.Ref.AttrPath)
}

func TestCompilerTracePolicyWithLinkTraceID(t *testing.T) {
	compiler := NewCompiler()
	stats := map[string]*PolicyStats{
		"link-trace-policy": {},
	}

	policies := []*policyv1.Policy{
		{
			Id:   "link-trace-policy",
			Name: "Link Trace ID Policy",
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_LinkTraceId{LinkTraceId: "abc123"},
							Match: &policyv1.TraceMatcher_Exact{Exact: "abc123"},
						},
					},
					Keep: &policyv1.TraceSamplingConfig{Percentage: 100},
				},
			},
		},
	}

	compiled, err := compiler.Compile(policies, stats)
	require.NoError(t, err)
	defer compiled.Close()

	policy, ok := compiled.Traces.GetPolicy("link-trace-policy")
	require.True(t, ok)
	assert.Equal(t, 1, policy.MatcherCount)

	require.Equal(t, 1, len(compiled.Traces.Databases()))
	entry := compiled.Traces.Databases()[0]
	assert.Equal(t, TraceFieldLinkTraceID, entry.Key.Ref.Field)
}

func TestCompilerTracePolicyWithSpanAttribute(t *testing.T) {
	compiler := NewCompiler()
	stats := map[string]*PolicyStats{
		"span-attr-policy": {},
	}

	policies := []*policyv1.Policy{
		{
			Id:   "span-attr-policy",
			Name: "Span Attribute Policy",
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_SpanAttribute{SpanAttribute: &policyv1.AttributePath{Path: []string{"http.method"}}},
							Match: &policyv1.TraceMatcher_Exact{Exact: "GET"},
						},
					},
					Keep: &policyv1.TraceSamplingConfig{Percentage: 100},
				},
			},
		},
	}

	compiled, err := compiler.Compile(policies, stats)
	require.NoError(t, err)
	defer compiled.Close()

	require.Equal(t, 1, len(compiled.Traces.Databases()))
	entry := compiled.Traces.Databases()[0]
	assert.Equal(t, AttrScopeRecord, entry.Key.Ref.AttrScope)
	assert.Equal(t, []string{"http.method"}, entry.Key.Ref.AttrPath)
}

func TestCompilerTracePolicyWithResourceAttribute(t *testing.T) {
	compiler := NewCompiler()
	stats := map[string]*PolicyStats{
		"trace-resource-attr": {},
	}

	policies := []*policyv1.Policy{
		{
			Id:   "trace-resource-attr",
			Name: "Trace Resource Attribute Policy",
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_ResourceAttribute{ResourceAttribute: &policyv1.AttributePath{Path: []string{"service.name"}}},
							Match: &policyv1.TraceMatcher_StartsWith{StartsWith: "api-"},
						},
					},
					Keep: &policyv1.TraceSamplingConfig{Percentage: 100},
				},
			},
		},
	}

	compiled, err := compiler.Compile(policies, stats)
	require.NoError(t, err)
	defer compiled.Close()

	require.Equal(t, 1, len(compiled.Traces.Databases()))
	entry := compiled.Traces.Databases()[0]
	assert.Equal(t, AttrScopeResource, entry.Key.Ref.AttrScope)
	assert.Equal(t, []string{"service.name"}, entry.Key.Ref.AttrPath)
}

func TestCompilerTracePolicyWithScopeAttribute(t *testing.T) {
	compiler := NewCompiler()
	stats := map[string]*PolicyStats{
		"trace-scope-attr": {},
	}

	policies := []*policyv1.Policy{
		{
			Id:   "trace-scope-attr",
			Name: "Trace Scope Attribute Policy",
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_ScopeAttribute{ScopeAttribute: &policyv1.AttributePath{Path: []string{"library.version"}}},
							Match: &policyv1.TraceMatcher_Regex{Regex: "1\\..*"},
						},
					},
					Keep: &policyv1.TraceSamplingConfig{Percentage: 100},
				},
			},
		},
	}

	compiled, err := compiler.Compile(policies, stats)
	require.NoError(t, err)
	defer compiled.Close()

	require.Equal(t, 1, len(compiled.Traces.Databases()))
	entry := compiled.Traces.Databases()[0]
	assert.Equal(t, AttrScopeScope, entry.Key.Ref.AttrScope)
	assert.Equal(t, []string{"library.version"}, entry.Key.Ref.AttrPath)
}

func TestCompilerTracePolicyMultipleMatchers(t *testing.T) {
	compiler := NewCompiler()
	stats := map[string]*PolicyStats{
		"multi-trace-matcher": {},
	}

	policies := []*policyv1.Policy{
		{
			Id:   "multi-trace-matcher",
			Name: "Multiple Trace Matchers",
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_TraceField{TraceField: policyv1.TraceField_TRACE_FIELD_NAME},
							Match: &policyv1.TraceMatcher_Contains{Contains: "/health"},
						},
						{
							Field: &policyv1.TraceMatcher_SpanKind{SpanKind: policyv1.SpanKind_SPAN_KIND_SERVER},
							// Match field is ignored - enum value is used as exact match
						},
						{
							Field: &policyv1.TraceMatcher_ResourceAttribute{ResourceAttribute: &policyv1.AttributePath{Path: []string{"k8s.namespace"}}},
							Match: &policyv1.TraceMatcher_Exact{Exact: "production"},
						},
					},
					Keep: &policyv1.TraceSamplingConfig{Percentage: 10},
				},
			},
		},
	}

	compiled, err := compiler.Compile(policies, stats)
	require.NoError(t, err)
	defer compiled.Close()

	policy, ok := compiled.Traces.GetPolicy("multi-trace-matcher")
	require.True(t, ok)
	assert.Equal(t, 3, policy.MatcherCount)

	// Should have 3 databases (span name, span kind, and resource attr) and no existence checks
	assert.Equal(t, 3, len(compiled.Traces.Databases()))
	assert.Empty(t, compiled.Traces.ExistenceChecks())
}

func TestCompilerTracePolicyWithScopeName(t *testing.T) {
	compiler := NewCompiler()
	stats := map[string]*PolicyStats{
		"scope-name-policy": {},
	}

	policies := []*policyv1.Policy{
		{
			Id:   "scope-name-policy",
			Name: "Scope Name Policy",
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_TraceField{TraceField: policyv1.TraceField_TRACE_FIELD_SCOPE_NAME},
							Match: &policyv1.TraceMatcher_Exact{Exact: "my.instrumentation.library"},
						},
					},
					Keep: &policyv1.TraceSamplingConfig{Percentage: 100},
				},
			},
		},
	}

	compiled, err := compiler.Compile(policies, stats)
	require.NoError(t, err)
	defer compiled.Close()

	policy, ok := compiled.Traces.GetPolicy("scope-name-policy")
	require.True(t, ok)
	assert.Equal(t, 1, policy.MatcherCount)

	require.Equal(t, 1, len(compiled.Traces.Databases()))
	entry := compiled.Traces.Databases()[0]
	assert.Equal(t, TraceFieldScopeName, entry.Key.Ref.Field)
}

func TestCompilerTracePolicyWithResourceSchemaURL(t *testing.T) {
	compiler := NewCompiler()
	stats := map[string]*PolicyStats{
		"schema-url-policy": {},
	}

	policies := []*policyv1.Policy{
		{
			Id:   "schema-url-policy",
			Name: "Schema URL Policy",
			Target: &policyv1.Policy_Trace{
				Trace: &policyv1.TraceTarget{
					Match: []*policyv1.TraceMatcher{
						{
							Field: &policyv1.TraceMatcher_TraceField{TraceField: policyv1.TraceField_TRACE_FIELD_RESOURCE_SCHEMA_URL},
							Match: &policyv1.TraceMatcher_Contains{Contains: "v1.0.0"},
						},
					},
					Keep: &policyv1.TraceSamplingConfig{Percentage: 100},
				},
			},
		},
	}

	compiled, err := compiler.Compile(policies, stats)
	require.NoError(t, err)
	defer compiled.Close()

	policy, ok := compiled.Traces.GetPolicy("schema-url-policy")
	require.True(t, ok)
	assert.Equal(t, 1, policy.MatcherCount)

	require.Equal(t, 1, len(compiled.Traces.Databases()))
	entry := compiled.Traces.Databases()[0]
	assert.Equal(t, TraceFieldResourceSchemaURL, entry.Key.Ref.Field)
}
