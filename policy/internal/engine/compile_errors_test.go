package engine

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
)

// compileSingle compiles one policy and returns its per-policy errors joined
// with newlines, or "" if the policy compiled cleanly.
func compileSingle(t *testing.T, p *policyv1.Policy) string {
	t.Helper()
	stats := map[string]*PolicyStats{p.GetId(): {}}
	result, err := NewCompiler().Compile([]*policyv1.Policy{p}, stats)
	require.NoError(t, err)
	defer result.Close()
	return strings.Join(result.Errors[p.GetId()], "\n")
}

func logPolicy(matchers []*policyv1.LogMatcher, keep string) *policyv1.Policy {
	if keep == "" {
		keep = "all"
	}
	return &policyv1.Policy{
		Id: "p",
		Target: &policyv1.Policy_Log{
			Log: &policyv1.LogTarget{Match: matchers, Keep: keep},
		},
	}
}

func metricPolicy(matchers []*policyv1.MetricMatcher) *policyv1.Policy {
	return &policyv1.Policy{
		Id: "p",
		Target: &policyv1.Policy_Metric{
			Metric: &policyv1.MetricTarget{Match: matchers, Keep: true},
		},
	}
}

func tracePolicy(matchers []*policyv1.TraceMatcher) *policyv1.Policy {
	return &policyv1.Policy{
		Id: "p",
		Target: &policyv1.Policy_Trace{
			Trace: &policyv1.TraceTarget{Match: matchers, Keep: &policyv1.TraceSamplingConfig{Percentage: 100}},
		},
	}
}

// ============================================================================
// Log matcher errors
// ============================================================================

func TestCompileLogMatcherErrors(t *testing.T) {
	tests := []struct {
		name    string
		matcher *policyv1.LogMatcher
		want    string
	}{
		{
			name:    "no field set",
			matcher: &policyv1.LogMatcher{Match: &policyv1.LogMatcher_Contains{Contains: "x"}},
			want:    "no field set",
		},
		{
			name: "unspecified field enum",
			matcher: &policyv1.LogMatcher{
				Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_UNSPECIFIED},
				Match: &policyv1.LogMatcher_Contains{Contains: "x"},
			},
			want: "field is unspecified",
		},
		{
			name: "empty log attribute path",
			matcher: &policyv1.LogMatcher{
				Field: &policyv1.LogMatcher_LogAttribute{LogAttribute: &policyv1.AttributePath{}},
				Match: &policyv1.LogMatcher_Contains{Contains: "x"},
			},
			want: "empty path",
		},
		{
			name: "empty resource attribute path",
			matcher: &policyv1.LogMatcher{
				Field: &policyv1.LogMatcher_ResourceAttribute{ResourceAttribute: &policyv1.AttributePath{}},
				Match: &policyv1.LogMatcher_Contains{Contains: "x"},
			},
			want: "empty path",
		},
		{
			name: "empty scope attribute path",
			matcher: &policyv1.LogMatcher{
				Field: &policyv1.LogMatcher_ScopeAttribute{ScopeAttribute: &policyv1.AttributePath{}},
				Match: &policyv1.LogMatcher_Contains{Contains: "x"},
			},
			want: "empty path",
		},
		{
			name: "missing match condition",
			matcher: &policyv1.LogMatcher{
				Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
			},
			want: "no match condition set",
		},
		{
			name: "invalid regex",
			matcher: &policyv1.LogMatcher{
				Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
				Match: &policyv1.LogMatcher_Regex{Regex: "["},
			},
			want: "invalid regex",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := compileSingle(t, logPolicy([]*policyv1.LogMatcher{tt.matcher}, ""))
			assert.Contains(t, got, "log: match[0]")
			assert.Contains(t, got, tt.want)
		})
	}
}

// ============================================================================
// Log target-level errors (keep, sampleKey)
// ============================================================================

func TestCompileLogTargetErrors(t *testing.T) {
	good := []*policyv1.LogMatcher{
		{
			Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
			Match: &policyv1.LogMatcher_Contains{Contains: "x"},
		},
	}

	t.Run("bad keep", func(t *testing.T) {
		p := logPolicy(good, "garbage")
		got := compileSingle(t, p)
		assert.Contains(t, got, "log: keep:")
	})

	t.Run("sampleKey empty path", func(t *testing.T) {
		p := logPolicy(good, "")
		p.GetLog().SampleKey = &policyv1.LogSampleKey{
			Field: &policyv1.LogSampleKey_LogAttribute{LogAttribute: &policyv1.AttributePath{}},
		}
		got := compileSingle(t, p)
		assert.Contains(t, got, "log: sampleKey:")
		assert.Contains(t, got, "empty path")
	})

	t.Run("sampleKey unspecified field", func(t *testing.T) {
		p := logPolicy(good, "")
		p.GetLog().SampleKey = &policyv1.LogSampleKey{
			Field: &policyv1.LogSampleKey_LogField{LogField: policyv1.LogField_LOG_FIELD_UNSPECIFIED},
		}
		got := compileSingle(t, p)
		assert.Contains(t, got, "log: sampleKey:")
		assert.Contains(t, got, "unspecified")
	})

	t.Run("sampleKey no field set", func(t *testing.T) {
		p := logPolicy(good, "")
		p.GetLog().SampleKey = &policyv1.LogSampleKey{}
		got := compileSingle(t, p)
		assert.Contains(t, got, "log: sampleKey:")
		assert.Contains(t, got, "no field set")
	})
}

// ============================================================================
// Log transform errors
// ============================================================================

func TestCompileLogTransformErrors(t *testing.T) {
	good := []*policyv1.LogMatcher{
		{
			Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
			Match: &policyv1.LogMatcher_Contains{Contains: "x"},
		},
	}

	tests := []struct {
		name      string
		transform *policyv1.LogTransform
		want      []string
	}{
		{
			name: "remove no field",
			transform: &policyv1.LogTransform{
				Remove: []*policyv1.LogRemove{{}},
			},
			want: []string{"log: transform:", "remove[0]", "no field set"},
		},
		{
			name: "remove empty path",
			transform: &policyv1.LogTransform{
				Remove: []*policyv1.LogRemove{{
					Field: &policyv1.LogRemove_LogAttribute{LogAttribute: &policyv1.AttributePath{}},
				}},
			},
			want: []string{"remove[0]", "empty path"},
		},
		{
			name: "redact no field",
			transform: &policyv1.LogTransform{
				Redact: []*policyv1.LogRedact{{}},
			},
			want: []string{"redact[0]", "no field set"},
		},
		{
			name: "redact empty path",
			transform: &policyv1.LogTransform{
				Redact: []*policyv1.LogRedact{{
					Field: &policyv1.LogRedact_ResourceAttribute{ResourceAttribute: &policyv1.AttributePath{}},
				}},
			},
			want: []string{"redact[0]", "empty path"},
		},
		{
			name: "rename no from",
			transform: &policyv1.LogTransform{
				Rename: []*policyv1.LogRename{{To: "x"}},
			},
			want: []string{"rename[0]", "no field set"},
		},
		{
			name: "rename empty to",
			transform: &policyv1.LogTransform{
				Rename: []*policyv1.LogRename{{
					From: &policyv1.LogRename_FromLogAttribute{FromLogAttribute: &policyv1.AttributePath{Path: []string{"x"}}},
				}},
			},
			want: []string{"rename[0]", "to is empty"},
		},
		{
			name: "add no field",
			transform: &policyv1.LogTransform{
				Add: []*policyv1.LogAdd{{Value: "v"}},
			},
			want: []string{"add[0]", "no field set"},
		},
		{
			name: "add empty path",
			transform: &policyv1.LogTransform{
				Add: []*policyv1.LogAdd{{
					Field: &policyv1.LogAdd_ScopeAttribute{ScopeAttribute: &policyv1.AttributePath{}},
					Value: "v",
				}},
			},
			want: []string{"add[0]", "empty path"},
		},
		{
			name: "redact unspecified field",
			transform: &policyv1.LogTransform{
				Redact: []*policyv1.LogRedact{{
					Field: &policyv1.LogRedact_LogField{LogField: policyv1.LogField_LOG_FIELD_UNSPECIFIED},
				}},
			},
			want: []string{"redact[0]", "unspecified"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := logPolicy(good, "")
			p.GetLog().Transform = tt.transform
			got := compileSingle(t, p)
			for _, want := range tt.want {
				assert.Contains(t, got, want, "expected error message to contain %q in %q", want, got)
			}
		})
	}
}

// ============================================================================
// Metric matcher errors
// ============================================================================

func TestCompileMetricMatcherErrors(t *testing.T) {
	tests := []struct {
		name    string
		matcher *policyv1.MetricMatcher
		want    string
	}{
		{
			name:    "no field set",
			matcher: &policyv1.MetricMatcher{Match: &policyv1.MetricMatcher_Contains{Contains: "x"}},
			want:    "no field set",
		},
		{
			name: "unspecified field enum",
			matcher: &policyv1.MetricMatcher{
				Field: &policyv1.MetricMatcher_MetricField{MetricField: policyv1.MetricField_METRIC_FIELD_UNSPECIFIED},
				Match: &policyv1.MetricMatcher_Contains{Contains: "x"},
			},
			want: "field is unspecified",
		},
		{
			name: "empty datapoint attribute path",
			matcher: &policyv1.MetricMatcher{
				Field: &policyv1.MetricMatcher_DatapointAttribute{DatapointAttribute: &policyv1.AttributePath{}},
				Match: &policyv1.MetricMatcher_Contains{Contains: "x"},
			},
			want: "empty path",
		},
		{
			name: "empty resource attribute path",
			matcher: &policyv1.MetricMatcher{
				Field: &policyv1.MetricMatcher_ResourceAttribute{ResourceAttribute: &policyv1.AttributePath{}},
				Match: &policyv1.MetricMatcher_Contains{Contains: "x"},
			},
			want: "empty path",
		},
		{
			name: "empty scope attribute path",
			matcher: &policyv1.MetricMatcher{
				Field: &policyv1.MetricMatcher_ScopeAttribute{ScopeAttribute: &policyv1.AttributePath{}},
				Match: &policyv1.MetricMatcher_Contains{Contains: "x"},
			},
			want: "empty path",
		},
		{
			name: "missing match condition",
			matcher: &policyv1.MetricMatcher{
				Field: &policyv1.MetricMatcher_MetricField{MetricField: policyv1.MetricField_METRIC_FIELD_NAME},
			},
			want: "no match condition set",
		},
		{
			name: "invalid regex",
			matcher: &policyv1.MetricMatcher{
				Field: &policyv1.MetricMatcher_MetricField{MetricField: policyv1.MetricField_METRIC_FIELD_NAME},
				Match: &policyv1.MetricMatcher_Regex{Regex: "["},
			},
			want: "invalid regex",
		},
		{
			name: "metricType unspecified",
			matcher: &policyv1.MetricMatcher{
				Field: &policyv1.MetricMatcher_MetricType{MetricType: policyv1.MetricType_METRIC_TYPE_UNSPECIFIED},
			},
			want: "metricType is unspecified",
		},
		{
			name: "aggregationTemporality unspecified",
			matcher: &policyv1.MetricMatcher{
				Field: &policyv1.MetricMatcher_AggregationTemporality{AggregationTemporality: policyv1.AggregationTemporality_AGGREGATION_TEMPORALITY_UNSPECIFIED},
			},
			want: "aggregationTemporality is unspecified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := compileSingle(t, metricPolicy([]*policyv1.MetricMatcher{tt.matcher}))
			assert.Contains(t, got, "metric: match[0]")
			assert.Contains(t, got, tt.want)
		})
	}
}

// ============================================================================
// Trace matcher errors
// ============================================================================

func TestCompileTraceMatcherErrors(t *testing.T) {
	tests := []struct {
		name    string
		matcher *policyv1.TraceMatcher
		want    string
	}{
		{
			name:    "no field set",
			matcher: &policyv1.TraceMatcher{Match: &policyv1.TraceMatcher_Contains{Contains: "x"}},
			want:    "no field set",
		},
		{
			name: "unspecified field enum",
			matcher: &policyv1.TraceMatcher{
				Field: &policyv1.TraceMatcher_TraceField{TraceField: policyv1.TraceField_TRACE_FIELD_UNSPECIFIED},
				Match: &policyv1.TraceMatcher_Contains{Contains: "x"},
			},
			want: "field is unspecified",
		},
		{
			name: "empty span attribute path",
			matcher: &policyv1.TraceMatcher{
				Field: &policyv1.TraceMatcher_SpanAttribute{SpanAttribute: &policyv1.AttributePath{}},
				Match: &policyv1.TraceMatcher_Contains{Contains: "x"},
			},
			want: "empty path",
		},
		{
			name: "empty resource attribute path",
			matcher: &policyv1.TraceMatcher{
				Field: &policyv1.TraceMatcher_ResourceAttribute{ResourceAttribute: &policyv1.AttributePath{}},
				Match: &policyv1.TraceMatcher_Contains{Contains: "x"},
			},
			want: "empty path",
		},
		{
			name: "empty scope attribute path",
			matcher: &policyv1.TraceMatcher{
				Field: &policyv1.TraceMatcher_ScopeAttribute{ScopeAttribute: &policyv1.AttributePath{}},
				Match: &policyv1.TraceMatcher_Contains{Contains: "x"},
			},
			want: "empty path",
		},
		{
			name: "empty event attribute path",
			matcher: &policyv1.TraceMatcher{
				Field: &policyv1.TraceMatcher_EventAttribute{EventAttribute: &policyv1.AttributePath{}},
				Match: &policyv1.TraceMatcher_Contains{Contains: "x"},
			},
			want: "empty path",
		},
		{
			name: "missing match condition",
			matcher: &policyv1.TraceMatcher{
				Field: &policyv1.TraceMatcher_TraceField{TraceField: policyv1.TraceField_TRACE_FIELD_NAME},
			},
			want: "no match condition set",
		},
		{
			name: "invalid regex",
			matcher: &policyv1.TraceMatcher{
				Field: &policyv1.TraceMatcher_TraceField{TraceField: policyv1.TraceField_TRACE_FIELD_NAME},
				Match: &policyv1.TraceMatcher_Regex{Regex: "["},
			},
			want: "invalid regex",
		},
		{
			name: "spanKind unspecified",
			matcher: &policyv1.TraceMatcher{
				Field: &policyv1.TraceMatcher_SpanKind{SpanKind: policyv1.SpanKind_SPAN_KIND_UNSPECIFIED},
			},
			want: "spanKind is unspecified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := compileSingle(t, tracePolicy([]*policyv1.TraceMatcher{tt.matcher}))
			assert.Contains(t, got, "trace: match[0]")
			assert.Contains(t, got, tt.want)
		})
	}
}

// ============================================================================
// Aggregation / cross-cutting behavior
// ============================================================================

func TestCompileReportsMultipleErrorsForOnePolicy(t *testing.T) {
	got := compileSingle(t, logPolicy([]*policyv1.LogMatcher{
		{
			Field: &policyv1.LogMatcher_LogAttribute{LogAttribute: &policyv1.AttributePath{}},
			Match: &policyv1.LogMatcher_Exists{Exists: true},
		},
		{
			Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
		},
	}, ""))
	assert.Contains(t, got, "match[0]")
	assert.Contains(t, got, "match[1]")
}

func TestCompileReportsErrorsAcrossTargets(t *testing.T) {
	p := &policyv1.Policy{
		Id: "p",
		Target: &policyv1.Policy_Log{
			Log: &policyv1.LogTarget{
				Match: []*policyv1.LogMatcher{{
					Field: &policyv1.LogMatcher_LogAttribute{LogAttribute: &policyv1.AttributePath{}},
					Match: &policyv1.LogMatcher_Exists{Exists: true},
				}},
				Keep: "all",
			},
		},
	}
	// Switch to a metric+trace bundle by abusing two policies with the same ID.
	// Since proto Policy is a oneof, two policies — both compiled — should
	// surface errors keyed by id only when policy IDs differ. We test the
	// cross-target case via per-policy aggregation instead by giving one
	// policy a metric oneof and verifying metric errors come through.
	mp := metricPolicy([]*policyv1.MetricMatcher{{
		Field: &policyv1.MetricMatcher_DatapointAttribute{DatapointAttribute: &policyv1.AttributePath{}},
		Match: &policyv1.MetricMatcher_Contains{Contains: "x"},
	}})
	mp.Id = "m"

	stats := map[string]*PolicyStats{"p": {}, "m": {}}
	result, err := NewCompiler().Compile([]*policyv1.Policy{p, mp}, stats)
	require.NoError(t, err)
	defer result.Close()

	require.Contains(t, result.Errors, "p")
	require.Contains(t, result.Errors, "m")
	assert.Contains(t, strings.Join(result.Errors["p"], "\n"), "log: match[0]")
	assert.Contains(t, strings.Join(result.Errors["m"], "\n"), "metric: match[0]")
}

func TestCompileValidPolicyHasNoErrors(t *testing.T) {
	stats := map[string]*PolicyStats{"p": {}}
	result, err := NewCompiler().Compile([]*policyv1.Policy{
		logPolicy([]*policyv1.LogMatcher{{
			Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
			Match: &policyv1.LogMatcher_Contains{Contains: "ok"},
		}}, "all"),
	}, stats)
	require.NoError(t, err)
	defer result.Close()
	assert.Empty(t, result.Errors)
}

// TestCompileBrokenPolicyIsExcluded verifies that a policy with any compile
// error is excluded from the compiled set entirely — it is not registered,
// claims no dense index, and contributes none of its matchers (even the
// well-formed ones) to the index. This matches policy-rs/policy-zig, where a
// broken policy is absent rather than present-but-inert, so it never counts a
// hit and never participates in most-restrictive-wins resolution.
func TestCompileBrokenPolicyIsExcluded(t *testing.T) {
	p := logPolicy([]*policyv1.LogMatcher{
		{
			Field: &policyv1.LogMatcher_LogAttribute{LogAttribute: &policyv1.AttributePath{}}, // broken
			Match: &policyv1.LogMatcher_Exists{Exists: true},
		},
		{
			Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
			Match: &policyv1.LogMatcher_Contains{Contains: "anything"},
		},
	}, "all")
	stats := map[string]*PolicyStats{p.GetId(): {}}
	result, err := NewCompiler().Compile([]*policyv1.Policy{p}, stats)
	require.NoError(t, err)
	defer result.Close()

	require.Contains(t, result.Errors, p.GetId())

	_, ok := result.Logs.GetPolicy(p.GetId())
	assert.False(t, ok, "broken policy must not be registered")
	assert.Equal(t, 0, result.Logs.PolicyCount(), "broken policy claims no dense index")

	// Not even the well-formed second matcher reaches the index — the whole
	// policy is dropped.
	totalPatterns := 0
	for _, entry := range result.Logs.Databases() {
		totalPatterns += len(entry.Database.PatternIndex())
	}
	assert.Equal(t, 0, totalPatterns, "no matcher from a broken policy is registered")
}

// TestCompileBrokenPolicyDoesNotShiftValidIndices verifies that excluding a
// broken policy leaves the surviving policies densely indexed (0..N-1) with no
// gap where the broken policy would have been.
func TestCompileBrokenPolicyDoesNotShiftValidIndices(t *testing.T) {
	broken := logPolicy([]*policyv1.LogMatcher{{
		Field: &policyv1.LogMatcher_LogAttribute{LogAttribute: &policyv1.AttributePath{}}, // broken
		Match: &policyv1.LogMatcher_Exists{Exists: true},
	}}, "all")
	broken.Id = "a-broken"
	valid := logPolicy([]*policyv1.LogMatcher{{
		Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
		Match: &policyv1.LogMatcher_Contains{Contains: "ok"},
	}}, "all")
	valid.Id = "b-valid"

	stats := map[string]*PolicyStats{"a-broken": {}, "b-valid": {}}
	result, err := NewCompiler().Compile([]*policyv1.Policy{broken, valid}, stats)
	require.NoError(t, err)
	defer result.Close()

	require.Contains(t, result.Errors, "a-broken")
	require.Equal(t, 1, result.Logs.PolicyCount(), "only the valid policy is indexed")

	policy, ok := result.Logs.GetPolicy("b-valid")
	require.True(t, ok)
	assert.Equal(t, 0, policy.Index, "valid policy occupies index 0 — no gap left by the broken one")
	assert.Same(t, policy, result.Logs.PolicyByIndex(0))
}
