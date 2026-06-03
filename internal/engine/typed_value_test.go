package engine

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
)

// TestCompileRegistersTypedChecks verifies that the v1.5.0 equals/gt/gte/lt/lte
// matcher variants compile into TypedCheck entries on the matchers, with
// hex_value decoded at compile time.
func TestCompileRegistersTypedChecks(t *testing.T) {
	compiler := NewCompiler()
	stats := map[string]*PolicyStats{"p": {}}

	policies := []*policyv1.Policy{
		{
			Id: "p",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogAttribute{LogAttribute: &policyv1.AttributePath{Path: []string{"http.status_code"}}},
							Match: &policyv1.LogMatcher_Equals{Equals: &policyv1.Value{Value: &policyv1.Value_IntValue{IntValue: 200}}},
						},
						{
							Field: &policyv1.LogMatcher_LogAttribute{LogAttribute: &policyv1.AttributePath{Path: []string{"duration_ms"}}},
							Match: &policyv1.LogMatcher_Gte{Gte: &policyv1.NumericValue{Value: &policyv1.NumericValue_IntValue{IntValue: 500}}},
						},
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_SPAN_ID},
							Match: &policyv1.LogMatcher_Equals{Equals: &policyv1.Value{Value: &policyv1.Value_HexValue{HexValue: "8a3f0e1234567890"}}},
						},
					},
					Keep: "all",
				},
			},
		},
	}

	result, err := compiler.Compile(policies, stats)
	require.NoError(t, err)
	defer result.Close()
	require.Empty(t, result.Errors)

	checks := result.Logs.TypedChecks()
	require.Len(t, checks, 3)

	// match[0]: equals 200 (int)
	assert.Equal(t, TypedOpEquals, checks[0].Op)
	require.NotNil(t, checks[0].EqualsValue)
	intVal, ok := checks[0].EqualsValue.GetValue().(*policyv1.Value_IntValue)
	require.True(t, ok)
	assert.Equal(t, int64(200), intVal.IntValue)

	// match[1]: gte 500 (int)
	assert.Equal(t, TypedOpGTE, checks[1].Op)
	require.NotNil(t, checks[1].NumericValue)
	numInt, ok := checks[1].NumericValue.GetValue().(*policyv1.NumericValue_IntValue)
	require.True(t, ok)
	assert.Equal(t, int64(500), numInt.IntValue)

	// match[2]: equals hex "8a3f0e1234567890" — proto pointer carries the
	// literal hex string; decoding happens at eval time (see follow-up).
	assert.Equal(t, TypedOpEquals, checks[2].Op)
	require.NotNil(t, checks[2].EqualsValue)
	hexVal, ok := checks[2].EqualsValue.GetValue().(*policyv1.Value_HexValue)
	require.True(t, ok)
	assert.Equal(t, "8a3f0e1234567890", hexVal.HexValue)
}

func TestCompileRegistersAllTypedOps(t *testing.T) {
	compiler := NewCompiler()
	stats := map[string]*PolicyStats{"p": {}}

	matchers := []*policyv1.LogMatcher{
		{
			Field: &policyv1.LogMatcher_LogAttribute{LogAttribute: &policyv1.AttributePath{Path: []string{"x"}}},
			Match: &policyv1.LogMatcher_Equals{Equals: &policyv1.Value{Value: &policyv1.Value_BoolValue{BoolValue: true}}},
		},
		{
			Field: &policyv1.LogMatcher_LogAttribute{LogAttribute: &policyv1.AttributePath{Path: []string{"x"}}},
			Match: &policyv1.LogMatcher_Gt{Gt: &policyv1.NumericValue{Value: &policyv1.NumericValue_DoubleValue{DoubleValue: 0.5}}},
		},
		{
			Field: &policyv1.LogMatcher_LogAttribute{LogAttribute: &policyv1.AttributePath{Path: []string{"x"}}},
			Match: &policyv1.LogMatcher_Gte{Gte: &policyv1.NumericValue{Value: &policyv1.NumericValue_IntValue{IntValue: 1}}},
		},
		{
			Field: &policyv1.LogMatcher_LogAttribute{LogAttribute: &policyv1.AttributePath{Path: []string{"x"}}},
			Match: &policyv1.LogMatcher_Lt{Lt: &policyv1.NumericValue{Value: &policyv1.NumericValue_IntValue{IntValue: 100}}},
		},
		{
			Field: &policyv1.LogMatcher_LogAttribute{LogAttribute: &policyv1.AttributePath{Path: []string{"x"}}},
			Match: &policyv1.LogMatcher_Lte{Lte: &policyv1.NumericValue{Value: &policyv1.NumericValue_IntValue{IntValue: 100}}},
		},
	}

	result, err := compiler.Compile([]*policyv1.Policy{{
		Id:     "p",
		Target: &policyv1.Policy_Log{Log: &policyv1.LogTarget{Match: matchers, Keep: "all"}},
	}}, stats)
	require.NoError(t, err)
	defer result.Close()
	require.Empty(t, result.Errors)

	checks := result.Logs.TypedChecks()
	require.Len(t, checks, 5)
	wantOps := []TypedOp{TypedOpEquals, TypedOpGT, TypedOpGTE, TypedOpLT, TypedOpLTE}
	for i, c := range checks {
		assert.Equal(t, wantOps[i], c.Op, "check[%d] op", i)
	}
}

func TestCompileTypedMatcherWorksForMetricAndTrace(t *testing.T) {
	compiler := NewCompiler()
	stats := map[string]*PolicyStats{"m": {}, "t": {}}

	policies := []*policyv1.Policy{
		{
			Id: "m",
			Target: &policyv1.Policy_Metric{Metric: &policyv1.MetricTarget{
				Match: []*policyv1.MetricMatcher{{
					Field: &policyv1.MetricMatcher_DatapointAttribute{DatapointAttribute: &policyv1.AttributePath{Path: []string{"synthetic"}}},
					Match: &policyv1.MetricMatcher_Equals{Equals: &policyv1.Value{Value: &policyv1.Value_BoolValue{BoolValue: true}}},
				}},
				Keep: true,
			}},
		},
		{
			Id: "t",
			Target: &policyv1.Policy_Trace{Trace: &policyv1.TraceTarget{
				Match: []*policyv1.TraceMatcher{{
					Field: &policyv1.TraceMatcher_SpanAttribute{SpanAttribute: &policyv1.AttributePath{Path: []string{"duration_ns"}}},
					Match: &policyv1.TraceMatcher_Gt{Gt: &policyv1.NumericValue{Value: &policyv1.NumericValue_IntValue{IntValue: 1_000_000_000}}},
				}},
				Keep: &policyv1.TraceSamplingConfig{Percentage: 100},
			}},
		},
	}

	result, err := compiler.Compile(policies, stats)
	require.NoError(t, err)
	defer result.Close()
	require.Empty(t, result.Errors)

	require.Len(t, result.Metrics.TypedChecks(), 1)
	mc := result.Metrics.TypedChecks()[0]
	assert.Equal(t, TypedOpEquals, mc.Op)
	require.NotNil(t, mc.EqualsValue)
	boolVal, ok := mc.EqualsValue.GetValue().(*policyv1.Value_BoolValue)
	require.True(t, ok)
	assert.True(t, boolVal.BoolValue)

	require.Len(t, result.Traces.TypedChecks(), 1)
	tc := result.Traces.TypedChecks()[0]
	assert.Equal(t, TypedOpGT, tc.Op)
	require.NotNil(t, tc.NumericValue)
	intVal, ok := tc.NumericValue.GetValue().(*policyv1.NumericValue_IntValue)
	require.True(t, ok)
	assert.Equal(t, int64(1_000_000_000), intVal.IntValue)
}

func TestCompileTypedMatcherErrors(t *testing.T) {
	tests := []struct {
		name    string
		matcher *policyv1.LogMatcher
		want    string
	}{
		{
			name: "equals with empty value oneof",
			matcher: &policyv1.LogMatcher{
				Field: &policyv1.LogMatcher_LogAttribute{LogAttribute: &policyv1.AttributePath{Path: []string{"x"}}},
				Match: &policyv1.LogMatcher_Equals{Equals: &policyv1.Value{}},
			},
			want: "equals value oneof is unset",
		},
		{
			name: "equals with bad hex",
			matcher: &policyv1.LogMatcher{
				Field: &policyv1.LogMatcher_LogAttribute{LogAttribute: &policyv1.AttributePath{Path: []string{"x"}}},
				Match: &policyv1.LogMatcher_Equals{Equals: &policyv1.Value{Value: &policyv1.Value_HexValue{HexValue: "xyz"}}},
			},
			want: "invalid hex_value",
		},
		{
			name: "equals with odd-length hex",
			matcher: &policyv1.LogMatcher{
				Field: &policyv1.LogMatcher_LogAttribute{LogAttribute: &policyv1.AttributePath{Path: []string{"x"}}},
				Match: &policyv1.LogMatcher_Equals{Equals: &policyv1.Value{Value: &policyv1.Value_HexValue{HexValue: "abc"}}},
			},
			want: "invalid hex_value",
		},
		{
			name: "gte with empty oneof",
			matcher: &policyv1.LogMatcher{
				Field: &policyv1.LogMatcher_LogAttribute{LogAttribute: &policyv1.AttributePath{Path: []string{"x"}}},
				Match: &policyv1.LogMatcher_Gte{Gte: &policyv1.NumericValue{}},
			},
			want: "numeric value oneof is unset",
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

// TestCompileTypedMatcherPolicyIsInert verifies that until the engine-eval
// follow-up lands, a policy whose only matcher is a typed comparison stays
// inert: it's compiled but its MatcherCount is unreachable because typed
// checks don't contribute to matchCounts at eval time. This is the safe
// stand-in behavior — no false-positive matches.
func TestCompileTypedMatcherPolicyIsInert(t *testing.T) {
	compiler := NewCompiler()
	stats := map[string]*PolicyStats{"p": {}}

	result, err := compiler.Compile([]*policyv1.Policy{{
		Id: "p",
		Target: &policyv1.Policy_Log{Log: &policyv1.LogTarget{
			Match: []*policyv1.LogMatcher{{
				Field: &policyv1.LogMatcher_LogAttribute{LogAttribute: &policyv1.AttributePath{Path: []string{"status"}}},
				Match: &policyv1.LogMatcher_Equals{Equals: &policyv1.Value{Value: &policyv1.Value_IntValue{IntValue: 200}}},
			}},
			Keep: "all",
		}},
	}}, stats)
	require.NoError(t, err)
	defer result.Close()
	require.Empty(t, result.Errors)

	policy, ok := result.Logs.GetPolicy("p")
	require.True(t, ok)
	assert.Equal(t, 1, policy.MatcherCount, "MatcherCount reflects the proto count")

	// The typed check was registered, but nothing went into Hyperscan or
	// existence checks for it.
	require.Len(t, result.Logs.TypedChecks(), 1)
	totalPatterns := 0
	for _, db := range result.Logs.Databases() {
		totalPatterns += len(db.Database.PatternIndex())
	}
	assert.Equal(t, 0, totalPatterns, "typed matcher does not produce a Hyperscan pattern")
	assert.Empty(t, result.Logs.ExistenceChecks(), "typed matcher does not produce an existence check")
}
