package jsonpolicy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
)

// parseFirstLogMatcher decodes a JSON policy file with one log policy and
// returns the first matcher, halting the test on any error.
func parseFirstLogMatcher(t *testing.T, json string) *policyv1.LogMatcher {
	t.Helper()
	pols, err := NewParser().ParseBytes([]byte(json))
	require.NoError(t, err)
	require.Len(t, pols, 1)
	require.NotNil(t, pols[0].GetLog())
	require.Len(t, pols[0].GetLog().GetMatch(), 1)
	return pols[0].GetLog().GetMatch()[0]
}

// ============================================================================
// equals — shorthand forms (type inferred from literal)
// ============================================================================

func TestParseEqualsShorthandBool(t *testing.T) {
	m := parseFirstLogMatcher(t, `{
		"policies": [{
			"id": "p", "name": "P",
			"log": {
				"match": [{"log_attribute": ["deprecated"], "equals": true}],
				"keep": "all"
			}
		}]
	}`)
	eq, ok := m.GetMatch().(*policyv1.LogMatcher_Equals)
	require.True(t, ok)
	bv, ok := eq.Equals.GetValue().(*policyv1.Value_BoolValue)
	require.True(t, ok)
	assert.True(t, bv.BoolValue)
}

func TestParseEqualsShorthandInt(t *testing.T) {
	m := parseFirstLogMatcher(t, `{
		"policies": [{
			"id": "p", "name": "P",
			"log": {
				"match": [{"log_attribute": ["http.status_code"], "equals": 200}],
				"keep": "all"
			}
		}]
	}`)
	eq := m.GetMatch().(*policyv1.LogMatcher_Equals)
	iv, ok := eq.Equals.GetValue().(*policyv1.Value_IntValue)
	require.True(t, ok)
	assert.Equal(t, int64(200), iv.IntValue)
}

func TestParseEqualsShorthandDouble(t *testing.T) {
	m := parseFirstLogMatcher(t, `{
		"policies": [{
			"id": "p", "name": "P",
			"log": {
				"match": [{"log_attribute": ["sampling.ratio"], "equals": 0.5}],
				"keep": "all"
			}
		}]
	}`)
	eq := m.GetMatch().(*policyv1.LogMatcher_Equals)
	dv, ok := eq.Equals.GetValue().(*policyv1.Value_DoubleValue)
	require.True(t, ok)
	assert.Equal(t, 0.5, dv.DoubleValue)
}

// ============================================================================
// equals — canonical proto forms
// ============================================================================

func TestParseEqualsCanonicalIntValue(t *testing.T) {
	m := parseFirstLogMatcher(t, `{
		"policies": [{
			"id": "p", "name": "P",
			"log": {
				"match": [{"log_attribute": ["x"], "equals": {"int_value": 42}}],
				"keep": "all"
			}
		}]
	}`)
	eq := m.GetMatch().(*policyv1.LogMatcher_Equals)
	iv := eq.Equals.GetValue().(*policyv1.Value_IntValue)
	assert.Equal(t, int64(42), iv.IntValue)
}

func TestParseEqualsCanonicalHexValue(t *testing.T) {
	m := parseFirstLogMatcher(t, `{
		"policies": [{
			"id": "p", "name": "P",
			"log": {
				"match": [{"log_field": "span_id", "equals": {"hex_value": "8a3f0e1234567890"}}],
				"keep": "all"
			}
		}]
	}`)
	eq := m.GetMatch().(*policyv1.LogMatcher_Equals)
	hv, ok := eq.Equals.GetValue().(*policyv1.Value_HexValue)
	require.True(t, ok)
	assert.Equal(t, "8a3f0e1234567890", hv.HexValue)
}

func TestParseEqualsCanonicalBytesValue(t *testing.T) {
	// Base64 for the 4-byte sequence DE AD BE EF.
	m := parseFirstLogMatcher(t, `{
		"policies": [{
			"id": "p", "name": "P",
			"log": {
				"match": [{"log_attribute": ["raw.token"], "equals": {"bytes_value": "3q2+7w=="}}],
				"keep": "all"
			}
		}]
	}`)
	eq := m.GetMatch().(*policyv1.LogMatcher_Equals)
	bv, ok := eq.Equals.GetValue().(*policyv1.Value_BytesValue)
	require.True(t, ok)
	assert.Equal(t, []byte{0xde, 0xad, 0xbe, 0xef}, bv.BytesValue)
}

// ============================================================================
// equals — rejected forms
// ============================================================================

func TestParseEqualsRejectsStringLiteral(t *testing.T) {
	_, err := NewParser().ParseBytes([]byte(`{
		"policies": [{
			"id": "p", "name": "P",
			"log": {
				"match": [{"log_attribute": ["x"], "equals": "foo"}],
				"keep": "all"
			}
		}]
	}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "string literal not allowed")
}

func TestParseEqualsRejectsBadHex(t *testing.T) {
	_, err := NewParser().ParseBytes([]byte(`{
		"policies": [{
			"id": "p", "name": "P",
			"log": {
				"match": [{"log_attribute": ["x"], "equals": {"hex_value": "xyz"}}],
				"keep": "all"
			}
		}]
	}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid hex")
}

func TestParseEqualsRejectsMultipleCanonicalVariants(t *testing.T) {
	_, err := NewParser().ParseBytes([]byte(`{
		"policies": [{
			"id": "p", "name": "P",
			"log": {
				"match": [{"log_attribute": ["x"], "equals": {"int_value": 1, "bool_value": true}}],
				"keep": "all"
			}
		}]
	}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exactly one variant")
}

func TestParseEqualsRejectsEmptyCanonical(t *testing.T) {
	_, err := NewParser().ParseBytes([]byte(`{
		"policies": [{
			"id": "p", "name": "P",
			"log": {
				"match": [{"log_attribute": ["x"], "equals": {}}],
				"keep": "all"
			}
		}]
	}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exactly one variant")
}

// ============================================================================
// gt / gte / lt / lte
// ============================================================================

func TestParseNumericComparators(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		wantKey string
	}{
		{"gt shorthand int", `"gt": 100`, "gt"},
		{"gte shorthand double", `"gte": 0.95`, "gte"},
		{"lt canonical", `"lt": {"int_value": 50}`, "lt"},
		{"lte canonical double", `"lte": {"double_value": 0.5}`, "lte"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			json := `{"policies": [{"id": "p", "name": "P", "log": {"match": [{"log_attribute": ["x"], ` + tt.json + `}], "keep": "all"}}]}`
			m := parseFirstLogMatcher(t, json)
			switch tt.wantKey {
			case "gt":
				_, ok := m.GetMatch().(*policyv1.LogMatcher_Gt)
				assert.True(t, ok, "expected Gt match")
			case "gte":
				_, ok := m.GetMatch().(*policyv1.LogMatcher_Gte)
				assert.True(t, ok, "expected Gte match")
			case "lt":
				_, ok := m.GetMatch().(*policyv1.LogMatcher_Lt)
				assert.True(t, ok, "expected Lt match")
			case "lte":
				_, ok := m.GetMatch().(*policyv1.LogMatcher_Lte)
				assert.True(t, ok, "expected Lte match")
			}
		})
	}
}

func TestParseNumericPicksIntVsDouble(t *testing.T) {
	m := parseFirstLogMatcher(t, `{
		"policies": [{
			"id": "p", "name": "P",
			"log": {
				"match": [{"log_attribute": ["x"], "gte": 500}],
				"keep": "all"
			}
		}]
	}`)
	gte := m.GetMatch().(*policyv1.LogMatcher_Gte)
	_, isInt := gte.Gte.GetValue().(*policyv1.NumericValue_IntValue)
	assert.True(t, isInt, "integer literal should select IntValue")

	m = parseFirstLogMatcher(t, `{
		"policies": [{
			"id": "p", "name": "P",
			"log": {
				"match": [{"log_attribute": ["x"], "gte": 500.0}],
				"keep": "all"
			}
		}]
	}`)
	gte = m.GetMatch().(*policyv1.LogMatcher_Gte)
	_, isDouble := gte.Gte.GetValue().(*policyv1.NumericValue_DoubleValue)
	assert.True(t, isDouble, "fractional literal should select DoubleValue")
}

func TestParseNumericRejectsBool(t *testing.T) {
	_, err := NewParser().ParseBytes([]byte(`{
		"policies": [{
			"id": "p", "name": "P",
			"log": {
				"match": [{"log_attribute": ["x"], "gt": true}],
				"keep": "all"
			}
		}]
	}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bool literal not allowed")
}

func TestParseNumericRejectsString(t *testing.T) {
	_, err := NewParser().ParseBytes([]byte(`{
		"policies": [{
			"id": "p", "name": "P",
			"log": {
				"match": [{"log_attribute": ["x"], "gt": "100"}],
				"keep": "all"
			}
		}]
	}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "string literal not allowed")
}

func TestParseNumericRejectsCanonicalWithBothVariants(t *testing.T) {
	_, err := NewParser().ParseBytes([]byte(`{
		"policies": [{
			"id": "p", "name": "P",
			"log": {
				"match": [{"log_attribute": ["x"], "gt": {"int_value": 1, "double_value": 1.5}}],
				"keep": "all"
			}
		}]
	}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exactly one variant")
}

// ============================================================================
// metric / trace also accept the new matchers
// ============================================================================

func TestParseTypedMatchersOnMetricAndTrace(t *testing.T) {
	pols, err := NewParser().ParseBytes([]byte(`{
		"policies": [
			{
				"id": "m", "name": "M",
				"metric": {
					"match": [{"datapoint_attribute": ["synthetic"], "equals": true}],
					"keep": true
				}
			},
			{
				"id": "t", "name": "T",
				"trace": {
					"match": [{"span_attribute": ["duration_ns"], "gt": 1000000000}],
					"keep": {"percentage": 100}
				}
			}
		]
	}`))
	require.NoError(t, err)
	require.Len(t, pols, 2)

	metricMatch := pols[0].GetMetric().GetMatch()[0].GetMatch()
	_, ok := metricMatch.(*policyv1.MetricMatcher_Equals)
	assert.True(t, ok, "metric should have Equals match")

	traceMatch := pols[1].GetTrace().GetMatch()[0].GetMatch()
	gt, ok := traceMatch.(*policyv1.TraceMatcher_Gt)
	require.True(t, ok, "trace should have Gt match")
	iv := gt.Gt.GetValue().(*policyv1.NumericValue_IntValue)
	assert.Equal(t, int64(1_000_000_000), iv.IntValue)
}
