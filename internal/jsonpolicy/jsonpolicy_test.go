package jsonpolicy

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/usetero/policy-go/internal/engine"
)

func TestParserParseEmpty(t *testing.T) {
	parser := NewParser()

	policies, err := parser.ParseBytes([]byte(`{"policies": []}`))
	require.NoError(t, err)
	assert.Empty(t, policies)
}

func TestParserParseSinglePolicy(t *testing.T) {
	parser := NewParser()

	json := `{
		"policies": [
			{
				"id": "test-policy",
				"name": "Test Policy",
				"log": {
					"match": [
						{"log_field": "body", "regex": "error"}
					],
					"keep": "none"
				}
			}
		]
	}`

	policies, err := parser.ParseBytes([]byte(json))
	require.NoError(t, err)
	require.Len(t, policies, 1)

	p := policies[0]
	assert.Equal(t, "test-policy", p.ID)
	assert.Equal(t, "Test Policy", p.Name)
	require.NotNil(t, p.Log)
	assert.Len(t, p.Log.Matchers, 1)
	assert.Equal(t, engine.KeepNone, p.Log.Keep.Action)
}

func TestParserParseReader(t *testing.T) {
	parser := NewParser()

	json := `{
		"policies": [
			{
				"id": "reader-test",
				"name": "Reader Test",
				"log": {
					"match": [{"log_field": "body", "regex": "test"}],
					"keep": "all"
				}
			}
		]
	}`

	policies, err := parser.Parse(strings.NewReader(json))
	require.NoError(t, err)
	require.Len(t, policies, 1)
	assert.Equal(t, "reader-test", policies[0].ID)
}

func TestParserParseMultiplePolicies(t *testing.T) {
	parser := NewParser()

	json := `{
		"policies": [
			{
				"id": "policy-1",
				"name": "Policy 1",
				"log": {
					"match": [{"log_field": "body", "regex": "error"}],
					"keep": "none"
				}
			},
			{
				"id": "policy-2",
				"name": "Policy 2",
				"log": {
					"match": [{"log_field": "severity_text", "exact": "DEBUG"}],
					"keep": false
				}
			}
		]
	}`

	policies, err := parser.ParseBytes([]byte(json))
	require.NoError(t, err)
	require.Len(t, policies, 2)

	assert.Equal(t, "policy-1", policies[0].ID)
	assert.Equal(t, "policy-2", policies[1].ID)
}

func TestParserParseAllLogFields(t *testing.T) {
	tests := []struct {
		name     string
		field    string
		expected engine.LogField
	}{
		{"body", "body", engine.LogFieldBody},
		{"severity_text", "severity_text", engine.LogFieldSeverityText},
		{"severity_number", "severity_number", engine.LogFieldSeverityNumber},
		{"timestamp", "timestamp", engine.LogFieldTimestamp},
		{"trace_id", "trace_id", engine.LogFieldTraceID},
		{"span_id", "span_id", engine.LogFieldSpanID},
	}

	parser := NewParser()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			json := `{
				"policies": [{
					"id": "test",
					"name": "Test",
					"log": {
						"match": [{"log_field": "` + tt.field + `", "regex": "test"}],
						"keep": "all"
					}
				}]
			}`

			policies, err := parser.ParseBytes([]byte(json))
			require.NoError(t, err)

			matcher := policies[0].Log.Matchers[0]
			assert.Equal(t, engine.FieldTypeLogField, matcher.Field.Type)
			assert.Equal(t, tt.expected, matcher.Field.Field)
		})
	}
}

func TestParserParseUnknownLogField(t *testing.T) {
	parser := NewParser()

	json := `{
		"policies": [{
			"id": "test",
			"name": "Test",
			"log": {
				"match": [{"log_field": "unknown_field", "regex": "test"}],
				"keep": "all"
			}
		}]
	}`

	_, err := parser.ParseBytes([]byte(json))
	require.Error(t, err)
}

func TestParserParseLogAttribute(t *testing.T) {
	parser := NewParser()

	json := `{
		"policies": [{
			"id": "test",
			"name": "Test",
			"log": {
				"match": [{"log_attribute": "custom_attr", "regex": "value"}],
				"keep": "all"
			}
		}]
	}`

	policies, err := parser.ParseBytes([]byte(json))
	require.NoError(t, err)

	matcher := policies[0].Log.Matchers[0]
	assert.Equal(t, engine.FieldTypeLogAttribute, matcher.Field.Type)
	assert.Equal(t, "custom_attr", matcher.Field.Key)
}

func TestParserParseResourceAttribute(t *testing.T) {
	parser := NewParser()

	json := `{
		"policies": [{
			"id": "test",
			"name": "Test",
			"log": {
				"match": [{"resource_attribute": "service.name", "exact": "my-service"}],
				"keep": "none"
			}
		}]
	}`

	policies, err := parser.ParseBytes([]byte(json))
	require.NoError(t, err)

	matcher := policies[0].Log.Matchers[0]
	assert.Equal(t, engine.FieldTypeResourceAttribute, matcher.Field.Type)
	assert.Equal(t, "service.name", matcher.Field.Key)
}

func TestParserParseScopeAttribute(t *testing.T) {
	parser := NewParser()

	json := `{
		"policies": [{
			"id": "test",
			"name": "Test",
			"log": {
				"match": [{"scope_attribute": "scope.name", "regex": ".*"}],
				"keep": "all"
			}
		}]
	}`

	policies, err := parser.ParseBytes([]byte(json))
	require.NoError(t, err)

	matcher := policies[0].Log.Matchers[0]
	assert.Equal(t, engine.FieldTypeScopeAttribute, matcher.Field.Type)
	assert.Equal(t, "scope.name", matcher.Field.Key)
}

func TestParserParseMultipleFieldTypesError(t *testing.T) {
	parser := NewParser()

	json := `{
		"policies": [{
			"id": "test",
			"name": "Test",
			"log": {
				"match": [{"log_field": "body", "log_attribute": "extra", "regex": "test"}],
				"keep": "all"
			}
		}]
	}`

	_, err := parser.ParseBytes([]byte(json))
	require.Error(t, err)
}

func TestParserParseNoFieldTypeError(t *testing.T) {
	parser := NewParser()

	json := `{
		"policies": [{
			"id": "test",
			"name": "Test",
			"log": {
				"match": [{"regex": "test"}],
				"keep": "all"
			}
		}]
	}`

	_, err := parser.ParseBytes([]byte(json))
	require.Error(t, err)
}

func TestParserParseRegexMatcher(t *testing.T) {
	parser := NewParser()

	json := `{
		"policies": [{
			"id": "test",
			"name": "Test",
			"log": {
				"match": [{"log_field": "body", "regex": "error|warning"}],
				"keep": "none"
			}
		}]
	}`

	policies, err := parser.ParseBytes([]byte(json))
	require.NoError(t, err)

	matcher := policies[0].Log.Matchers[0]
	assert.Equal(t, "error|warning", matcher.Pattern)
}

func TestParserParseExactMatcher(t *testing.T) {
	parser := NewParser()

	json := `{
		"policies": [{
			"id": "test",
			"name": "Test",
			"log": {
				"match": [{"log_field": "severity_text", "exact": "ERROR"}],
				"keep": "none"
			}
		}]
	}`

	policies, err := parser.ParseBytes([]byte(json))
	require.NoError(t, err)

	matcher := policies[0].Log.Matchers[0]
	// Exact should be converted to anchored regex
	assert.Equal(t, "^ERROR$", matcher.Pattern)
}

func TestParserParseExactMatcherWithSpecialChars(t *testing.T) {
	parser := NewParser()

	json := `{
		"policies": [{
			"id": "test",
			"name": "Test",
			"log": {
				"match": [{"log_field": "body", "exact": "error (code: 123)"}],
				"keep": "none"
			}
		}]
	}`

	policies, err := parser.ParseBytes([]byte(json))
	require.NoError(t, err)

	matcher := policies[0].Log.Matchers[0]
	// Special regex chars should be escaped
	assert.Equal(t, `^error \(code: 123\)$`, matcher.Pattern)
}

func TestParserParseExistsMatcher(t *testing.T) {
	tests := []struct {
		name      string
		existsVal string
		expected  bool
	}{
		{"exists true", "true", true},
		{"exists false", "false", false},
	}

	parser := NewParser()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			json := `{
				"policies": [{
					"id": "test",
					"name": "Test",
					"log": {
						"match": [{"log_attribute": "trace_id", "exists": ` + tt.existsVal + `}],
						"keep": "all"
					}
				}]
			}`

			policies, err := parser.ParseBytes([]byte(json))
			require.NoError(t, err)

			matcher := policies[0].Log.Matchers[0]
			require.NotNil(t, matcher.Exists)
			assert.Equal(t, tt.expected, *matcher.Exists)
			assert.Empty(t, matcher.Pattern, "pattern should be empty for exists matcher")
		})
	}
}

func TestParserParseNoMatchConditionError(t *testing.T) {
	parser := NewParser()

	json := `{
		"policies": [{
			"id": "test",
			"name": "Test",
			"log": {
				"match": [{"log_field": "body"}],
				"keep": "all"
			}
		}]
	}`

	_, err := parser.ParseBytes([]byte(json))
	require.Error(t, err)
}

func TestParserParseInvalidRegex(t *testing.T) {
	parser := NewParser()

	json := `{
		"policies": [{
			"id": "test",
			"name": "Test",
			"log": {
				"match": [{"log_field": "body", "regex": "[invalid"}],
				"keep": "all"
			}
		}]
	}`

	_, err := parser.ParseBytes([]byte(json))
	require.Error(t, err)
}

func TestParserParseKeepStringAll(t *testing.T) {
	parser := NewParser()

	json := `{
		"policies": [{
			"id": "test",
			"name": "Test",
			"log": {
				"match": [{"log_field": "body", "regex": ".*"}],
				"keep": "all"
			}
		}]
	}`

	policies, err := parser.ParseBytes([]byte(json))
	require.NoError(t, err)
	assert.Equal(t, engine.KeepAll, policies[0].Log.Keep.Action)
}

func TestParserParseKeepStringNone(t *testing.T) {
	parser := NewParser()

	json := `{
		"policies": [{
			"id": "test",
			"name": "Test",
			"log": {
				"match": [{"log_field": "body", "regex": ".*"}],
				"keep": "none"
			}
		}]
	}`

	policies, err := parser.ParseBytes([]byte(json))
	require.NoError(t, err)
	assert.Equal(t, engine.KeepNone, policies[0].Log.Keep.Action)
}

func TestParserParseKeepStringEmpty(t *testing.T) {
	parser := NewParser()

	json := `{
		"policies": [{
			"id": "test",
			"name": "Test",
			"log": {
				"match": [{"log_field": "body", "regex": ".*"}],
				"keep": ""
			}
		}]
	}`

	policies, err := parser.ParseBytes([]byte(json))
	require.NoError(t, err)
	// Empty string should default to KeepAll
	assert.Equal(t, engine.KeepAll, policies[0].Log.Keep.Action)
}

func TestParserParseKeepStringUnknown(t *testing.T) {
	parser := NewParser()

	json := `{
		"policies": [{
			"id": "test",
			"name": "Test",
			"log": {
				"match": [{"log_field": "body", "regex": ".*"}],
				"keep": "unknown"
			}
		}]
	}`

	_, err := parser.ParseBytes([]byte(json))
	require.Error(t, err)
}

func TestParserParseKeepBoolTrue(t *testing.T) {
	parser := NewParser()

	json := `{
		"policies": [{
			"id": "test",
			"name": "Test",
			"log": {
				"match": [{"log_field": "body", "regex": ".*"}],
				"keep": true
			}
		}]
	}`

	policies, err := parser.ParseBytes([]byte(json))
	require.NoError(t, err)
	assert.Equal(t, engine.KeepAll, policies[0].Log.Keep.Action)
}

func TestParserParseKeepBoolFalse(t *testing.T) {
	parser := NewParser()

	json := `{
		"policies": [{
			"id": "test",
			"name": "Test",
			"log": {
				"match": [{"log_field": "body", "regex": ".*"}],
				"keep": false
			}
		}]
	}`

	policies, err := parser.ParseBytes([]byte(json))
	require.NoError(t, err)
	assert.Equal(t, engine.KeepNone, policies[0].Log.Keep.Action)
}

func TestParserParseKeepSample(t *testing.T) {
	parser := NewParser()

	json := `{
		"policies": [{
			"id": "test",
			"name": "Test",
			"log": {
				"match": [{"log_field": "body", "regex": ".*"}],
				"keep": {"percentage": 50}
			}
		}]
	}`

	policies, err := parser.ParseBytes([]byte(json))
	require.NoError(t, err)

	keep := policies[0].Log.Keep
	assert.Equal(t, engine.KeepSample, keep.Action)
	assert.Equal(t, float64(50), keep.Value)
}

func TestParserParseKeepSampleZeroPercent(t *testing.T) {
	parser := NewParser()

	json := `{
		"policies": [{
			"id": "test",
			"name": "Test",
			"log": {
				"match": [{"log_field": "body", "regex": ".*"}],
				"keep": {"percentage": 0}
			}
		}]
	}`

	policies, err := parser.ParseBytes([]byte(json))
	require.NoError(t, err)
	// 0% sample should be KeepNone
	assert.Equal(t, engine.KeepNone, policies[0].Log.Keep.Action)
}

func TestParserParseKeepSampleHundredPercent(t *testing.T) {
	parser := NewParser()

	json := `{
		"policies": [{
			"id": "test",
			"name": "Test",
			"log": {
				"match": [{"log_field": "body", "regex": ".*"}],
				"keep": {"percentage": 100}
			}
		}]
	}`

	policies, err := parser.ParseBytes([]byte(json))
	require.NoError(t, err)
	// 100% sample should be KeepAll
	assert.Equal(t, engine.KeepAll, policies[0].Log.Keep.Action)
}

func TestParserParseKeepSampleInvalidPercentage(t *testing.T) {
	tests := []struct {
		name       string
		percentage string
	}{
		{"negative", "-1"},
		{"over 100", "101"},
	}

	parser := NewParser()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			json := `{
				"policies": [{
					"id": "test",
					"name": "Test",
					"log": {
						"match": [{"log_field": "body", "regex": ".*"}],
						"keep": {"percentage": ` + tt.percentage + `}
					}
				}]
			}`

			_, err := parser.ParseBytes([]byte(json))
			require.Error(t, err)
		})
	}
}

func TestParserParseMissingID(t *testing.T) {
	parser := NewParser()

	json := `{
		"policies": [{
			"name": "Test",
			"log": {
				"match": [{"log_field": "body", "regex": ".*"}],
				"keep": "all"
			}
		}]
	}`

	_, err := parser.ParseBytes([]byte(json))
	require.Error(t, err)
}

func TestParserParseMissingName(t *testing.T) {
	parser := NewParser()

	json := `{
		"policies": [{
			"id": "test",
			"log": {
				"match": [{"log_field": "body", "regex": ".*"}],
				"keep": "all"
			}
		}]
	}`

	_, err := parser.ParseBytes([]byte(json))
	require.Error(t, err)
}

func TestParserParseNonLogPolicy(t *testing.T) {
	parser := NewParser()

	json := `{
		"policies": [{
			"id": "test",
			"name": "Test"
		}]
	}`

	policies, err := parser.ParseBytes([]byte(json))
	require.NoError(t, err)
	require.Len(t, policies, 1)
	assert.Nil(t, policies[0].Log)
}

func TestParserParseInvalidJSON(t *testing.T) {
	parser := NewParser()

	_, err := parser.ParseBytes([]byte(`{invalid json}`))
	require.Error(t, err)
}

func TestParserParseMultipleMatchers(t *testing.T) {
	parser := NewParser()

	json := `{
		"policies": [{
			"id": "test",
			"name": "Test",
			"log": {
				"match": [
					{"log_field": "body", "regex": "error"},
					{"log_field": "severity_text", "exact": "ERROR"},
					{"log_attribute": "source", "regex": "critical"}
				],
				"keep": "none"
			}
		}]
	}`

	policies, err := parser.ParseBytes([]byte(json))
	require.NoError(t, err)

	matchers := policies[0].Log.Matchers
	require.Len(t, matchers, 3)

	// Verify each matcher
	assert.Equal(t, engine.FieldTypeLogField, matchers[0].Field.Type)
	assert.Equal(t, engine.LogFieldBody, matchers[0].Field.Field)

	assert.Equal(t, engine.FieldTypeLogField, matchers[1].Field.Type)
	assert.Equal(t, engine.LogFieldSeverityText, matchers[1].Field.Field)

	assert.Equal(t, engine.FieldTypeLogAttribute, matchers[2].Field.Type)
	assert.Equal(t, "source", matchers[2].Field.Key)
}

func TestKeepValueUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name        string
		json        string
		expectStr   *string
		expectBool  *bool
		expectSamp  bool
		expectError bool
	}{
		{
			name:      "string all",
			json:      `"all"`,
			expectStr: strPtr("all"),
		},
		{
			name:      "string none",
			json:      `"none"`,
			expectStr: strPtr("none"),
		},
		{
			name:       "bool true",
			json:       `true`,
			expectBool: boolPtr(true),
		},
		{
			name:       "bool false",
			json:       `false`,
			expectBool: boolPtr(false),
		},
		{
			name:       "sample object",
			json:       `{"percentage": 50}`,
			expectSamp: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var kv KeepValue
			err := kv.UnmarshalJSON([]byte(tt.json))

			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)

			if tt.expectStr != nil {
				require.NotNil(t, kv.StringValue)
				assert.Equal(t, *tt.expectStr, *kv.StringValue)
			}
			if tt.expectBool != nil {
				require.NotNil(t, kv.BoolValue)
				assert.Equal(t, *tt.expectBool, *kv.BoolValue)
			}
			if tt.expectSamp {
				assert.NotNil(t, kv.SampleValue)
			}
		})
	}
}

func TestParseError(t *testing.T) {
	err := NewParseError("test_field", "test message")

	assert.Equal(t, "test_field", err.Field)
	assert.Equal(t, "test message", err.Message)
	assert.Equal(t, "parse error in test_field: test message", err.Error())
}

func TestParserParseNegatedMatcher(t *testing.T) {
	parser := NewParser()

	json := `{
		"policies": [{
			"id": "test",
			"name": "Test",
			"log": {
				"match": [{"log_field": "body", "regex": "debug", "negated": true}],
				"keep": "all"
			}
		}]
	}`

	policies, err := parser.ParseBytes([]byte(json))
	require.NoError(t, err)

	matcher := policies[0].Log.Matchers[0]
	assert.True(t, matcher.Negated)
}

func TestParserParseNonNegatedMatcher(t *testing.T) {
	parser := NewParser()

	json := `{
		"policies": [{
			"id": "test",
			"name": "Test",
			"log": {
				"match": [{"log_field": "body", "regex": "debug"}],
				"keep": "all"
			}
		}]
	}`

	policies, err := parser.ParseBytes([]byte(json))
	require.NoError(t, err)

	matcher := policies[0].Log.Matchers[0]
	assert.False(t, matcher.Negated, "Negated should be false by default")
}

func TestParserParseNegatedFalseExplicit(t *testing.T) {
	parser := NewParser()

	json := `{
		"policies": [{
			"id": "test",
			"name": "Test",
			"log": {
				"match": [{"log_field": "body", "regex": "debug", "negated": false}],
				"keep": "all"
			}
		}]
	}`

	policies, err := parser.ParseBytes([]byte(json))
	require.NoError(t, err)

	matcher := policies[0].Log.Matchers[0]
	assert.False(t, matcher.Negated)
}

func TestParserParseMixedNegation(t *testing.T) {
	parser := NewParser()

	json := `{
		"policies": [{
			"id": "test",
			"name": "Test",
			"log": {
				"match": [
					{"log_field": "body", "regex": "error"},
					{"log_field": "body", "regex": "debug", "negated": true}
				],
				"keep": "all"
			}
		}]
	}`

	policies, err := parser.ParseBytes([]byte(json))
	require.NoError(t, err)

	matchers := policies[0].Log.Matchers
	require.Len(t, matchers, 2)

	assert.False(t, matchers[0].Negated, "first matcher should not be negated")
	assert.True(t, matchers[1].Negated, "second matcher should be negated")
}

// Helper functions
func strPtr(s string) *string {
	return &s
}

func boolPtr(b bool) *bool {
	return &b
}
