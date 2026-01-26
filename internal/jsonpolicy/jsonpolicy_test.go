package jsonpolicy

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
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
	assert.Equal(t, "test-policy", p.GetId())
	assert.Equal(t, "Test Policy", p.GetName())
	require.NotNil(t, p.GetLog())
	assert.Len(t, p.GetLog().GetMatch(), 1)
	assert.Equal(t, "none", p.GetLog().GetKeep())
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
	assert.Equal(t, "reader-test", policies[0].GetId())
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

	assert.Equal(t, "policy-1", policies[0].GetId())
	assert.Equal(t, "policy-2", policies[1].GetId())
}

func TestParserParseAllLogFields(t *testing.T) {
	tests := []struct {
		name     string
		field    string
		expected policyv1.LogField
	}{
		{"body", "body", policyv1.LogField_LOG_FIELD_BODY},
		{"severity_text", "severity_text", policyv1.LogField_LOG_FIELD_SEVERITY_TEXT},
		{"trace_id", "trace_id", policyv1.LogField_LOG_FIELD_TRACE_ID},
		{"span_id", "span_id", policyv1.LogField_LOG_FIELD_SPAN_ID},
		{"event_name", "event_name", policyv1.LogField_LOG_FIELD_EVENT_NAME},
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

			matcher := policies[0].GetLog().GetMatch()[0]
			logField, ok := matcher.GetField().(*policyv1.LogMatcher_LogField)
			require.True(t, ok)
			assert.Equal(t, tt.expected, logField.LogField)
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

	matcher := policies[0].GetLog().GetMatch()[0]
	logAttr, ok := matcher.GetField().(*policyv1.LogMatcher_LogAttribute)
	require.True(t, ok)
	assert.Equal(t, "custom_attr", logAttr.LogAttribute)
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

	matcher := policies[0].GetLog().GetMatch()[0]
	resAttr, ok := matcher.GetField().(*policyv1.LogMatcher_ResourceAttribute)
	require.True(t, ok)
	assert.Equal(t, "service.name", resAttr.ResourceAttribute)
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

	matcher := policies[0].GetLog().GetMatch()[0]
	scopeAttr, ok := matcher.GetField().(*policyv1.LogMatcher_ScopeAttribute)
	require.True(t, ok)
	assert.Equal(t, "scope.name", scopeAttr.ScopeAttribute)
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

	matcher := policies[0].GetLog().GetMatch()[0]
	assert.Equal(t, "error|warning", matcher.GetRegex())
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

	matcher := policies[0].GetLog().GetMatch()[0]
	assert.Equal(t, "ERROR", matcher.GetExact())
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

			matcher := policies[0].GetLog().GetMatch()[0]
			_, ok := matcher.GetMatch().(*policyv1.LogMatcher_Exists)
			require.True(t, ok)
			assert.Equal(t, tt.expected, matcher.GetExists())
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

func TestParserParseKeepValues(t *testing.T) {
	tests := []struct {
		name     string
		keepJson string
		expected string
	}{
		{"string all", `"all"`, "all"},
		{"string none", `"none"`, "none"},
		{"string empty", `""`, "all"},
		{"bool true", `true`, "all"},
		{"bool false", `false`, "none"},
		{"sample 50%", `{"percentage": 50}`, "50%"},
		{"sample 0%", `{"percentage": 0}`, "0%"},
		{"sample 100%", `{"percentage": 100}`, "100%"},
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
						"keep": ` + tt.keepJson + `
					}
				}]
			}`

			policies, err := parser.ParseBytes([]byte(json))
			require.NoError(t, err)
			assert.Equal(t, tt.expected, policies[0].GetLog().GetKeep())
		})
	}
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
	assert.Nil(t, policies[0].GetLog())
}

func TestParserParseInvalidJSON(t *testing.T) {
	parser := NewParser()

	_, err := parser.ParseBytes([]byte(`{invalid json}`))
	require.Error(t, err)
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

	matcher := policies[0].GetLog().GetMatch()[0]
	assert.True(t, matcher.GetNegate())
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

	matcher := policies[0].GetLog().GetMatch()[0]
	assert.False(t, matcher.GetNegate(), "Negated should be false by default")
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

// Helper functions
func strPtr(s string) *string {
	return &s
}

func boolPtr(b bool) *bool {
	return &b
}
