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
	assert.Equal(t, []string{"custom_attr"}, logAttr.LogAttribute.GetPath())
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
	assert.Equal(t, []string{"service.name"}, resAttr.ResourceAttribute.GetPath())
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
	assert.Equal(t, []string{"scope.name"}, scopeAttr.ScopeAttribute.GetPath())
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

func TestParserParseTransformRemove(t *testing.T) {
	parser := NewParser()

	j := `{
		"policies": [{
			"id": "test",
			"name": "Test",
			"log": {
				"match": [{"log_field": "body", "regex": ".*"}],
				"keep": "all",
				"transform": {
					"remove": [
						{"log_field": "trace_id"},
						{"log_attribute": "secret"},
						{"resource_attribute": {"path": ["host", "name"]}},
						{"scope_attribute": "internal"}
					]
				}
			}
		}]
	}`

	policies, err := parser.ParseBytes([]byte(j))
	require.NoError(t, err)

	transform := policies[0].GetLog().GetTransform()
	require.NotNil(t, transform)
	require.Len(t, transform.GetRemove(), 4)

	// log_field
	assert.Equal(t, policyv1.LogField_LOG_FIELD_TRACE_ID, transform.GetRemove()[0].GetLogField())
	// log_attribute
	assert.Equal(t, []string{"secret"}, transform.GetRemove()[1].GetLogAttribute().GetPath())
	// resource_attribute with path
	assert.Equal(t, []string{"host", "name"}, transform.GetRemove()[2].GetResourceAttribute().GetPath())
	// scope_attribute
	assert.Equal(t, []string{"internal"}, transform.GetRemove()[3].GetScopeAttribute().GetPath())
}

func TestParserParseTransformRedact(t *testing.T) {
	parser := NewParser()

	j := `{
		"policies": [{
			"id": "test",
			"name": "Test",
			"log": {
				"match": [{"log_field": "body", "regex": ".*"}],
				"keep": "all",
				"transform": {
					"redact": [
						{"log_attribute": "api_key", "replacement": "[REDACTED]"},
						{"log_field": "body", "replacement": "***"}
					]
				}
			}
		}]
	}`

	policies, err := parser.ParseBytes([]byte(j))
	require.NoError(t, err)

	transform := policies[0].GetLog().GetTransform()
	require.Len(t, transform.GetRedact(), 2)

	assert.Equal(t, []string{"api_key"}, transform.GetRedact()[0].GetLogAttribute().GetPath())
	assert.Equal(t, "[REDACTED]", transform.GetRedact()[0].GetReplacement())

	assert.Equal(t, policyv1.LogField_LOG_FIELD_BODY, transform.GetRedact()[1].GetLogField())
	assert.Equal(t, "***", transform.GetRedact()[1].GetReplacement())
}

func TestParserParseTransformRename(t *testing.T) {
	parser := NewParser()

	j := `{
		"policies": [{
			"id": "test",
			"name": "Test",
			"log": {
				"match": [{"log_field": "body", "regex": ".*"}],
				"keep": "all",
				"transform": {
					"rename": [
						{"log_attribute": "old_name", "to": "new_name", "upsert": true},
						{"resource_attribute": "host", "to": "hostname"}
					]
				}
			}
		}]
	}`

	policies, err := parser.ParseBytes([]byte(j))
	require.NoError(t, err)

	transform := policies[0].GetLog().GetTransform()
	require.Len(t, transform.GetRename(), 2)

	assert.Equal(t, []string{"old_name"}, transform.GetRename()[0].GetFromLogAttribute().GetPath())
	assert.Equal(t, "new_name", transform.GetRename()[0].GetTo())
	assert.True(t, transform.GetRename()[0].GetUpsert())

	assert.Equal(t, []string{"host"}, transform.GetRename()[1].GetFromResourceAttribute().GetPath())
	assert.Equal(t, "hostname", transform.GetRename()[1].GetTo())
	assert.False(t, transform.GetRename()[1].GetUpsert())
}

func TestParserParseTransformAdd(t *testing.T) {
	parser := NewParser()

	j := `{
		"policies": [{
			"id": "test",
			"name": "Test",
			"log": {
				"match": [{"log_field": "body", "regex": ".*"}],
				"keep": "all",
				"transform": {
					"add": [
						{"log_attribute": "processed", "value": "true"},
						{"log_field": "event_name", "value": "transformed", "upsert": true}
					]
				}
			}
		}]
	}`

	policies, err := parser.ParseBytes([]byte(j))
	require.NoError(t, err)

	transform := policies[0].GetLog().GetTransform()
	require.Len(t, transform.GetAdd(), 2)

	assert.Equal(t, []string{"processed"}, transform.GetAdd()[0].GetLogAttribute().GetPath())
	assert.Equal(t, "true", transform.GetAdd()[0].GetValue())
	assert.False(t, transform.GetAdd()[0].GetUpsert())

	assert.Equal(t, policyv1.LogField_LOG_FIELD_EVENT_NAME, transform.GetAdd()[1].GetLogField())
	assert.Equal(t, "transformed", transform.GetAdd()[1].GetValue())
	assert.True(t, transform.GetAdd()[1].GetUpsert())
}

func TestParserParseTransformMixed(t *testing.T) {
	parser := NewParser()

	j := `{
		"policies": [{
			"id": "test",
			"name": "Test",
			"log": {
				"match": [{"log_field": "body", "regex": ".*"}],
				"keep": "all",
				"transform": {
					"remove": [{"log_attribute": "secret"}],
					"redact": [{"log_attribute": "api_key", "replacement": "[REDACTED]"}],
					"rename": [{"log_attribute": "old", "to": "new", "upsert": true}],
					"add": [{"log_attribute": "processed", "value": "true"}]
				}
			}
		}]
	}`

	policies, err := parser.ParseBytes([]byte(j))
	require.NoError(t, err)

	transform := policies[0].GetLog().GetTransform()
	require.NotNil(t, transform)
	assert.Len(t, transform.GetRemove(), 1)
	assert.Len(t, transform.GetRedact(), 1)
	assert.Len(t, transform.GetRename(), 1)
	assert.Len(t, transform.GetAdd(), 1)
}

func TestParserParseTransformNoFieldError(t *testing.T) {
	parser := NewParser()

	j := `{
		"policies": [{
			"id": "test",
			"name": "Test",
			"log": {
				"match": [{"log_field": "body", "regex": ".*"}],
				"keep": "all",
				"transform": {
					"remove": [{}]
				}
			}
		}]
	}`

	_, err := parser.ParseBytes([]byte(j))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must specify a field type")
}

func TestParserParseTransformMultipleFieldsError(t *testing.T) {
	parser := NewParser()

	j := `{
		"policies": [{
			"id": "test",
			"name": "Test",
			"log": {
				"match": [{"log_field": "body", "regex": ".*"}],
				"keep": "all",
				"transform": {
					"redact": [{"log_field": "body", "log_attribute": "extra", "replacement": "x"}]
				}
			}
		}]
	}`

	_, err := parser.ParseBytes([]byte(j))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must specify only one field type")
}

func TestParserParseTransformUnknownFieldError(t *testing.T) {
	parser := NewParser()

	j := `{
		"policies": [{
			"id": "test",
			"name": "Test",
			"log": {
				"match": [{"log_field": "body", "regex": ".*"}],
				"keep": "all",
				"transform": {
					"remove": [{"log_field": "nonexistent"}]
				}
			}
		}]
	}`

	_, err := parser.ParseBytes([]byte(j))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown field")
}

func TestParserParseTransformRenameMissingToError(t *testing.T) {
	parser := NewParser()

	j := `{
		"policies": [{
			"id": "test",
			"name": "Test",
			"log": {
				"match": [{"log_field": "body", "regex": ".*"}],
				"keep": "all",
				"transform": {
					"rename": [{"log_attribute": "old"}]
				}
			}
		}]
	}`

	_, err := parser.ParseBytes([]byte(j))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rename.to")
}

func TestParserParseNoTransform(t *testing.T) {
	parser := NewParser()

	j := `{
		"policies": [{
			"id": "test",
			"name": "Test",
			"log": {
				"match": [{"log_field": "body", "regex": ".*"}],
				"keep": "all"
			}
		}]
	}`

	policies, err := parser.ParseBytes([]byte(j))
	require.NoError(t, err)
	assert.Nil(t, policies[0].GetLog().GetTransform())
}

// Helper functions
func strPtr(s string) *string {
	return &s
}

func boolPtr(b bool) *bool {
	return &b
}
