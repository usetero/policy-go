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
				"match": [{"log_field": "body", "regex": "debug", "negate": true}],
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
						{"from_log_attribute": "old_name", "to": "new_name", "upsert": true},
						{"from_resource_attribute": "host", "to": "hostname"}
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
					"rename": [{"from_log_attribute": "old", "to": "new", "upsert": true}],
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
					"rename": [{"from_log_attribute": "old"}]
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

// ============================================================================
// METRIC TESTS
// ============================================================================

func TestParserParseMetricPolicy(t *testing.T) {
	parser := NewParser()

	j := `{
		"policies": [{
			"id": "drop-metrics",
			"name": "Drop Metrics",
			"metric": {
				"match": [{"metric_field": "name", "regex": "http\\..*"}],
				"keep": false
			}
		}]
	}`

	policies, err := parser.ParseBytes([]byte(j))
	require.NoError(t, err)
	require.Len(t, policies, 1)

	p := policies[0]
	assert.Equal(t, "drop-metrics", p.GetId())
	require.NotNil(t, p.GetMetric())
	assert.Nil(t, p.GetLog())
	assert.Len(t, p.GetMetric().GetMatch(), 1)
	assert.False(t, p.GetMetric().GetKeep())

	matcher := p.GetMetric().GetMatch()[0]
	mf, ok := matcher.GetField().(*policyv1.MetricMatcher_MetricField)
	require.True(t, ok)
	assert.Equal(t, policyv1.MetricField_METRIC_FIELD_NAME, mf.MetricField)
	assert.Equal(t, "http\\..*", matcher.GetRegex())
}

func TestParserParseMetricKeepTrue(t *testing.T) {
	parser := NewParser()

	j := `{
		"policies": [{
			"id": "keep-metrics",
			"name": "Keep Metrics",
			"metric": {
				"match": [{"metric_field": "name", "exact": "important"}],
				"keep": true
			}
		}]
	}`

	policies, err := parser.ParseBytes([]byte(j))
	require.NoError(t, err)
	assert.True(t, policies[0].GetMetric().GetKeep())
}

func TestParserParseMetricAllFields(t *testing.T) {
	tests := []struct {
		name     string
		field    string
		expected policyv1.MetricField
	}{
		{"name", "name", policyv1.MetricField_METRIC_FIELD_NAME},
		{"description", "description", policyv1.MetricField_METRIC_FIELD_DESCRIPTION},
		{"unit", "unit", policyv1.MetricField_METRIC_FIELD_UNIT},
		{"scope_name", "scope_name", policyv1.MetricField_METRIC_FIELD_SCOPE_NAME},
		{"scope_version", "scope_version", policyv1.MetricField_METRIC_FIELD_SCOPE_VERSION},
	}

	parser := NewParser()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := `{"policies": [{"id": "test", "name": "Test", "metric": {"match": [{"metric_field": "` + tt.field + `", "regex": ".*"}], "keep": false}}]}`
			policies, err := parser.ParseBytes([]byte(j))
			require.NoError(t, err)

			matcher := policies[0].GetMetric().GetMatch()[0]
			mf, ok := matcher.GetField().(*policyv1.MetricMatcher_MetricField)
			require.True(t, ok)
			assert.Equal(t, tt.expected, mf.MetricField)
		})
	}
}

func TestParserParseMetricDatapointAttribute(t *testing.T) {
	parser := NewParser()

	j := `{
		"policies": [{
			"id": "test",
			"name": "Test",
			"metric": {
				"match": [{"datapoint_attribute": "host.name", "exact": "prod-1"}],
				"keep": false
			}
		}]
	}`

	policies, err := parser.ParseBytes([]byte(j))
	require.NoError(t, err)

	matcher := policies[0].GetMetric().GetMatch()[0]
	attr, ok := matcher.GetField().(*policyv1.MetricMatcher_DatapointAttribute)
	require.True(t, ok)
	assert.Equal(t, []string{"host.name"}, attr.DatapointAttribute.GetPath())
}

func TestParserParseMetricType(t *testing.T) {
	tests := []struct {
		name     string
		typeName string
		expected policyv1.MetricType
	}{
		{"gauge", "gauge", policyv1.MetricType_METRIC_TYPE_GAUGE},
		{"sum", "sum", policyv1.MetricType_METRIC_TYPE_SUM},
		{"histogram", "histogram", policyv1.MetricType_METRIC_TYPE_HISTOGRAM},
		{"exponential_histogram", "exponential_histogram", policyv1.MetricType_METRIC_TYPE_EXPONENTIAL_HISTOGRAM},
		{"summary", "summary", policyv1.MetricType_METRIC_TYPE_SUMMARY},
	}

	parser := NewParser()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := `{"policies": [{"id": "test", "name": "Test", "metric": {"match": [{"metric_type": "` + tt.typeName + `"}], "keep": false}}]}`
			policies, err := parser.ParseBytes([]byte(j))
			require.NoError(t, err)

			matcher := policies[0].GetMetric().GetMatch()[0]
			mt, ok := matcher.GetField().(*policyv1.MetricMatcher_MetricType)
			require.True(t, ok)
			assert.Equal(t, tt.expected, mt.MetricType)
		})
	}
}

func TestParserParseMetricAggregationTemporality(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected policyv1.AggregationTemporality
	}{
		{"delta", "delta", policyv1.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA},
		{"cumulative", "cumulative", policyv1.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE},
	}

	parser := NewParser()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := `{"policies": [{"id": "test", "name": "Test", "metric": {"match": [{"aggregation_temporality": "` + tt.value + `"}], "keep": false}}]}`
			policies, err := parser.ParseBytes([]byte(j))
			require.NoError(t, err)

			matcher := policies[0].GetMetric().GetMatch()[0]
			at, ok := matcher.GetField().(*policyv1.MetricMatcher_AggregationTemporality)
			require.True(t, ok)
			assert.Equal(t, tt.expected, at.AggregationTemporality)
		})
	}
}

func TestParserParseMetricUnknownFieldError(t *testing.T) {
	parser := NewParser()

	j := `{"policies": [{"id": "test", "name": "Test", "metric": {"match": [{"metric_field": "unknown", "regex": ".*"}], "keep": false}}]}`
	_, err := parser.ParseBytes([]byte(j))
	require.Error(t, err)
}

// ============================================================================
// TRACE TESTS
// ============================================================================

func TestParserParseTracePolicy(t *testing.T) {
	parser := NewParser()

	j := `{
		"policies": [{
			"id": "trace-policy",
			"name": "Trace Policy",
			"trace": {
				"match": [{"trace_field": "name", "regex": "/api/.*"}],
				"keep": {"percentage": 50}
			}
		}]
	}`

	policies, err := parser.ParseBytes([]byte(j))
	require.NoError(t, err)
	require.Len(t, policies, 1)

	p := policies[0]
	assert.Equal(t, "trace-policy", p.GetId())
	require.NotNil(t, p.GetTrace())
	assert.Nil(t, p.GetLog())
	assert.Nil(t, p.GetMetric())
	assert.Len(t, p.GetTrace().GetMatch(), 1)
	assert.Equal(t, float32(50), p.GetTrace().GetKeep().GetPercentage())
}

func TestParserParseTraceNoKeep(t *testing.T) {
	parser := NewParser()

	j := `{
		"policies": [{
			"id": "test",
			"name": "Test",
			"trace": {
				"match": [{"trace_field": "name", "regex": ".*"}]
			}
		}]
	}`

	policies, err := parser.ParseBytes([]byte(j))
	require.NoError(t, err)
	assert.Nil(t, policies[0].GetTrace().GetKeep())
}

func TestParserParseTraceAllFields(t *testing.T) {
	tests := []struct {
		name     string
		field    string
		expected policyv1.TraceField
	}{
		{"name", "name", policyv1.TraceField_TRACE_FIELD_NAME},
		{"trace_id", "trace_id", policyv1.TraceField_TRACE_FIELD_TRACE_ID},
		{"span_id", "span_id", policyv1.TraceField_TRACE_FIELD_SPAN_ID},
		{"parent_span_id", "parent_span_id", policyv1.TraceField_TRACE_FIELD_PARENT_SPAN_ID},
		{"trace_state", "trace_state", policyv1.TraceField_TRACE_FIELD_TRACE_STATE},
		{"scope_name", "scope_name", policyv1.TraceField_TRACE_FIELD_SCOPE_NAME},
		{"scope_version", "scope_version", policyv1.TraceField_TRACE_FIELD_SCOPE_VERSION},
	}

	parser := NewParser()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := `{"policies": [{"id": "test", "name": "Test", "trace": {"match": [{"trace_field": "` + tt.field + `", "regex": ".*"}]}}]}`
			policies, err := parser.ParseBytes([]byte(j))
			require.NoError(t, err)

			matcher := policies[0].GetTrace().GetMatch()[0]
			tf, ok := matcher.GetField().(*policyv1.TraceMatcher_TraceField)
			require.True(t, ok)
			assert.Equal(t, tt.expected, tf.TraceField)
		})
	}
}

func TestParserParseTraceSpanKind(t *testing.T) {
	tests := []struct {
		name     string
		kind     string
		expected policyv1.SpanKind
	}{
		{"internal", "internal", policyv1.SpanKind_SPAN_KIND_INTERNAL},
		{"server", "server", policyv1.SpanKind_SPAN_KIND_SERVER},
		{"client", "client", policyv1.SpanKind_SPAN_KIND_CLIENT},
		{"producer", "producer", policyv1.SpanKind_SPAN_KIND_PRODUCER},
		{"consumer", "consumer", policyv1.SpanKind_SPAN_KIND_CONSUMER},
		{"proto form", "SPAN_KIND_INTERNAL", policyv1.SpanKind_SPAN_KIND_INTERNAL},
	}

	parser := NewParser()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := `{"policies": [{"id": "test", "name": "Test", "trace": {"match": [{"span_kind": "` + tt.kind + `"}]}}]}`
			policies, err := parser.ParseBytes([]byte(j))
			require.NoError(t, err)

			matcher := policies[0].GetTrace().GetMatch()[0]
			sk, ok := matcher.GetField().(*policyv1.TraceMatcher_SpanKind)
			require.True(t, ok)
			assert.Equal(t, tt.expected, sk.SpanKind)
		})
	}
}

func TestParserParseTraceSpanStatus(t *testing.T) {
	tests := []struct {
		name     string
		status   string
		expected policyv1.SpanStatusCode
	}{
		{"ok", "ok", policyv1.SpanStatusCode_SPAN_STATUS_CODE_OK},
		{"error", "error", policyv1.SpanStatusCode_SPAN_STATUS_CODE_ERROR},
		{"proto form", "SPAN_STATUS_CODE_ERROR", policyv1.SpanStatusCode_SPAN_STATUS_CODE_ERROR},
	}

	parser := NewParser()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := `{"policies": [{"id": "test", "name": "Test", "trace": {"match": [{"span_status": "` + tt.status + `"}]}}]}`
			policies, err := parser.ParseBytes([]byte(j))
			require.NoError(t, err)

			matcher := policies[0].GetTrace().GetMatch()[0]
			ss, ok := matcher.GetField().(*policyv1.TraceMatcher_SpanStatus)
			require.True(t, ok)
			assert.Equal(t, tt.expected, ss.SpanStatus)
		})
	}
}

func TestParserParseTraceSpanAttribute(t *testing.T) {
	parser := NewParser()

	j := `{
		"policies": [{
			"id": "test",
			"name": "Test",
			"trace": {
				"match": [{"span_attribute": "http.method", "exact": "GET"}]
			}
		}]
	}`

	policies, err := parser.ParseBytes([]byte(j))
	require.NoError(t, err)

	matcher := policies[0].GetTrace().GetMatch()[0]
	attr, ok := matcher.GetField().(*policyv1.TraceMatcher_SpanAttribute)
	require.True(t, ok)
	assert.Equal(t, []string{"http.method"}, attr.SpanAttribute.GetPath())
	assert.Equal(t, "GET", matcher.GetExact())
}

func TestParserParseTraceUnknownFieldError(t *testing.T) {
	parser := NewParser()

	j := `{"policies": [{"id": "test", "name": "Test", "trace": {"match": [{"trace_field": "unknown", "regex": ".*"}]}}]}`
	_, err := parser.ParseBytes([]byte(j))
	require.Error(t, err)
}

func TestParserParseTraceUnknownSpanKindError(t *testing.T) {
	parser := NewParser()

	j := `{"policies": [{"id": "test", "name": "Test", "trace": {"match": [{"span_kind": "unknown"}]}}]}`
	_, err := parser.ParseBytes([]byte(j))
	require.Error(t, err)
}

func TestParserParseTraceUnknownSpanStatusError(t *testing.T) {
	parser := NewParser()

	j := `{"policies": [{"id": "test", "name": "Test", "trace": {"match": [{"span_status": "unknown"}]}}]}`
	_, err := parser.ParseBytes([]byte(j))
	require.Error(t, err)
}

func TestParserParseMixedPolicies(t *testing.T) {
	parser := NewParser()

	j := `{
		"policies": [
			{
				"id": "log-policy",
				"name": "Log Policy",
				"log": {
					"match": [{"log_field": "body", "regex": "error"}],
					"keep": "none"
				}
			},
			{
				"id": "metric-policy",
				"name": "Metric Policy",
				"metric": {
					"match": [{"metric_field": "name", "regex": "http\\..*"}],
					"keep": false
				}
			},
			{
				"id": "trace-policy",
				"name": "Trace Policy",
				"trace": {
					"match": [{"span_kind": "internal"}],
					"keep": {"percentage": 100}
				}
			}
		]
	}`

	policies, err := parser.ParseBytes([]byte(j))
	require.NoError(t, err)
	require.Len(t, policies, 3)

	assert.NotNil(t, policies[0].GetLog())
	assert.NotNil(t, policies[1].GetMetric())
	assert.NotNil(t, policies[2].GetTrace())
}

// ============================================================================
// ENUM-TYPE MATCHERS SET EXISTS:TRUE
// ============================================================================

func TestParserParseEnumMatcherSetsExistsTrue(t *testing.T) {
	tests := []struct {
		name  string
		json  string
		check func(t *testing.T, p *policyv1.Policy)
	}{
		{
			name: "metric_type",
			json: `{"policies": [{"id": "test", "name": "Test", "metric": {"match": [{"metric_type": "gauge"}], "keep": false}}]}`,
			check: func(t *testing.T, p *policyv1.Policy) {
				matcher := p.GetMetric().GetMatch()[0]
				_, ok := matcher.GetMatch().(*policyv1.MetricMatcher_Exists)
				require.True(t, ok, "metric_type matcher should have Exists match type")
				assert.True(t, matcher.GetExists())
			},
		},
		{
			name: "aggregation_temporality",
			json: `{"policies": [{"id": "test", "name": "Test", "metric": {"match": [{"aggregation_temporality": "delta"}], "keep": false}}]}`,
			check: func(t *testing.T, p *policyv1.Policy) {
				matcher := p.GetMetric().GetMatch()[0]
				_, ok := matcher.GetMatch().(*policyv1.MetricMatcher_Exists)
				require.True(t, ok, "aggregation_temporality matcher should have Exists match type")
				assert.True(t, matcher.GetExists())
			},
		},
		{
			name: "span_kind",
			json: `{"policies": [{"id": "test", "name": "Test", "trace": {"match": [{"span_kind": "server"}]}}]}`,
			check: func(t *testing.T, p *policyv1.Policy) {
				matcher := p.GetTrace().GetMatch()[0]
				_, ok := matcher.GetMatch().(*policyv1.TraceMatcher_Exists)
				require.True(t, ok, "span_kind matcher should have Exists match type")
				assert.True(t, matcher.GetExists())
			},
		},
		{
			name: "span_status",
			json: `{"policies": [{"id": "test", "name": "Test", "trace": {"match": [{"span_status": "error"}]}}]}`,
			check: func(t *testing.T, p *policyv1.Policy) {
				matcher := p.GetTrace().GetMatch()[0]
				_, ok := matcher.GetMatch().(*policyv1.TraceMatcher_Exists)
				require.True(t, ok, "span_status matcher should have Exists match type")
				assert.True(t, matcher.GetExists())
			},
		},
	}

	parser := NewParser()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policies, err := parser.ParseBytes([]byte(tt.json))
			require.NoError(t, err)
			tt.check(t, policies[0])
		})
	}
}

// ============================================================================
// LOG ADDITIONAL MATCH TYPES AND FLAGS
// ============================================================================

func TestParserParseLogMatchTypes(t *testing.T) {
	tests := []struct {
		name      string
		matchJSON string
		check     func(t *testing.T, m *policyv1.LogMatcher)
	}{
		{"starts_with", `"starts_with": "ERROR:"`, func(t *testing.T, m *policyv1.LogMatcher) { assert.Equal(t, "ERROR:", m.GetStartsWith()) }},
		{"ends_with", `"ends_with": ".error"`, func(t *testing.T, m *policyv1.LogMatcher) { assert.Equal(t, ".error", m.GetEndsWith()) }},
		{"contains", `"contains": "fatal"`, func(t *testing.T, m *policyv1.LogMatcher) { assert.Equal(t, "fatal", m.GetContains()) }},
		{"case_insensitive", `"regex": "error", "case_insensitive": true`, func(t *testing.T, m *policyv1.LogMatcher) { assert.True(t, m.GetCaseInsensitive()) }},
	}

	parser := NewParser()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := `{"policies": [{"id": "test", "name": "Test", "log": {"match": [{"log_field": "body", ` + tt.matchJSON + `}], "keep": "none"}}]}`
			policies, err := parser.ParseBytes([]byte(j))
			require.NoError(t, err)

			tt.check(t, policies[0].GetLog().GetMatch()[0])
		})
	}
}

func TestParserParseLogFieldSchemaURLs(t *testing.T) {
	tests := []struct {
		name     string
		field    string
		expected policyv1.LogField
	}{
		{"resource_schema_url", "resource_schema_url", policyv1.LogField_LOG_FIELD_RESOURCE_SCHEMA_URL},
		{"scope_schema_url", "scope_schema_url", policyv1.LogField_LOG_FIELD_SCOPE_SCHEMA_URL},
	}

	parser := NewParser()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := `{"policies": [{"id": "test", "name": "Test", "log": {"match": [{"log_field": "` + tt.field + `", "regex": ".*"}], "keep": "all"}}]}`
			policies, err := parser.ParseBytes([]byte(j))
			require.NoError(t, err)

			matcher := policies[0].GetLog().GetMatch()[0]
			lf, ok := matcher.GetField().(*policyv1.LogMatcher_LogField)
			require.True(t, ok)
			assert.Equal(t, tt.expected, lf.LogField)
		})
	}
}

// ============================================================================
// LOG SAMPLE KEY
// ============================================================================

func TestParserParseSampleKey(t *testing.T) {
	tests := []struct {
		name       string
		fieldJSON  string
		checkField func(t *testing.T, sk *policyv1.LogSampleKey)
	}{
		{
			name:      "log_field",
			fieldJSON: `"log_field": "body"`,
			checkField: func(t *testing.T, sk *policyv1.LogSampleKey) {
				lf, ok := sk.GetField().(*policyv1.LogSampleKey_LogField)
				require.True(t, ok)
				assert.Equal(t, policyv1.LogField_LOG_FIELD_BODY, lf.LogField)
			},
		},
		{
			name:      "log_attribute",
			fieldJSON: `"log_attribute": "request_id"`,
			checkField: func(t *testing.T, sk *policyv1.LogSampleKey) {
				la, ok := sk.GetField().(*policyv1.LogSampleKey_LogAttribute)
				require.True(t, ok)
				assert.Equal(t, []string{"request_id"}, la.LogAttribute.GetPath())
			},
		},
		{
			name:      "resource_attribute",
			fieldJSON: `"resource_attribute": "service.name"`,
			checkField: func(t *testing.T, sk *policyv1.LogSampleKey) {
				ra, ok := sk.GetField().(*policyv1.LogSampleKey_ResourceAttribute)
				require.True(t, ok)
				assert.Equal(t, []string{"service.name"}, ra.ResourceAttribute.GetPath())
			},
		},
		{
			name:      "scope_attribute",
			fieldJSON: `"scope_attribute": "scope.name"`,
			checkField: func(t *testing.T, sk *policyv1.LogSampleKey) {
				sa, ok := sk.GetField().(*policyv1.LogSampleKey_ScopeAttribute)
				require.True(t, ok)
				assert.Equal(t, []string{"scope.name"}, sa.ScopeAttribute.GetPath())
			},
		},
	}

	parser := NewParser()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := `{"policies": [{"id": "test", "name": "Test", "log": {"match": [{"log_field": "body", "regex": ".*"}], "keep": "50%", "sample_key": {` + tt.fieldJSON + `}}}]}`
			policies, err := parser.ParseBytes([]byte(j))
			require.NoError(t, err)

			sk := policies[0].GetLog().GetSampleKey()
			require.NotNil(t, sk)
			tt.checkField(t, sk)
		})
	}
}

func TestParserParseSampleKeyErrors(t *testing.T) {
	tests := []struct {
		name        string
		sampleJSON  string
		errContains string
	}{
		{"no field", `{}`, "must specify a field type"},
		{"multiple fields", `{"log_field": "body", "log_attribute": "extra"}`, "must specify only one field type"},
		{"unknown log_field", `{"log_field": "nonexistent"}`, "unknown field"},
	}

	parser := NewParser()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := `{"policies": [{"id": "test", "name": "Test", "log": {"match": [{"log_field": "body", "regex": ".*"}], "keep": "all", "sample_key": ` + tt.sampleJSON + `}}]}`
			_, err := parser.ParseBytes([]byte(j))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errContains)
		})
	}
}

// ============================================================================
// METRIC ADDITIONAL COVERAGE
// ============================================================================

func TestParserParseMetricAllFieldsExtended(t *testing.T) {
	tests := []struct {
		name     string
		field    string
		expected policyv1.MetricField
	}{
		{"resource_schema_url", "resource_schema_url", policyv1.MetricField_METRIC_FIELD_RESOURCE_SCHEMA_URL},
		{"scope_schema_url", "scope_schema_url", policyv1.MetricField_METRIC_FIELD_SCOPE_SCHEMA_URL},
	}

	parser := NewParser()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := `{"policies": [{"id": "test", "name": "Test", "metric": {"match": [{"metric_field": "` + tt.field + `", "regex": ".*"}], "keep": false}}]}`
			policies, err := parser.ParseBytes([]byte(j))
			require.NoError(t, err)

			matcher := policies[0].GetMetric().GetMatch()[0]
			mf, ok := matcher.GetField().(*policyv1.MetricMatcher_MetricField)
			require.True(t, ok)
			assert.Equal(t, tt.expected, mf.MetricField)
		})
	}
}

func TestParserParseMetricMatchTypes(t *testing.T) {
	tests := []struct {
		name      string
		matchJSON string
		check     func(t *testing.T, m *policyv1.MetricMatcher)
	}{
		{"starts_with", `"starts_with": "http."`, func(t *testing.T, m *policyv1.MetricMatcher) { assert.Equal(t, "http.", m.GetStartsWith()) }},
		{"ends_with", `"ends_with": ".total"`, func(t *testing.T, m *policyv1.MetricMatcher) { assert.Equal(t, ".total", m.GetEndsWith()) }},
		{"contains", `"contains": "request"`, func(t *testing.T, m *policyv1.MetricMatcher) { assert.Equal(t, "request", m.GetContains()) }},
		{"exists true", `"exists": true`, func(t *testing.T, m *policyv1.MetricMatcher) { assert.True(t, m.GetExists()) }},
		{"exists false", `"exists": false`, func(t *testing.T, m *policyv1.MetricMatcher) {
			_, ok := m.GetMatch().(*policyv1.MetricMatcher_Exists)
			require.True(t, ok)
			assert.False(t, m.GetExists())
		}},
	}

	parser := NewParser()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := `{"policies": [{"id": "test", "name": "Test", "metric": {"match": [{"metric_field": "name", ` + tt.matchJSON + `}], "keep": false}}]}`
			policies, err := parser.ParseBytes([]byte(j))
			require.NoError(t, err)

			tt.check(t, policies[0].GetMetric().GetMatch()[0])
		})
	}
}

func TestParserParseMetricAttributeSelectors(t *testing.T) {
	tests := []struct {
		name      string
		fieldJSON string
		check     func(t *testing.T, m *policyv1.MetricMatcher)
	}{
		{
			name:      "resource_attribute",
			fieldJSON: `"resource_attribute": "service.name", "exact": "my-svc"`,
			check: func(t *testing.T, m *policyv1.MetricMatcher) {
				attr, ok := m.GetField().(*policyv1.MetricMatcher_ResourceAttribute)
				require.True(t, ok)
				assert.Equal(t, []string{"service.name"}, attr.ResourceAttribute.GetPath())
			},
		},
		{
			name:      "scope_attribute",
			fieldJSON: `"scope_attribute": "scope.name", "exact": "my-scope"`,
			check: func(t *testing.T, m *policyv1.MetricMatcher) {
				attr, ok := m.GetField().(*policyv1.MetricMatcher_ScopeAttribute)
				require.True(t, ok)
				assert.Equal(t, []string{"scope.name"}, attr.ScopeAttribute.GetPath())
			},
		},
	}

	parser := NewParser()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := `{"policies": [{"id": "test", "name": "Test", "metric": {"match": [{` + tt.fieldJSON + `}], "keep": false}}]}`
			policies, err := parser.ParseBytes([]byte(j))
			require.NoError(t, err)

			tt.check(t, policies[0].GetMetric().GetMatch()[0])
		})
	}
}

func TestParserParseMetricFlags(t *testing.T) {
	parser := NewParser()

	j := `{"policies": [{"id": "test", "name": "Test", "metric": {"match": [{"metric_field": "name", "regex": "debug", "negate": true, "case_insensitive": true}], "keep": false}}]}`
	policies, err := parser.ParseBytes([]byte(j))
	require.NoError(t, err)

	matcher := policies[0].GetMetric().GetMatch()[0]
	assert.True(t, matcher.GetNegate())
	assert.True(t, matcher.GetCaseInsensitive())
}

func TestParserParseMetricErrors(t *testing.T) {
	tests := []struct {
		name        string
		json        string
		errContains string
	}{
		{
			name:        "invalid regex",
			json:        `{"policies": [{"id": "test", "name": "Test", "metric": {"match": [{"metric_field": "name", "regex": "[invalid"}], "keep": false}}]}`,
			errContains: "invalid regex",
		},
		{
			name:        "no field type",
			json:        `{"policies": [{"id": "test", "name": "Test", "metric": {"match": [{"regex": ".*"}], "keep": false}}]}`,
			errContains: "must specify a field type",
		},
		{
			name:        "multiple field types",
			json:        `{"policies": [{"id": "test", "name": "Test", "metric": {"match": [{"metric_field": "name", "datapoint_attribute": "extra", "regex": ".*"}], "keep": false}}]}`,
			errContains: "must specify only one field type",
		},
		{
			name:        "no match type",
			json:        `{"policies": [{"id": "test", "name": "Test", "metric": {"match": [{"metric_field": "name"}], "keep": false}}]}`,
			errContains: "must have a match type",
		},
		{
			name:        "unknown metric_type",
			json:        `{"policies": [{"id": "test", "name": "Test", "metric": {"match": [{"metric_type": "unknown"}], "keep": false}}]}`,
			errContains: "unknown type",
		},
		{
			name:        "unknown aggregation_temporality",
			json:        `{"policies": [{"id": "test", "name": "Test", "metric": {"match": [{"aggregation_temporality": "unknown"}], "keep": false}}]}`,
			errContains: "unknown temporality",
		},
	}

	parser := NewParser()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parser.ParseBytes([]byte(tt.json))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errContains)
		})
	}
}

// ============================================================================
// TRACE ADDITIONAL COVERAGE
// ============================================================================

func TestParserParseTraceAllFieldsExtended(t *testing.T) {
	tests := []struct {
		name     string
		field    string
		expected policyv1.TraceField
	}{
		{"resource_schema_url", "resource_schema_url", policyv1.TraceField_TRACE_FIELD_RESOURCE_SCHEMA_URL},
		{"scope_schema_url", "scope_schema_url", policyv1.TraceField_TRACE_FIELD_SCOPE_SCHEMA_URL},
	}

	parser := NewParser()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := `{"policies": [{"id": "test", "name": "Test", "trace": {"match": [{"trace_field": "` + tt.field + `", "regex": ".*"}]}}]}`
			policies, err := parser.ParseBytes([]byte(j))
			require.NoError(t, err)

			matcher := policies[0].GetTrace().GetMatch()[0]
			tf, ok := matcher.GetField().(*policyv1.TraceMatcher_TraceField)
			require.True(t, ok)
			assert.Equal(t, tt.expected, tf.TraceField)
		})
	}
}

func TestParserParseTraceMatchTypes(t *testing.T) {
	tests := []struct {
		name      string
		matchJSON string
		check     func(t *testing.T, m *policyv1.TraceMatcher)
	}{
		{"starts_with", `"starts_with": "/api/"`, func(t *testing.T, m *policyv1.TraceMatcher) { assert.Equal(t, "/api/", m.GetStartsWith()) }},
		{"ends_with", `"ends_with": "/health"`, func(t *testing.T, m *policyv1.TraceMatcher) { assert.Equal(t, "/health", m.GetEndsWith()) }},
		{"contains", `"contains": "user"`, func(t *testing.T, m *policyv1.TraceMatcher) { assert.Equal(t, "user", m.GetContains()) }},
		{"exists true", `"exists": true`, func(t *testing.T, m *policyv1.TraceMatcher) { assert.True(t, m.GetExists()) }},
	}

	parser := NewParser()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := `{"policies": [{"id": "test", "name": "Test", "trace": {"match": [{"trace_field": "name", ` + tt.matchJSON + `}]}}]}`
			policies, err := parser.ParseBytes([]byte(j))
			require.NoError(t, err)

			tt.check(t, policies[0].GetTrace().GetMatch()[0])
		})
	}
}

func TestParserParseTraceFieldSelectors(t *testing.T) {
	tests := []struct {
		name  string
		json  string
		check func(t *testing.T, m *policyv1.TraceMatcher)
	}{
		{
			name: "resource_attribute",
			json: `{"policies": [{"id": "test", "name": "Test", "trace": {"match": [{"resource_attribute": "service.name", "exact": "my-svc"}]}}]}`,
			check: func(t *testing.T, m *policyv1.TraceMatcher) {
				attr, ok := m.GetField().(*policyv1.TraceMatcher_ResourceAttribute)
				require.True(t, ok)
				assert.Equal(t, []string{"service.name"}, attr.ResourceAttribute.GetPath())
			},
		},
		{
			name: "scope_attribute",
			json: `{"policies": [{"id": "test", "name": "Test", "trace": {"match": [{"scope_attribute": "scope.name", "exact": "my-scope"}]}}]}`,
			check: func(t *testing.T, m *policyv1.TraceMatcher) {
				attr, ok := m.GetField().(*policyv1.TraceMatcher_ScopeAttribute)
				require.True(t, ok)
				assert.Equal(t, []string{"scope.name"}, attr.ScopeAttribute.GetPath())
			},
		},
		{
			name: "event_name",
			json: `{"policies": [{"id": "test", "name": "Test", "trace": {"match": [{"event_name": "exception"}]}}]}`,
			check: func(t *testing.T, m *policyv1.TraceMatcher) {
				en, ok := m.GetField().(*policyv1.TraceMatcher_EventName)
				require.True(t, ok)
				assert.Equal(t, "exception", en.EventName)
				assert.Nil(t, m.GetMatch())
			},
		},
		{
			name: "event_attribute",
			json: `{"policies": [{"id": "test", "name": "Test", "trace": {"match": [{"event_attribute": "exception.type", "exact": "NullPointerException"}]}}]}`,
			check: func(t *testing.T, m *policyv1.TraceMatcher) {
				attr, ok := m.GetField().(*policyv1.TraceMatcher_EventAttribute)
				require.True(t, ok)
				assert.Equal(t, []string{"exception.type"}, attr.EventAttribute.GetPath())
				assert.Equal(t, "NullPointerException", m.GetExact())
			},
		},
		{
			name: "link_trace_id",
			json: `{"policies": [{"id": "test", "name": "Test", "trace": {"match": [{"link_trace_id": "abc123"}]}}]}`,
			check: func(t *testing.T, m *policyv1.TraceMatcher) {
				lt, ok := m.GetField().(*policyv1.TraceMatcher_LinkTraceId)
				require.True(t, ok)
				assert.Equal(t, "abc123", lt.LinkTraceId)
				assert.Nil(t, m.GetMatch())
			},
		},
	}

	parser := NewParser()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policies, err := parser.ParseBytes([]byte(tt.json))
			require.NoError(t, err)

			tt.check(t, policies[0].GetTrace().GetMatch()[0])
		})
	}
}

func TestParserParseTraceKeepOptions(t *testing.T) {
	tests := []struct {
		name  string
		json  string
		check func(t *testing.T, keep *policyv1.TraceSamplingConfig)
	}{
		{
			name: "all options",
			json: `{"policies": [{"id": "test", "name": "Test", "trace": {"match": [{"trace_field": "name", "regex": ".*"}], "keep": {"percentage": 25, "mode": "hash_seed", "sampling_precision": 14, "hash_seed": 42, "fail_closed": true}}}]}`,
			check: func(t *testing.T, keep *policyv1.TraceSamplingConfig) {
				assert.Equal(t, float32(25), keep.GetPercentage())
				assert.NotNil(t, keep.Mode)
				assert.Equal(t, policyv1.SamplingMode_SAMPLING_MODE_HASH_SEED, *keep.Mode)
				assert.Equal(t, uint32(14), keep.GetSamplingPrecision())
				assert.Equal(t, uint32(42), keep.GetHashSeed())
				assert.True(t, keep.GetFailClosed())
			},
		},
		{
			name: "mode hash_seed",
			json: `{"policies": [{"id": "test", "name": "Test", "trace": {"match": [{"trace_field": "name", "regex": ".*"}], "keep": {"percentage": 50, "mode": "hash_seed"}}}]}`,
			check: func(t *testing.T, keep *policyv1.TraceSamplingConfig) {
				assert.Equal(t, policyv1.SamplingMode_SAMPLING_MODE_HASH_SEED, *keep.Mode)
			},
		},
		{
			name: "mode proportional",
			json: `{"policies": [{"id": "test", "name": "Test", "trace": {"match": [{"trace_field": "name", "regex": ".*"}], "keep": {"percentage": 50, "mode": "proportional"}}}]}`,
			check: func(t *testing.T, keep *policyv1.TraceSamplingConfig) {
				assert.Equal(t, policyv1.SamplingMode_SAMPLING_MODE_PROPORTIONAL, *keep.Mode)
			},
		},
		{
			name: "mode equalizing",
			json: `{"policies": [{"id": "test", "name": "Test", "trace": {"match": [{"trace_field": "name", "regex": ".*"}], "keep": {"percentage": 50, "mode": "equalizing"}}}]}`,
			check: func(t *testing.T, keep *policyv1.TraceSamplingConfig) {
				assert.Equal(t, policyv1.SamplingMode_SAMPLING_MODE_EQUALIZING, *keep.Mode)
			},
		},
		{
			name: "mode proto form",
			json: `{"policies": [{"id": "test", "name": "Test", "trace": {"match": [{"trace_field": "name", "regex": ".*"}], "keep": {"percentage": 50, "mode": "SAMPLING_MODE_HASH_SEED"}}}]}`,
			check: func(t *testing.T, keep *policyv1.TraceSamplingConfig) {
				assert.Equal(t, policyv1.SamplingMode_SAMPLING_MODE_HASH_SEED, *keep.Mode)
			},
		},
	}

	parser := NewParser()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policies, err := parser.ParseBytes([]byte(tt.json))
			require.NoError(t, err)

			keep := policies[0].GetTrace().GetKeep()
			require.NotNil(t, keep)
			tt.check(t, keep)
		})
	}
}

func TestParserParseTraceFlags(t *testing.T) {
	parser := NewParser()

	j := `{"policies": [{"id": "test", "name": "Test", "trace": {"match": [{"trace_field": "name", "regex": "debug", "negate": true, "case_insensitive": true}]}}]}`
	policies, err := parser.ParseBytes([]byte(j))
	require.NoError(t, err)

	matcher := policies[0].GetTrace().GetMatch()[0]
	assert.True(t, matcher.GetNegate())
	assert.True(t, matcher.GetCaseInsensitive())
}

func TestParserParseTraceErrors(t *testing.T) {
	tests := []struct {
		name        string
		json        string
		errContains string
	}{
		{
			name:        "invalid regex",
			json:        `{"policies": [{"id": "test", "name": "Test", "trace": {"match": [{"trace_field": "name", "regex": "[invalid"}]}}]}`,
			errContains: "invalid regex",
		},
		{
			name:        "no field type",
			json:        `{"policies": [{"id": "test", "name": "Test", "trace": {"match": [{"regex": ".*"}]}}]}`,
			errContains: "must specify a field type",
		},
		{
			name:        "multiple field types",
			json:        `{"policies": [{"id": "test", "name": "Test", "trace": {"match": [{"trace_field": "name", "span_attribute": "extra", "regex": ".*"}]}}]}`,
			errContains: "must specify only one field type",
		},
		{
			name:        "no match type",
			json:        `{"policies": [{"id": "test", "name": "Test", "trace": {"match": [{"trace_field": "name"}]}}]}`,
			errContains: "must have a match type",
		},
		{
			name:        "unknown keep mode",
			json:        `{"policies": [{"id": "test", "name": "Test", "trace": {"match": [{"trace_field": "name", "regex": ".*"}], "keep": {"percentage": 50, "mode": "unknown"}}}]}`,
			errContains: "unknown mode",
		},
	}

	parser := NewParser()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parser.ParseBytes([]byte(tt.json))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errContains)
		})
	}
}

// ============================================================================
// KEEP PERCENTAGE STRING AND READER ERROR
// ============================================================================

func TestParserParseKeepPercentageString(t *testing.T) {
	parser := NewParser()

	j := `{"policies": [{"id": "test", "name": "Test", "log": {"match": [{"log_field": "body", "regex": ".*"}], "keep": "50%"}}]}`
	policies, err := parser.ParseBytes([]byte(j))
	require.NoError(t, err)
	assert.Equal(t, "50%", policies[0].GetLog().GetKeep())
}

func TestParserParseReaderInvalidJSON(t *testing.T) {
	parser := NewParser()

	_, err := parser.Parse(strings.NewReader(`{invalid json}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode JSON")
}

func TestParserParseEnabledField(t *testing.T) {
	tests := []struct {
		name     string
		json     string
		expected bool
	}{
		{
			name:     "omitted defaults to true",
			json:     `{"policies": [{"id": "p1", "name": "P1", "log": {"match": [{"log_field": "body", "regex": ".*"}], "keep": "all"}}]}`,
			expected: true,
		},
		{
			name:     "explicit true",
			json:     `{"policies": [{"id": "p1", "name": "P1", "enabled": true, "log": {"match": [{"log_field": "body", "regex": ".*"}], "keep": "all"}}]}`,
			expected: true,
		},
		{
			name:     "explicit false",
			json:     `{"policies": [{"id": "p1", "name": "P1", "enabled": false, "log": {"match": [{"log_field": "body", "regex": ".*"}], "keep": "all"}}]}`,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewParser()
			policies, err := parser.ParseBytes([]byte(tt.json))
			require.NoError(t, err)
			require.Len(t, policies, 1)
			assert.Equal(t, tt.expected, policies[0].GetEnabled())
		})
	}
}

// Helper functions
func strPtr(s string) *string {
	return &s
}

func boolPtr(b bool) *bool {
	return &b
}
