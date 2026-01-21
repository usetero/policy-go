package engine

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper to create a bool pointer
func boolPtr(b bool) *bool {
	return &b
}

func TestKeepRestrictiveness(t *testing.T) {
	tests := []struct {
		name     string
		keep     Keep
		expected int
	}{
		{"KeepNone is most restrictive", Keep{Action: KeepNone}, 1000},
		{"KeepAll is least restrictive", Keep{Action: KeepAll}, 0},
		{"KeepSample 0% is very restrictive", Keep{Action: KeepSample, Value: 0}, 1000},
		{"KeepSample 50% is medium", Keep{Action: KeepSample, Value: 50}, 500},
		{"KeepSample 100% is least restrictive", Keep{Action: KeepSample, Value: 100}, 0},
		{"KeepRatePerSecond is medium", Keep{Action: KeepRatePerSecond, Value: 10}, 500},
		{"KeepRatePerMinute is medium", Keep{Action: KeepRatePerMinute, Value: 100}, 500},
		{"Unknown action defaults to 0", Keep{Action: KeepAction(99)}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.keep.Restrictiveness()
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestPolicyStats(t *testing.T) {
	stats := &PolicyStats{}

	// Test initial values
	snapshot := stats.Snapshot("test-policy")
	assert.Equal(t, uint64(0), snapshot.Hits)
	assert.Equal(t, uint64(0), snapshot.Drops)
	assert.Equal(t, uint64(0), snapshot.Samples)
	assert.Equal(t, uint64(0), snapshot.RateLimited)
	assert.Equal(t, "test-policy", snapshot.PolicyID)

	// Test incrementing
	stats.RecordHit()
	stats.RecordHit()
	stats.RecordDrop()
	stats.RecordSample()
	stats.RecordRateLimited()

	snapshot = stats.Snapshot("test-policy")
	assert.Equal(t, uint64(2), snapshot.Hits)
	assert.Equal(t, uint64(1), snapshot.Drops)
	assert.Equal(t, uint64(1), snapshot.Samples)
	assert.Equal(t, uint64(1), snapshot.RateLimited)
}

func TestPolicyIsLogPolicy(t *testing.T) {
	tests := []struct {
		name     string
		policy   *Policy
		expected bool
	}{
		{
			name:     "Policy with Log is a log policy",
			policy:   &Policy{ID: "test", Log: &LogPolicy{}},
			expected: true,
		},
		{
			name:     "Policy without Log is not a log policy",
			policy:   &Policy{ID: "test", Log: nil},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.policy.IsLogPolicy()
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestCompilerCompileEmpty(t *testing.T) {
	compiler := NewCompiler()
	stats := make(map[string]*PolicyStats)

	compiled, err := compiler.Compile(nil, stats)
	require.NoError(t, err)
	defer compiled.Close()

	assert.Empty(t, compiled.Databases())
	assert.Empty(t, compiled.ExistenceChecks())
	assert.Empty(t, compiled.Policies())
}

func TestCompilerCompileSinglePolicy(t *testing.T) {
	compiler := NewCompiler()
	stats := map[string]*PolicyStats{
		"test-policy": {},
	}

	policies := []*Policy{
		{
			ID:   "test-policy",
			Name: "Test Policy",
			Log: &LogPolicy{
				Matchers: []Matcher{
					{
						Field:   FieldSelector{Type: FieldTypeLogField, Field: LogFieldBody},
						Pattern: "error",
					},
				},
				Keep: Keep{Action: KeepNone},
			},
		},
	}

	compiled, err := compiler.Compile(policies, stats)
	require.NoError(t, err)
	defer compiled.Close()

	// Check policy was compiled
	policy, ok := compiled.GetPolicy("test-policy")
	require.True(t, ok, "expected to find test-policy")
	assert.Equal(t, 1, policy.MatcherCount)
	assert.Equal(t, KeepNone, policy.Keep.Action)

	// Check database was created
	assert.Len(t, compiled.Databases(), 1)
}

func TestCompilerCompileMultipleMatchers(t *testing.T) {
	compiler := NewCompiler()
	stats := map[string]*PolicyStats{
		"multi-matcher": {},
	}

	policies := []*Policy{
		{
			ID:   "multi-matcher",
			Name: "Multiple Matchers",
			Log: &LogPolicy{
				Matchers: []Matcher{
					{
						Field:   FieldSelector{Type: FieldTypeLogField, Field: LogFieldBody},
						Pattern: "error",
					},
					{
						Field:   FieldSelector{Type: FieldTypeLogField, Field: LogFieldSeverityText},
						Pattern: "ERROR",
					},
				},
				Keep: Keep{Action: KeepNone},
			},
		},
	}

	compiled, err := compiler.Compile(policies, stats)
	require.NoError(t, err)
	defer compiled.Close()

	policy, ok := compiled.GetPolicy("multi-matcher")
	require.True(t, ok, "expected to find multi-matcher")
	assert.Equal(t, 2, policy.MatcherCount)

	// Should have 2 databases (one per field selector)
	assert.Len(t, compiled.Databases(), 2)
}

func TestCompilerCompileNegatedMatcher(t *testing.T) {
	compiler := NewCompiler()
	stats := map[string]*PolicyStats{
		"negated-policy": {},
	}

	policies := []*Policy{
		{
			ID:   "negated-policy",
			Name: "Negated Matcher",
			Log: &LogPolicy{
				Matchers: []Matcher{
					{
						Field:   FieldSelector{Type: FieldTypeLogField, Field: LogFieldBody},
						Pattern: "debug",
						Negated: true,
					},
				},
				Keep: Keep{Action: KeepAll},
			},
		},
	}

	compiled, err := compiler.Compile(policies, stats)
	require.NoError(t, err)
	defer compiled.Close()

	// Check database key has Negated = true
	for key := range compiled.Databases() {
		assert.True(t, key.Negated, "expected database key to have Negated = true")
	}
}

func TestCompilerCompileMixedNegation(t *testing.T) {
	compiler := NewCompiler()
	stats := map[string]*PolicyStats{
		"normal":  {},
		"negated": {},
	}

	policies := []*Policy{
		{
			ID:   "normal",
			Name: "Normal",
			Log: &LogPolicy{
				Matchers: []Matcher{
					{
						Field:   FieldSelector{Type: FieldTypeLogField, Field: LogFieldBody},
						Pattern: "error",
						Negated: false,
					},
				},
				Keep: Keep{Action: KeepNone},
			},
		},
		{
			ID:   "negated",
			Name: "Negated",
			Log: &LogPolicy{
				Matchers: []Matcher{
					{
						Field:   FieldSelector{Type: FieldTypeLogField, Field: LogFieldBody},
						Pattern: "debug",
						Negated: true,
					},
				},
				Keep: Keep{Action: KeepAll},
			},
		},
	}

	compiled, err := compiler.Compile(policies, stats)
	require.NoError(t, err)
	defer compiled.Close()

	// Should have 2 databases (same field but different negation)
	assert.Len(t, compiled.Databases(), 2)

	// Verify both keys exist
	normalKey := MatchKey{
		Selector: FieldSelector{Type: FieldTypeLogField, Field: LogFieldBody},
		Negated:  false,
	}
	negatedKey := MatchKey{
		Selector: FieldSelector{Type: FieldTypeLogField, Field: LogFieldBody},
		Negated:  true,
	}

	_, hasNormal := compiled.Databases()[normalKey]
	_, hasNegated := compiled.Databases()[negatedKey]
	assert.True(t, hasNormal, "expected to find normal (non-negated) database")
	assert.True(t, hasNegated, "expected to find negated database")
}

func TestCompilerCompileExistenceCheck(t *testing.T) {
	compiler := NewCompiler()
	stats := map[string]*PolicyStats{
		"exists-check": {},
	}

	policies := []*Policy{
		{
			ID:   "exists-check",
			Name: "Existence Check",
			Log: &LogPolicy{
				Matchers: []Matcher{
					{
						Field:  FieldSelector{Type: FieldTypeLogAttribute, Key: "trace_id"},
						Exists: boolPtr(true),
					},
				},
				Keep: Keep{Action: KeepAll},
			},
		},
	}

	compiled, err := compiler.Compile(policies, stats)
	require.NoError(t, err)
	defer compiled.Close()

	// Should have no databases (existence checks don't use Hyperscan)
	assert.Empty(t, compiled.Databases())

	// Should have 1 existence check
	require.Len(t, compiled.ExistenceChecks(), 1)

	check := compiled.ExistenceChecks()[0]
	assert.Equal(t, "exists-check", check.PolicyID)
	assert.True(t, check.MustExist)
	assert.Equal(t, FieldTypeLogAttribute, check.Selector.Type)
	assert.Equal(t, "trace_id", check.Selector.Key)
}

func TestCompilerCompileNotExistsCheck(t *testing.T) {
	compiler := NewCompiler()
	stats := map[string]*PolicyStats{
		"not-exists-check": {},
	}

	policies := []*Policy{
		{
			ID:   "not-exists-check",
			Name: "Not Exists Check",
			Log: &LogPolicy{
				Matchers: []Matcher{
					{
						Field:  FieldSelector{Type: FieldTypeResourceAttribute, Key: "debug"},
						Exists: boolPtr(false),
					},
				},
				Keep: Keep{Action: KeepNone},
			},
		},
	}

	compiled, err := compiler.Compile(policies, stats)
	require.NoError(t, err)
	defer compiled.Close()

	require.Len(t, compiled.ExistenceChecks(), 1)

	check := compiled.ExistenceChecks()[0]
	assert.False(t, check.MustExist)
}

func TestCompilerCompileAllFieldTypes(t *testing.T) {
	compiler := NewCompiler()
	stats := map[string]*PolicyStats{
		"all-fields": {},
	}

	policies := []*Policy{
		{
			ID:   "all-fields",
			Name: "All Field Types",
			Log: &LogPolicy{
				Matchers: []Matcher{
					{
						Field:   FieldSelector{Type: FieldTypeLogField, Field: LogFieldBody},
						Pattern: "body-pattern",
					},
					{
						Field:   FieldSelector{Type: FieldTypeLogAttribute, Key: "log_attr"},
						Pattern: "log-attr-pattern",
					},
					{
						Field:   FieldSelector{Type: FieldTypeResourceAttribute, Key: "resource_attr"},
						Pattern: "resource-attr-pattern",
					},
					{
						Field:   FieldSelector{Type: FieldTypeScopeAttribute, Key: "scope_attr"},
						Pattern: "scope-attr-pattern",
					},
				},
				Keep: Keep{Action: KeepNone},
			},
		},
	}

	compiled, err := compiler.Compile(policies, stats)
	require.NoError(t, err)
	defer compiled.Close()

	// Should have 4 databases (one per field type/key)
	assert.Len(t, compiled.Databases(), 4)

	policy, ok := compiled.GetPolicy("all-fields")
	require.True(t, ok, "expected to find all-fields policy")
	assert.Equal(t, 4, policy.MatcherCount)
}

func TestCompilerCompileInvalidRegex(t *testing.T) {
	compiler := NewCompiler()
	stats := map[string]*PolicyStats{
		"invalid-regex": {},
	}

	policies := []*Policy{
		{
			ID:   "invalid-regex",
			Name: "Invalid Regex",
			Log: &LogPolicy{
				Matchers: []Matcher{
					{
						Field:   FieldSelector{Type: FieldTypeLogField, Field: LogFieldBody},
						Pattern: "[invalid",
					},
				},
				Keep: Keep{Action: KeepNone},
			},
		},
	}

	_, err := compiler.Compile(policies, stats)
	assert.Error(t, err)
}

func TestCompilerSkipsNonLogPolicies(t *testing.T) {
	compiler := NewCompiler()
	stats := map[string]*PolicyStats{}

	policies := []*Policy{
		{
			ID:   "non-log-policy",
			Name: "Non-Log Policy",
			Log:  nil, // Not a log policy
		},
	}

	compiled, err := compiler.Compile(policies, stats)
	require.NoError(t, err)
	defer compiled.Close()

	assert.Empty(t, compiled.Policies())
}

func TestCompiledDatabaseScan(t *testing.T) {
	compiler := NewCompiler()
	stats := map[string]*PolicyStats{
		"scan-test": {},
	}

	policies := []*Policy{
		{
			ID:   "scan-test",
			Name: "Scan Test",
			Log: &LogPolicy{
				Matchers: []Matcher{
					{
						Field:   FieldSelector{Type: FieldTypeLogField, Field: LogFieldBody},
						Pattern: "error",
					},
					{
						Field:   FieldSelector{Type: FieldTypeLogField, Field: LogFieldBody},
						Pattern: "warning",
					},
				},
				Keep: Keep{Action: KeepNone},
			},
		},
	}

	compiled, err := compiler.Compile(policies, stats)
	require.NoError(t, err)
	defer compiled.Close()

	key := MatchKey{
		Selector: FieldSelector{Type: FieldTypeLogField, Field: LogFieldBody},
		Negated:  false,
	}
	db, ok := compiled.Databases()[key]
	require.True(t, ok, "expected to find database for body field")

	tests := []struct {
		name     string
		input    string
		expected map[int]bool
	}{
		{
			name:     "Matches error",
			input:    "this is an error message",
			expected: map[int]bool{0: true},
		},
		{
			name:     "Matches warning",
			input:    "this is a warning message",
			expected: map[int]bool{1: true},
		},
		{
			name:     "Matches both",
			input:    "error and warning together",
			expected: map[int]bool{0: true, 1: true},
		},
		{
			name:     "Matches neither",
			input:    "just a normal message",
			expected: map[int]bool{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched, err := db.Scan([]byte(tt.input))
			require.NoError(t, err)

			for id, expected := range tt.expected {
				assert.Equal(t, expected, matched[id], "pattern %d", id)
			}

			// Check no unexpected matches
			for id := range matched {
				assert.True(t, tt.expected[id], "unexpected match for pattern %d", id)
			}
		})
	}
}

func TestCompiledDatabaseScanConcurrent(t *testing.T) {
	compiler := NewCompiler()
	stats := map[string]*PolicyStats{
		"concurrent-test": {},
	}

	policies := []*Policy{
		{
			ID:   "concurrent-test",
			Name: "Concurrent Test",
			Log: &LogPolicy{
				Matchers: []Matcher{
					{
						Field:   FieldSelector{Type: FieldTypeLogField, Field: LogFieldBody},
						Pattern: "test",
					},
				},
				Keep: Keep{Action: KeepNone},
			},
		},
	}

	compiled, err := compiler.Compile(policies, stats)
	require.NoError(t, err)
	defer compiled.Close()

	key := MatchKey{
		Selector: FieldSelector{Type: FieldTypeLogField, Field: LogFieldBody},
		Negated:  false,
	}
	db := compiled.Databases()[key]

	// Run concurrent scans
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				matched, err := db.Scan([]byte("this is a test message"))
				assert.NoError(t, err)
				assert.True(t, matched[0], "expected pattern to match")
			}
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestCompiledMatchersClose(t *testing.T) {
	compiler := NewCompiler()
	stats := map[string]*PolicyStats{
		"close-test": {},
	}

	policies := []*Policy{
		{
			ID:   "close-test",
			Name: "Close Test",
			Log: &LogPolicy{
				Matchers: []Matcher{
					{
						Field:   FieldSelector{Type: FieldTypeLogField, Field: LogFieldBody},
						Pattern: "test",
					},
				},
				Keep: Keep{Action: KeepNone},
			},
		},
	}

	compiled, err := compiler.Compile(policies, stats)
	require.NoError(t, err)

	// Close should not error
	err = compiled.Close()
	assert.NoError(t, err)
}

func TestNewCompiledMatchers(t *testing.T) {
	cm := NewCompiledMatchers()

	assert.NotNil(t, cm.databases)
	assert.NotNil(t, cm.existenceChecks)
	assert.NotNil(t, cm.policies)
}

func TestCompiledPolicyWithStats(t *testing.T) {
	compiler := NewCompiler()
	stats := map[string]*PolicyStats{
		"stats-test": {},
	}

	policies := []*Policy{
		{
			ID:   "stats-test",
			Name: "Stats Test",
			Log: &LogPolicy{
				Matchers: []Matcher{
					{
						Field:   FieldSelector{Type: FieldTypeLogField, Field: LogFieldBody},
						Pattern: "test",
					},
				},
				Keep: Keep{Action: KeepNone},
			},
		},
	}

	compiled, err := compiler.Compile(policies, stats)
	require.NoError(t, err)
	defer compiled.Close()

	policy, ok := compiled.GetPolicy("stats-test")
	require.True(t, ok, "expected to find stats-test policy")

	// Stats should be linked
	assert.Same(t, stats["stats-test"], policy.Stats)

	// Record some stats
	policy.Stats.RecordHit()
	policy.Stats.RecordDrop()

	// Verify via snapshot
	snapshot := stats["stats-test"].Snapshot("stats-test")
	assert.Equal(t, uint64(1), snapshot.Hits)
	assert.Equal(t, uint64(1), snapshot.Drops)
}

func TestPatternIndexMapping(t *testing.T) {
	compiler := NewCompiler()
	stats := map[string]*PolicyStats{
		"policy-a": {},
		"policy-b": {},
	}

	policies := []*Policy{
		{
			ID:   "policy-a",
			Name: "Policy A",
			Log: &LogPolicy{
				Matchers: []Matcher{
					{
						Field:   FieldSelector{Type: FieldTypeLogField, Field: LogFieldBody},
						Pattern: "pattern-a",
					},
				},
				Keep: Keep{Action: KeepNone},
			},
		},
		{
			ID:   "policy-b",
			Name: "Policy B",
			Log: &LogPolicy{
				Matchers: []Matcher{
					{
						Field:   FieldSelector{Type: FieldTypeLogField, Field: LogFieldBody},
						Pattern: "pattern-b",
					},
				},
				Keep: Keep{Action: KeepAll},
			},
		},
	}

	compiled, err := compiler.Compile(policies, stats)
	require.NoError(t, err)
	defer compiled.Close()

	key := MatchKey{
		Selector: FieldSelector{Type: FieldTypeLogField, Field: LogFieldBody},
		Negated:  false,
	}
	db := compiled.Databases()[key]

	// Pattern index should map back to correct policies
	patternIndex := db.PatternIndex()
	assert.Len(t, patternIndex, 2)

	// Scan and verify mapping
	matched, err := db.Scan([]byte("pattern-a here"))
	require.NoError(t, err)

	for patternID, didMatch := range matched {
		if didMatch {
			ref := patternIndex[patternID]
			assert.Equal(t, "policy-a", ref.PolicyID)
		}
	}
}
