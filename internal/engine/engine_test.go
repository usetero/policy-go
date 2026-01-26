package engine

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
)

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

func TestParseKeep(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected Keep
		hasError bool
	}{
		{"empty is all", "", Keep{Action: KeepAll}, false},
		{"all", "all", Keep{Action: KeepAll}, false},
		{"none", "none", Keep{Action: KeepNone}, false},
		{"50%", "50%", Keep{Action: KeepSample, Value: 50}, false},
		{"100%", "100%", Keep{Action: KeepSample, Value: 100}, false},
		{"0%", "0%", Keep{Action: KeepSample, Value: 0}, false},
		{"100/s", "100/s", Keep{Action: KeepRatePerSecond, Value: 100}, false},
		{"1000/m", "1000/m", Keep{Action: KeepRatePerMinute, Value: 1000}, false},
		{"invalid", "invalid", Keep{}, true},
		{"negative percentage", "-10%", Keep{}, true},
		{"over 100%", "150%", Keep{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseKeep(tt.input)
			if tt.hasError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, got)
			}
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

	policies := []*policyv1.Policy{
		{
			Id:   "test-policy",
			Name: "Test Policy",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Regex{Regex: "error"},
						},
					},
					Keep: "none",
				},
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

	policies := []*policyv1.Policy{
		{
			Id:   "multi-matcher",
			Name: "Multiple Matchers",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Regex{Regex: "error"},
						},
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_SEVERITY_TEXT},
							Match: &policyv1.LogMatcher_Regex{Regex: "ERROR"},
						},
					},
					Keep: "none",
				},
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

	policies := []*policyv1.Policy{
		{
			Id:   "negated-policy",
			Name: "Negated Matcher",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field:  &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match:  &policyv1.LogMatcher_Regex{Regex: "debug"},
							Negate: true,
						},
					},
					Keep: "all",
				},
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

func TestCompilerCompileExistenceCheck(t *testing.T) {
	compiler := NewCompiler()
	stats := map[string]*PolicyStats{
		"exists-check": {},
	}

	policies := []*policyv1.Policy{
		{
			Id:   "exists-check",
			Name: "Existence Check",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogAttribute{LogAttribute: "trace_id"},
							Match: &policyv1.LogMatcher_Exists{Exists: true},
						},
					},
					Keep: "all",
				},
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
	assert.Equal(t, "trace_id", check.Selector.LogAttribute)
}

func TestCompilerCompileExactMatch(t *testing.T) {
	compiler := NewCompiler()
	stats := map[string]*PolicyStats{
		"exact-match": {},
	}

	policies := []*policyv1.Policy{
		{
			Id:   "exact-match",
			Name: "Exact Match",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Exact{Exact: "hello.world"},
						},
					},
					Keep: "none",
				},
			},
		},
	}

	compiled, err := compiler.Compile(policies, stats)
	require.NoError(t, err)
	defer compiled.Close()

	// Should have 1 database
	assert.Len(t, compiled.Databases(), 1)

	// Scan for exact match (dots should be escaped)
	for _, db := range compiled.Databases() {
		matched, err := db.Scan([]byte("hello.world"))
		require.NoError(t, err)
		assert.True(t, matched[0], "expected exact match")

		// Should not match with different character
		matched, err = db.Scan([]byte("helloXworld"))
		require.NoError(t, err)
		assert.False(t, matched[0], "should not match")
	}
}

func TestCompilerSkipsNonLogPolicies(t *testing.T) {
	compiler := NewCompiler()
	stats := map[string]*PolicyStats{}

	policies := []*policyv1.Policy{
		{
			Id:   "metric-policy",
			Name: "Metric Policy",
			Target: &policyv1.Policy_Metric{
				Metric: &policyv1.MetricTarget{},
			},
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

	policies := []*policyv1.Policy{
		{
			Id:   "scan-test",
			Name: "Scan Test",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Regex{Regex: "error"},
						},
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Regex{Regex: "warning"},
						},
					},
					Keep: "none",
				},
			},
		},
	}

	compiled, err := compiler.Compile(policies, stats)
	require.NoError(t, err)
	defer compiled.Close()

	// Find the database
	var db *CompiledDatabase
	for _, d := range compiled.Databases() {
		db = d
		break
	}
	require.NotNil(t, db)

	tests := []struct {
		name     string
		input    string
		expected []bool
	}{
		{
			name:     "Matches error",
			input:    "this is an error message",
			expected: []bool{true, false},
		},
		{
			name:     "Matches warning",
			input:    "this is a warning message",
			expected: []bool{false, true},
		},
		{
			name:     "Matches both",
			input:    "error and warning together",
			expected: []bool{true, true},
		},
		{
			name:     "Matches neither",
			input:    "just a normal message",
			expected: []bool{false, false},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched, err := db.Scan([]byte(tt.input))
			require.NoError(t, err)
			assert.Equal(t, tt.expected, matched)
		})
	}
}

func TestCompiledDatabaseScanConcurrent(t *testing.T) {
	compiler := NewCompiler()
	stats := map[string]*PolicyStats{
		"concurrent-test": {},
	}

	policies := []*policyv1.Policy{
		{
			Id:   "concurrent-test",
			Name: "Concurrent Test",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Regex{Regex: "test"},
						},
					},
					Keep: "none",
				},
			},
		},
	}

	compiled, err := compiler.Compile(policies, stats)
	require.NoError(t, err)
	defer compiled.Close()

	var db *CompiledDatabase
	for _, d := range compiled.Databases() {
		db = d
		break
	}

	// Run concurrent scans
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				matched, err := db.Scan([]byte("this is a test message"))
				assert.NoError(t, err)
				assert.True(t, len(matched) > 0 && matched[0], "expected pattern to match")
			}
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestNewCompiledMatchers(t *testing.T) {
	cm := NewCompiledMatchers()

	assert.NotNil(t, cm.databases)
	assert.NotNil(t, cm.existenceChecks)
	assert.NotNil(t, cm.policies)
}

func TestPolicyCount(t *testing.T) {
	compiler := NewCompiler()
	stats := map[string]*PolicyStats{
		"policy-0": {},
		"policy-1": {},
		"policy-2": {},
	}

	policies := []*policyv1.Policy{
		{
			Id:   "policy-0",
			Name: "Policy 0",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{{
						Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
						Match: &policyv1.LogMatcher_Regex{Regex: "a"},
					}},
					Keep: "none",
				},
			},
		},
		{
			Id:   "policy-1",
			Name: "Policy 1",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{{
						Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
						Match: &policyv1.LogMatcher_Regex{Regex: "b"},
					}},
					Keep: "all",
				},
			},
		},
		{
			Id:   "policy-2",
			Name: "Policy 2",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{{
						Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
						Match: &policyv1.LogMatcher_Regex{Regex: "c"},
					}},
					Keep: "none",
				},
			},
		},
	}

	compiled, err := compiler.Compile(policies, stats)
	require.NoError(t, err)
	defer compiled.Close()

	// Verify PolicyCount
	assert.Equal(t, 3, compiled.PolicyCount())

	// Verify PolicyByIndex returns correct policies
	for i := 0; i < 3; i++ {
		policy := compiled.PolicyByIndex(i)
		assert.Equal(t, i, policy.Index)
	}
}
