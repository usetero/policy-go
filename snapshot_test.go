package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
)

func TestSnapshotCompiledMatchers(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "test-policy",
			Name: "Test Policy",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Contains{Contains: "test"},
						},
					},
					Keep: "all",
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	// Get the log snapshot and access its compiled matchers
	snapshot := registry.LogSnapshot()
	require.NotNil(t, snapshot, "snapshot should not be nil")

	matchers := snapshot.CompiledMatchers()
	require.NotNil(t, matchers, "CompiledMatchers should not be nil")

	// Verify we can access the policy
	policy, ok := matchers.GetPolicy("test-policy")
	assert.True(t, ok, "should find test-policy")
	assert.Equal(t, "test-policy", policy.ID)
}

func TestSnapshotGetStats(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "stats-test-policy",
			Name: "Stats Test Policy",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Contains{Contains: "stats"},
						},
					},
					Keep: "none",
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	// Evaluate a log to generate stats
	record := &SimpleLogRecord{
		Body: []byte("stats test message"),
	}
	EvaluateLog(engine, record, SimpleLogMatcher)

	// Get stats from snapshot
	snapshot := registry.LogSnapshot()
	require.NotNil(t, snapshot)

	stats := snapshot.GetStats("stats-test-policy")
	require.NotNil(t, stats, "GetStats should return stats for the policy")

	// Verify stats were recorded
	assert.Greater(t, stats.Hits.Load(), uint64(0), "should have at least one hit")
	assert.Greater(t, stats.Drops.Load(), uint64(0), "should have at least one drop")
}

func TestSnapshotGetStatsNotFound(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "existing-policy",
			Name: "Existing Policy",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Contains{Contains: "test"},
						},
					},
					Keep: "all",
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	snapshot := registry.LogSnapshot()
	require.NotNil(t, snapshot)

	// Try to get stats for a non-existent policy
	stats := snapshot.GetStats("non-existent-policy")
	assert.Nil(t, stats, "GetStats should return nil for non-existent policy")
}

func TestSnapshotNilHandling(t *testing.T) {
	// Test that nil snapshots are handled gracefully
	var snapshot *LogSnapshot = nil

	// CompiledMatchers should return nil for nil snapshot
	assert.Nil(t, snapshot.CompiledMatchers(), "CompiledMatchers should return nil for nil snapshot")

	// GetStats should return nil for nil snapshot
	assert.Nil(t, snapshot.GetStats("any-policy"), "GetStats should return nil for nil snapshot")

	// GetPolicy should return nil, false for nil snapshot
	policy, ok := snapshot.GetPolicy("any-policy")
	assert.Nil(t, policy)
	assert.False(t, ok)
}
