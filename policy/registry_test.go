package policy

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
)

func TestRegistryAndSnapshot(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := NewFileProvider(filepath.Join("testdata", "policies.json"))

	handle, err := registry.Register(provider)
	require.NoError(t, err)
	defer handle.Unregister()

	snapshot := registry.Snapshot()
	require.NotNil(t, snapshot)

	// Check that we can iterate over policies
	count := 0
	for id, p := range snapshot.Iter() {
		assert.NotEmpty(t, id, "policy ID should not be empty")
		assert.NotNil(t, p, "policy should not be nil")
		count++
	}

	assert.Greater(t, count, 0, "should have at least one policy")
}

func TestCollectStatsFiltersZeroStatsByDefault(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "keep-info",
			Name: "Keep Info",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_SEVERITY_TEXT},
							Match: &policyv1.LogMatcher_Exact{Exact: "INFO"},
						},
					},
					Keep: "all",
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	stats := registry.CollectStats()
	assert.Empty(t, stats)
}

func TestCollectStatsIncludesZeroStatsWhenEnabled(t *testing.T) {
	registry := NewPolicyRegistry()
	registry.SetIncludeZeroHitPolicyStats(true)
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "keep-info",
			Name: "Keep Info",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_SEVERITY_TEXT},
							Match: &policyv1.LogMatcher_Exact{Exact: "INFO"},
						},
					},
					Keep: "all",
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	stats := registry.CollectStats()
	require.Len(t, stats, 1)
	assert.Equal(t, "keep-info", stats[0].PolicyID)
	assert.Equal(t, uint64(0), stats[0].MatchHits)
	assert.Equal(t, uint64(0), stats[0].MatchMisses)
}
