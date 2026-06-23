package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
	"google.golang.org/protobuf/encoding/protojson"
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

func TestCollectStatsWithFivePolicies(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "five-policies.json"))
	require.NoError(t, err)
	var resp policyv1.SyncResponse
	require.NoError(t, protojson.Unmarshal(data, &resp))

	registry := NewPolicyRegistry()
	handle, err := registry.Register(newStaticProvider(resp.Policies))
	require.NoError(t, err)
	defer handle.Unregister()

	stats := registry.CollectStats()
	require.Len(t, stats, 5)

	ids := make([]string, len(stats))
	for i, s := range stats {
		ids[i] = s.PolicyID
		assert.Empty(t, s.Errors, "policy %s should have no compile errors", s.PolicyID)
	}
	assert.ElementsMatch(t, []string{
		"log_event_policy:019e84c2-4e25-7bf4-824c-772805e6d64b",
		"log_event_policy:019e98f8-99cf-7022-83b2-add8ca12aa92",
		"log_event_policy:019e9951-ee14-738a-ae73-e86f050a4543",
		"log_event_policy:c8b30b43-8e5a-5108-adc7-b9f746ffa6b9",
		"log_event_policy:fde62bcb-e202-42b2-bdf1-49259f35eb63",
	}, ids)
	fmt.Println(stats)
}

func TestCollectStatsIncludesZeroStats(t *testing.T) {
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
	require.Len(t, stats, 1)
	assert.Equal(t, "keep-info", stats[0].PolicyID)
	assert.Equal(t, uint64(0), stats[0].MatchHits)
	assert.Equal(t, uint64(0), stats[0].MatchMisses)
}
