package policy

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
