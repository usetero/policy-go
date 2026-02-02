package policy

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileProviderLoad(t *testing.T) {
	provider := NewFileProvider(filepath.Join("testdata", "policies.json"))
	policies, err := provider.Load()
	require.NoError(t, err)

	// We have 12 log policies in the test file (7 original + 5 v1.2.0 feature demos)
	logPolicies := 0
	for _, p := range policies {
		if p.GetLog() != nil {
			logPolicies++
		}
	}

	assert.Equal(t, 12, logPolicies, "expected 12 log policies")

	// Check first policy
	var found *Policy
	for _, p := range policies {
		if p.GetId() == "drop-echo-logs" {
			found = p
			break
		}
	}
	require.NotNil(t, found, "policy 'drop-echo-logs' not found")
	assert.Equal(t, "drop-echo-logs", found.GetName())
	assert.NotNil(t, found.GetLog())
	keep, err := ParseKeep(found.GetLog().GetKeep())
	require.NoError(t, err)
	assert.Equal(t, KeepNone, keep.Action)
	assert.Len(t, found.GetLog().GetMatch(), 1)
}

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

func TestFileProviderWithPollInterval(t *testing.T) {
	// Create a temp file with initial policy
	tmpFile := filepath.Join(t.TempDir(), "policies.json")
	initialContent := `{
		"policies": [{
			"id": "test-policy",
			"name": "Test Policy",
			"log": {
				"match": [{"log_field": "body", "regex": "error"}],
				"keep": "none"
			}
		}]
	}`
	err := os.WriteFile(tmpFile, []byte(initialContent), 0644)
	require.NoError(t, err)

	// Track reload count
	var reloadCount int
	var mu sync.Mutex

	provider := NewFileProvider(tmpFile,
		WithPollInterval(50*time.Millisecond),
		WithOnReload(func() {
			mu.Lock()
			reloadCount++
			mu.Unlock()
		}),
	)
	defer provider.Stop()

	// Track policy updates
	var lastPolicies []*Policy
	err = provider.Subscribe(func(policies []*Policy) {
		mu.Lock()
		lastPolicies = policies
		mu.Unlock()
	})
	require.NoError(t, err)

	// Verify initial load
	mu.Lock()
	assert.Len(t, lastPolicies, 1, "expected 1 policy after initial load")
	assert.Equal(t, "test-policy", lastPolicies[0].GetId())
	mu.Unlock()

	// Wait a bit, then update the file
	time.Sleep(100 * time.Millisecond)

	updatedContent := `{
		"policies": [
			{
				"id": "test-policy",
				"name": "Test Policy",
				"log": {
					"match": [{"log_field": "body", "regex": "error"}],
					"keep": "none"
				}
			},
			{
				"id": "new-policy",
				"name": "New Policy",
				"log": {
					"match": [{"log_field": "body", "regex": "warning"}],
					"keep": "all"
				}
			}
		]
	}`
	err = os.WriteFile(tmpFile, []byte(updatedContent), 0644)
	require.NoError(t, err)

	// Wait for reload to happen
	time.Sleep(150 * time.Millisecond)

	// Verify reload happened
	mu.Lock()
	assert.Greater(t, reloadCount, 0, "expected at least one reload")
	assert.Len(t, lastPolicies, 2, "expected 2 policies after reload")
	mu.Unlock()

	// Stop the provider
	provider.Stop()
}

func TestFileProviderPollIntervalOnError(t *testing.T) {
	// Create a temp file
	tmpFile := filepath.Join(t.TempDir(), "policies.json")
	initialContent := `{
		"policies": [{
			"id": "test-policy",
			"name": "Test Policy",
			"log": {
				"match": [{"log_field": "body", "regex": "error"}],
				"keep": "none"
			}
		}]
	}`
	err := os.WriteFile(tmpFile, []byte(initialContent), 0644)
	require.NoError(t, err)

	// Track errors
	var lastError error
	var mu sync.Mutex

	provider := NewFileProvider(tmpFile,
		WithPollInterval(50*time.Millisecond),
		WithOnError(func(err error) {
			mu.Lock()
			lastError = err
			mu.Unlock()
		}),
	)
	defer provider.Stop()

	err = provider.Subscribe(func(policies []*Policy) {})
	require.NoError(t, err)

	// Wait a bit, then write invalid JSON
	time.Sleep(100 * time.Millisecond)

	err = os.WriteFile(tmpFile, []byte(`{invalid json`), 0644)
	require.NoError(t, err)

	// Wait for error to be detected
	time.Sleep(150 * time.Millisecond)

	mu.Lock()
	assert.NotNil(t, lastError, "expected an error from invalid JSON")
	mu.Unlock()

	provider.Stop()
}

func TestFileProviderStop(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "policies.json")
	content := `{"policies": []}`
	err := os.WriteFile(tmpFile, []byte(content), 0644)
	require.NoError(t, err)

	provider := NewFileProvider(tmpFile, WithPollInterval(10*time.Millisecond))

	err = provider.Subscribe(func(policies []*Policy) {})
	require.NoError(t, err)

	// Stop should not block
	done := make(chan struct{})
	go func() {
		provider.Stop()
		close(done)
	}()

	select {
	case <-done:
		// OK
	case <-time.After(1 * time.Second):
		t.Error("Stop() blocked for too long")
	}
}

func TestFileProviderWithoutPolling(t *testing.T) {
	// Without poll interval, provider should work as before (one-shot load)
	provider := NewFileProvider(filepath.Join("testdata", "policies.json"))

	var called int
	err := provider.Subscribe(func(policies []*Policy) {
		called++
	})
	require.NoError(t, err)

	assert.Equal(t, 1, called, "callback should be called once")

	// Stop should be safe to call even without polling
	provider.Stop()
}
