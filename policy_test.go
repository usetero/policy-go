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

	// We have 7 log policies in the test file
	logPolicies := 0
	for _, p := range policies {
		if p.GetLog() != nil {
			logPolicies++
		}
	}

	assert.Equal(t, 7, logPolicies, "expected 7 log policies")

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

func TestEngineEvaluateDropDebugLogs(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := NewFileProvider(filepath.Join("testdata", "policies.json"))

	_, err := registry.Register(provider)
	require.NoError(t, err)

	snapshot := registry.Snapshot()
	require.NotNil(t, snapshot)

	engine := NewPolicyEngine()

	// Test log that should be dropped (matches "drop-debug-logs" - body contains BOTH "debug" AND "trace")
	// Note: multiple matchers in a policy are AND'd together
	debugTraceLog := &SimpleLogRecord{
		Body:         []byte("this is a debug trace message"),
		SeverityText: []byte("INFO"),
	}

	result := engine.Evaluate(snapshot, debugTraceLog)
	assert.Equal(t, ResultDrop, result)
}

func TestEngineEvaluateDropBySeverity(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := NewFileProvider(filepath.Join("testdata", "policies.json"))

	_, err := registry.Register(provider)
	require.NoError(t, err)

	snapshot := registry.Snapshot()
	require.NotNil(t, snapshot)

	engine := NewPolicyEngine()

	// Test log that should be dropped (matches "drop-debug-level" - severity_text is DEBUG)
	debugLog := &SimpleLogRecord{
		Body:         []byte("some normal message"),
		SeverityText: []byte("DEBUG"),
	}

	result := engine.Evaluate(snapshot, debugLog)
	assert.Equal(t, ResultDrop, result)
}

func TestEngineEvaluateNoMatch(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := NewFileProvider(filepath.Join("testdata", "policies.json"))

	_, err := registry.Register(provider)
	require.NoError(t, err)

	snapshot := registry.Snapshot()
	require.NotNil(t, snapshot)

	engine := NewPolicyEngine()

	// Test log that doesn't match any policy:
	// - Contains "debug" so it fails the "keep-non-debug-non-trace" negated policy
	// - Doesn't contain "trace" so it fails the "drop-debug-logs" AND policy (needs both)
	// - Severity is INFO so it doesn't match "drop-debug-level"
	// - No log attributes or resource attributes to match other policies
	debugOnlyLog := &SimpleLogRecord{
		Body:         []byte("debug only message"),
		SeverityText: []byte("INFO"),
	}

	result := engine.Evaluate(snapshot, debugOnlyLog)
	assert.Equal(t, ResultNoMatch, result)
}

func TestEngineEvaluateDropByLogAttribute(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := NewFileProvider(filepath.Join("testdata", "policies.json"))

	_, err := registry.Register(provider)
	require.NoError(t, err)

	snapshot := registry.Snapshot()
	require.NotNil(t, snapshot)

	engine := NewPolicyEngine()

	// Test log that should be dropped (matches "drop-echo-logs" - log_attribute ddsource=nginx)
	nginxLog := &SimpleLogRecord{
		Body:         []byte("GET /api/health 200"),
		SeverityText: []byte("INFO"),
		LogAttributes: map[string]any{
			"ddsource": "nginx",
		},
	}

	result := engine.Evaluate(snapshot, nginxLog)
	assert.Equal(t, ResultDrop, result)
}

func TestEngineEvaluateDropByResourceAttribute(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := NewFileProvider(filepath.Join("testdata", "policies.json"))

	_, err := registry.Register(provider)
	require.NoError(t, err)

	snapshot := registry.Snapshot()
	require.NotNil(t, snapshot)

	engine := NewPolicyEngine()

	// Test log that should be dropped (matches "drop-edge-logs" - service.name ends with "edge")
	edgeLog := &SimpleLogRecord{
		Body:         []byte("processing request"),
		SeverityText: []byte("INFO"),
		ResourceAttributes: map[string]any{
			"service.name": "api-edge",
		},
	}

	result := engine.Evaluate(snapshot, edgeLog)
	assert.Equal(t, ResultDrop, result)
}

func TestEngineEvaluateAllNegatedMatchersPass(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := NewFileProvider(filepath.Join("testdata", "policies.json"))

	_, err := registry.Register(provider)
	require.NoError(t, err)

	snapshot := registry.Snapshot()
	require.NotNil(t, snapshot)

	engine := NewPolicyEngine()

	// Test log that should match "keep-non-debug-non-trace" policy
	// which has ALL negated matchers:
	// - body NOT contains "debug" (negated)
	// - severity_text NOT contains "TRACE" (negated)
	// This log has neither, so all negated conditions are satisfied
	normalLog := &SimpleLogRecord{
		Body:         []byte("normal application message"),
		SeverityText: []byte("INFO"),
	}

	result := engine.Evaluate(snapshot, normalLog)
	assert.Equal(t, ResultKeep, result, "all negated matchers should pass")
}

func TestEngineEvaluateAllNegatedMatchersFailOne(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := NewFileProvider(filepath.Join("testdata", "policies.json"))

	_, err := registry.Register(provider)
	require.NoError(t, err)

	snapshot := registry.Snapshot()
	require.NotNil(t, snapshot)

	engine := NewPolicyEngine()

	// Test log that should NOT match "keep-non-debug-non-trace" policy
	// because body contains "debug" (fails the negated matcher)
	debugLog := &SimpleLogRecord{
		Body:         []byte("this is a debug message"),
		SeverityText: []byte("INFO"),
	}

	result := engine.Evaluate(snapshot, debugLog)
	// Should either be no match or match a different policy (like drop-debug-logs if it has trace too)
	// Since this log only has "debug" but not "trace", it won't match drop-debug-logs either
	// So it should be no match (the negated policy fails, no other policy matches)
	assert.NotEqual(t, ResultKeep, result, "negated body matcher should fail")
}

func TestEngineEvaluateAllNegatedMatchersFailBoth(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := NewFileProvider(filepath.Join("testdata", "policies.json"))

	_, err := registry.Register(provider)
	require.NoError(t, err)

	snapshot := registry.Snapshot()
	require.NotNil(t, snapshot)

	engine := NewPolicyEngine()

	// Test log that fails BOTH negated matchers:
	// - body contains "debug" (fails negated)
	// - severity_text is "TRACE" (fails negated)
	traceDebugLog := &SimpleLogRecord{
		Body:         []byte("debug information here"),
		SeverityText: []byte("TRACE"),
	}

	result := engine.Evaluate(snapshot, traceDebugLog)
	// Should NOT match the all-negated policy
	assert.NotEqual(t, ResultKeep, result, "both negated matchers should fail")
}

func TestStatsCollection(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := NewFileProvider(filepath.Join("testdata", "policies.json"))

	_, err := registry.Register(provider)
	require.NoError(t, err)

	snapshot := registry.Snapshot()
	require.NotNil(t, snapshot)

	engine := NewPolicyEngine()

	// Evaluate a log that matches drop-debug-level (severity_text = DEBUG)
	debugLog := &SimpleLogRecord{
		Body:         []byte("some message"),
		SeverityText: []byte("DEBUG"),
	}

	engine.Evaluate(snapshot, debugLog)

	// Collect stats
	stats := registry.CollectStats()
	require.NotEmpty(t, stats)

	// Find stats for drop-debug-level
	var found *PolicyStatsSnapshot
	for _, s := range stats {
		if s.PolicyID == "drop-debug-level" {
			found = &s
			break
		}
	}
	require.NotNil(t, found, "stats for 'drop-debug-level' not found")
	assert.Greater(t, found.Hits, uint64(0), "expected hits > 0")
	assert.Greater(t, found.Drops, uint64(0), "expected drops > 0")
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
