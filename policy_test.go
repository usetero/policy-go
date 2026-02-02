package policy

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
)

// staticProvider is a simple provider for testing that returns static policies.
type staticProvider struct {
	policies []*policyv1.Policy
}

func newStaticProvider(policies []*policyv1.Policy) *staticProvider {
	return &staticProvider{policies: policies}
}

func (p *staticProvider) Load() ([]*policyv1.Policy, error) {
	return p.policies, nil
}

func (p *staticProvider) Subscribe(callback PolicyCallback) error {
	callback(p.policies)
	return nil
}

func (p *staticProvider) SetStatsCollector(collector StatsCollector) {}

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

func TestEngineEvaluateDropDebugLogs(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := NewFileProvider(filepath.Join("testdata", "policies.json"))

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	// Test log that should be dropped (matches "drop-debug-logs" - body contains BOTH "debug" AND "trace")
	// Note: multiple matchers in a policy are AND'd together
	debugTraceLog := &SimpleLogRecord{
		Body:         []byte("this is a debug trace message"),
		SeverityText: []byte("INFO"),
	}

	result := EvaluateLog(engine, debugTraceLog, SimpleLogMatcher)
	assert.Equal(t, ResultDrop, result)
}

func TestEngineEvaluateDropBySeverity(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := NewFileProvider(filepath.Join("testdata", "policies.json"))

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	// Test log that should be dropped (matches "drop-debug-level" - severity_text is DEBUG)
	debugLog := &SimpleLogRecord{
		Body:         []byte("some normal message"),
		SeverityText: []byte("DEBUG"),
	}

	result := EvaluateLog(engine, debugLog, SimpleLogMatcher)
	assert.Equal(t, ResultDrop, result)
}

func TestEngineEvaluateNoMatch(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := NewFileProvider(filepath.Join("testdata", "policies.json"))

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	// Test log that doesn't match any policy:
	// - Contains "debug" so it fails the "keep-non-debug-non-trace" negated policy
	// - Doesn't contain "trace" so it fails the "drop-debug-logs" AND policy (needs both)
	// - Severity is INFO so it doesn't match "drop-debug-level"
	// - No log attributes or resource attributes to match other policies
	debugOnlyLog := &SimpleLogRecord{
		Body:         []byte("debug only message"),
		SeverityText: []byte("INFO"),
	}

	result := EvaluateLog(engine, debugOnlyLog, SimpleLogMatcher)
	assert.Equal(t, ResultNoMatch, result)
}

func TestEngineEvaluateDropByLogAttribute(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := NewFileProvider(filepath.Join("testdata", "policies.json"))

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	// Test log that should be dropped (matches "drop-echo-logs" - log_attribute ddsource=nginx)
	nginxLog := &SimpleLogRecord{
		Body:         []byte("GET /api/health 200"),
		SeverityText: []byte("INFO"),
		LogAttributes: map[string]any{
			"ddsource": "nginx",
		},
	}

	result := EvaluateLog(engine, nginxLog, SimpleLogMatcher)
	assert.Equal(t, ResultDrop, result)
}

func TestEngineEvaluateDropByResourceAttribute(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := NewFileProvider(filepath.Join("testdata", "policies.json"))

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	// Test log that should be dropped (matches "drop-edge-logs" - service.name ends with "edge")
	edgeLog := &SimpleLogRecord{
		Body:         []byte("processing request"),
		SeverityText: []byte("INFO"),
		ResourceAttributes: map[string]any{
			"service.name": "api-edge",
		},
	}

	result := EvaluateLog(engine, edgeLog, SimpleLogMatcher)
	assert.Equal(t, ResultDrop, result)
}

func TestEngineEvaluateAllNegatedMatchersPass(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := NewFileProvider(filepath.Join("testdata", "policies.json"))

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	// Test log that should match "keep-non-debug-non-trace" policy
	// which has ALL negated matchers:
	// - body NOT contains "debug" (negated)
	// - severity_text NOT contains "TRACE" (negated)
	// This log has neither, so all negated conditions are satisfied
	normalLog := &SimpleLogRecord{
		Body:         []byte("normal application message"),
		SeverityText: []byte("INFO"),
	}

	result := EvaluateLog(engine, normalLog, SimpleLogMatcher)
	assert.Equal(t, ResultKeep, result, "all negated matchers should pass")
}

func TestEngineEvaluateAllNegatedMatchersFailOne(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := NewFileProvider(filepath.Join("testdata", "policies.json"))

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	// Test log that should NOT match "keep-non-debug-non-trace" policy
	// because body contains "debug" (fails the negated matcher)
	debugLog := &SimpleLogRecord{
		Body:         []byte("this is a debug message"),
		SeverityText: []byte("INFO"),
	}

	result := EvaluateLog(engine, debugLog, SimpleLogMatcher)
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

	engine := NewPolicyEngine(registry)

	// Test log that fails BOTH negated matchers:
	// - body contains "debug" (fails negated)
	// - severity_text is "TRACE" (fails negated)
	traceDebugLog := &SimpleLogRecord{
		Body:         []byte("debug information here"),
		SeverityText: []byte("TRACE"),
	}

	result := EvaluateLog(engine, traceDebugLog, SimpleLogMatcher)
	// Should NOT match the all-negated policy
	assert.NotEqual(t, ResultKeep, result, "both negated matchers should fail")
}

func TestStatsCollection(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := NewFileProvider(filepath.Join("testdata", "policies.json"))

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	// Evaluate a log that matches drop-debug-level (severity_text = DEBUG)
	debugLog := &SimpleLogRecord{
		Body:         []byte("some message"),
		SeverityText: []byte("DEBUG"),
	}

	EvaluateLog(engine, debugLog, SimpleLogMatcher)

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

func TestSamplingWithSampleKey(t *testing.T) {
	// Create a policy with 50% sampling using trace_id as the sample key
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "sample-policy",
			Name: "Sample Policy",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Contains{Contains: "test"},
						},
					},
					Keep: "50%",
					SampleKey: &policyv1.LogSampleKey{
						Field: &policyv1.LogSampleKey_LogField{LogField: policyv1.LogField_LOG_FIELD_TRACE_ID},
					},
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	// Test that the same trace_id always produces the same result (deterministic)
	traceID1 := []byte("trace-id-abc123")
	traceID2 := []byte("trace-id-xyz789")

	record1 := &SimpleLogRecord{
		Body:    []byte("test message"),
		TraceID: traceID1,
	}
	record2 := &SimpleLogRecord{
		Body:    []byte("test message"),
		TraceID: traceID2,
	}

	// Run multiple times to verify determinism
	result1a := EvaluateLog(engine, record1, SimpleLogMatcher)
	result1b := EvaluateLog(engine, record1, SimpleLogMatcher)
	result1c := EvaluateLog(engine, record1, SimpleLogMatcher)

	result2a := EvaluateLog(engine, record2, SimpleLogMatcher)
	result2b := EvaluateLog(engine, record2, SimpleLogMatcher)
	result2c := EvaluateLog(engine, record2, SimpleLogMatcher)

	// Same trace_id should always produce the same result
	assert.Equal(t, result1a, result1b, "same trace_id should produce consistent result")
	assert.Equal(t, result1b, result1c, "same trace_id should produce consistent result")
	assert.Equal(t, result2a, result2b, "same trace_id should produce consistent result")
	assert.Equal(t, result2b, result2c, "same trace_id should produce consistent result")
}

func TestSamplingDistribution(t *testing.T) {
	// Test that sampling roughly follows the expected distribution
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "sample-policy",
			Name: "Sample Policy",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Contains{Contains: "test"},
						},
					},
					Keep: "50%",
					SampleKey: &policyv1.LogSampleKey{
						Field: &policyv1.LogSampleKey_LogAttribute{
							LogAttribute: &policyv1.AttributePath{Path: []string{"request_id"}},
						},
					},
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	// Test with many different request IDs
	kept := 0
	dropped := 0
	total := 1000

	for i := 0; i < total; i++ {
		record := &SimpleLogRecord{
			Body: []byte("test message"),
			LogAttributes: map[string]any{
				"request_id": string(rune('a'+i%26)) + string(rune('0'+i%10)) + string(rune(i)),
			},
		}
		result := EvaluateLog(engine, record, SimpleLogMatcher)
		if result == ResultKeep {
			kept++
		} else if result == ResultDrop {
			dropped++
		}
	}

	// With 50% sampling, we expect roughly 50% kept
	// Allow 15% tolerance for statistical variation
	keepRate := float64(kept) / float64(total) * 100
	assert.InDelta(t, 50.0, keepRate, 15.0, "sampling rate should be roughly 50%% (got %.1f%%)", keepRate)
}

func TestSamplingWithoutSampleKey(t *testing.T) {
	// When no sample key is configured but field is empty, should keep
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "sample-policy",
			Name: "Sample Policy",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Contains{Contains: "test"},
						},
					},
					Keep: "50%",
					SampleKey: &policyv1.LogSampleKey{
						Field: &policyv1.LogSampleKey_LogField{LogField: policyv1.LogField_LOG_FIELD_TRACE_ID},
					},
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	// Record without trace_id - should be kept (fallback behavior)
	record := &SimpleLogRecord{
		Body: []byte("test message"),
		// No TraceID set
	}

	result := EvaluateLog(engine, record, SimpleLogMatcher)
	assert.Equal(t, ResultKeep, result, "record without sample key value should be kept")
}

func TestSampling100Percent(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "sample-policy",
			Name: "Sample Policy",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Contains{Contains: "test"},
						},
					},
					Keep: "100%",
					SampleKey: &policyv1.LogSampleKey{
						Field: &policyv1.LogSampleKey_LogField{LogField: policyv1.LogField_LOG_FIELD_TRACE_ID},
					},
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	// All records should be kept with 100% sampling
	for i := 0; i < 100; i++ {
		record := &SimpleLogRecord{
			Body:    []byte("test message"),
			TraceID: []byte("trace-" + string(rune('a'+i))),
		}
		result := EvaluateLog(engine, record, SimpleLogMatcher)
		assert.Equal(t, ResultKeep, result, "100%% sampling should keep all records")
	}
}

func TestSampling0Percent(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{
		{
			Id:   "sample-policy",
			Name: "Sample Policy",
			Target: &policyv1.Policy_Log{
				Log: &policyv1.LogTarget{
					Match: []*policyv1.LogMatcher{
						{
							Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
							Match: &policyv1.LogMatcher_Contains{Contains: "test"},
						},
					},
					Keep: "0%",
					SampleKey: &policyv1.LogSampleKey{
						Field: &policyv1.LogSampleKey_LogField{LogField: policyv1.LogField_LOG_FIELD_TRACE_ID},
					},
				},
			},
		},
	})

	_, err := registry.Register(provider)
	require.NoError(t, err)

	engine := NewPolicyEngine(registry)

	// All records should be dropped with 0% sampling
	for i := 0; i < 100; i++ {
		record := &SimpleLogRecord{
			Body:    []byte("test message"),
			TraceID: []byte("trace-" + string(rune('a'+i))),
		}
		result := EvaluateLog(engine, record, SimpleLogMatcher)
		assert.Equal(t, ResultDrop, result, "0%% sampling should drop all records")
	}
}
