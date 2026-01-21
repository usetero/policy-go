package policy

import (
	"path/filepath"
	"testing"
)

func TestVersion(t *testing.T) {
	v := Version()
	if v == "" {
		t.Error("Version() returned empty string")
	}
	if v != "0.1.0" {
		t.Errorf("Version() = %q, want %q", v, "0.1.0")
	}
}

func TestFileProviderLoad(t *testing.T) {
	provider := NewFileProvider(filepath.Join("testdata", "policies.json"))
	policies, err := provider.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// We have 6 log policies in the test file
	logPolicies := 0
	for _, p := range policies {
		if p.IsLogPolicy() {
			logPolicies++
		}
	}

	if logPolicies != 6 {
		t.Errorf("got %d log policies, want 6", logPolicies)
	}

	// Check first policy
	found := false
	for _, p := range policies {
		if p.ID == "drop-echo-logs" {
			found = true
			if p.Name != "drop-echo-logs" {
				t.Errorf("policy name = %q, want %q", p.Name, "drop-echo-logs")
			}
			if !p.IsLogPolicy() {
				t.Error("expected log policy")
			}
			if p.Log.Keep.Action != KeepNone {
				t.Errorf("keep action = %v, want KeepNone", p.Log.Keep.Action)
			}
			if len(p.Log.Matchers) != 1 {
				t.Errorf("got %d matchers, want 1", len(p.Log.Matchers))
			}
			break
		}
	}
	if !found {
		t.Error("policy 'drop-echo-logs' not found")
	}
}

func TestRegistryAndSnapshot(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := NewFileProvider(filepath.Join("testdata", "policies.json"))

	handle, err := registry.Register(provider)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	defer handle.Unregister()

	snapshot := registry.Snapshot()
	if snapshot == nil {
		t.Fatal("Snapshot() returned nil")
	}
	defer snapshot.Release()

	// Check that we can iterate over policies
	count := 0
	for id, p := range snapshot.Iter() {
		if id == "" {
			t.Error("policy ID is empty")
		}
		if p == nil {
			t.Error("policy is nil")
		}
		count++
	}

	if count == 0 {
		t.Error("no policies in snapshot")
	}
}

func TestEngineEvaluateDropDebugLogs(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := NewFileProvider(filepath.Join("testdata", "policies.json"))

	_, err := registry.Register(provider)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	snapshot := registry.Snapshot()
	if snapshot == nil {
		t.Fatal("Snapshot() returned nil")
	}
	defer snapshot.Release()

	engine := NewPolicyEngine()

	// Test log that should be dropped (matches "drop-debug-logs" - body contains BOTH "debug" AND "trace")
	// Note: multiple matchers in a policy are AND'd together
	debugTraceLog := &SimpleLogRecord{
		BodyValue:         []byte("this is a debug trace message"),
		SeverityTextValue: []byte("INFO"),
	}

	result := engine.Evaluate(snapshot, debugTraceLog)
	if result != ResultDrop {
		t.Errorf("Evaluate() = %v, want ResultDrop", result)
	}
}

func TestEngineEvaluateDropBySeverity(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := NewFileProvider(filepath.Join("testdata", "policies.json"))

	_, err := registry.Register(provider)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	snapshot := registry.Snapshot()
	if snapshot == nil {
		t.Fatal("Snapshot() returned nil")
	}
	defer snapshot.Release()

	engine := NewPolicyEngine()

	// Test log that should be dropped (matches "drop-debug-level" - severity_text is DEBUG)
	debugLog := &SimpleLogRecord{
		BodyValue:         []byte("some normal message"),
		SeverityTextValue: []byte("DEBUG"),
	}

	result := engine.Evaluate(snapshot, debugLog)
	if result != ResultDrop {
		t.Errorf("Evaluate() = %v, want ResultDrop", result)
	}
}

func TestEngineEvaluateNoMatch(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := NewFileProvider(filepath.Join("testdata", "policies.json"))

	_, err := registry.Register(provider)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	snapshot := registry.Snapshot()
	if snapshot == nil {
		t.Fatal("Snapshot() returned nil")
	}
	defer snapshot.Release()

	engine := NewPolicyEngine()

	// Test log that doesn't match any policy
	normalLog := &SimpleLogRecord{
		BodyValue:         []byte("normal application log"),
		SeverityTextValue: []byte("INFO"),
	}

	result := engine.Evaluate(snapshot, normalLog)
	if result != ResultNoMatch {
		t.Errorf("Evaluate() = %v, want ResultNoMatch", result)
	}
}

func TestEngineEvaluateDropByLogAttribute(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := NewFileProvider(filepath.Join("testdata", "policies.json"))

	_, err := registry.Register(provider)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	snapshot := registry.Snapshot()
	if snapshot == nil {
		t.Fatal("Snapshot() returned nil")
	}
	defer snapshot.Release()

	engine := NewPolicyEngine()

	// Test log that should be dropped (matches "drop-echo-logs" - log_attribute ddsource=nginx)
	nginxLog := &SimpleLogRecord{
		BodyValue:         []byte("GET /api/health 200"),
		SeverityTextValue: []byte("INFO"),
		LogAttributes: map[string][]byte{
			"ddsource": []byte("nginx"),
		},
	}

	result := engine.Evaluate(snapshot, nginxLog)
	if result != ResultDrop {
		t.Errorf("Evaluate() = %v, want ResultDrop", result)
	}
}

func TestEngineEvaluateDropByResourceAttribute(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := NewFileProvider(filepath.Join("testdata", "policies.json"))

	_, err := registry.Register(provider)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	snapshot := registry.Snapshot()
	if snapshot == nil {
		t.Fatal("Snapshot() returned nil")
	}
	defer snapshot.Release()

	engine := NewPolicyEngine()

	// Test log that should be dropped (matches "drop-edge-logs" - service.name ends with "edge")
	edgeLog := &SimpleLogRecord{
		BodyValue:         []byte("processing request"),
		SeverityTextValue: []byte("INFO"),
		ResourceAttributes: map[string][]byte{
			"service.name": []byte("api-edge"),
		},
	}

	result := engine.Evaluate(snapshot, edgeLog)
	if result != ResultDrop {
		t.Errorf("Evaluate() = %v, want ResultDrop", result)
	}
}

func TestStatsCollection(t *testing.T) {
	registry := NewPolicyRegistry()
	provider := NewFileProvider(filepath.Join("testdata", "policies.json"))

	_, err := registry.Register(provider)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	snapshot := registry.Snapshot()
	if snapshot == nil {
		t.Fatal("Snapshot() returned nil")
	}
	defer snapshot.Release()

	engine := NewPolicyEngine()

	// Evaluate a log that matches drop-debug-level (severity_text = DEBUG)
	debugLog := &SimpleLogRecord{
		BodyValue:         []byte("some message"),
		SeverityTextValue: []byte("DEBUG"),
	}

	engine.Evaluate(snapshot, debugLog)

	// Collect stats
	stats := registry.CollectStats()
	if len(stats) == 0 {
		t.Fatal("CollectStats() returned empty")
	}

	// Find stats for drop-debug-level
	found := false
	for _, s := range stats {
		if s.PolicyID == "drop-debug-level" {
			found = true
			if s.Hits == 0 {
				t.Error("expected hits > 0 for drop-debug-level")
			}
			if s.Drops == 0 {
				t.Error("expected drops > 0 for drop-debug-level")
			}
			break
		}
	}
	if !found {
		t.Error("stats for 'drop-debug-level' not found")
	}
}
