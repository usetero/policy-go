package bench

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/usetero/policy-go"
	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
)

// BenchLogRecord implements policy.LogMatchable for benchmarking.
type BenchLogRecord struct {
	Body               []byte
	SeverityText       []byte
	LogAttributes      map[string][]byte
	ResourceAttributes map[string][]byte
	ScopeAttributes    map[string][]byte
}

func (r *BenchLogRecord) GetField(field policyv1.LogField) []byte {
	switch field {
	case policyv1.LogField_LOG_FIELD_BODY:
		return r.Body
	case policyv1.LogField_LOG_FIELD_SEVERITY_TEXT:
		return r.SeverityText
	default:
		return nil
	}
}

func (r *BenchLogRecord) GetAttribute(scope policy.AttrScope, name string) []byte {
	switch scope {
	case policy.AttrScopeResource:
		return r.ResourceAttributes[name]
	case policy.AttrScopeScope:
		return r.ScopeAttributes[name]
	case policy.AttrScopeRecord:
		return r.LogAttributes[name]
	default:
		return nil
	}
}

// setupBenchmark creates a registry with policies loaded from testdata.
func setupBenchmark(b *testing.B) (*policy.PolicyRegistry, *policy.PolicySnapshot, *policy.PolicyEngine) {
	b.Helper()

	registry := policy.NewPolicyRegistry()
	provider := policy.NewFileProvider(filepath.Join("..", "testdata", "policies.json"))

	_, err := registry.Register(provider)
	if err != nil {
		b.Fatalf("Failed to register provider: %v", err)
	}

	snapshot := registry.Snapshot()
	if snapshot == nil {
		b.Fatal("Snapshot() returned nil")
	}

	engine := policy.NewPolicyEngine()

	return registry, snapshot, engine
}

// BenchmarkEvaluateNoMatch benchmarks evaluation when no policy matches.
func BenchmarkEvaluateNoMatch(b *testing.B) {
	_, snapshot, engine := setupBenchmark(b)

	record := &BenchLogRecord{
		Body:         []byte("normal application log message"),
		SeverityText: []byte("INFO"),
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		engine.Evaluate(snapshot, record)
	}
}

// BenchmarkEvaluateMatchBody benchmarks evaluation matching on body field.
func BenchmarkEvaluateMatchBody(b *testing.B) {
	_, snapshot, engine := setupBenchmark(b)

	// Matches "drop-debug-logs" policy (body contains "debug" AND "trace")
	record := &BenchLogRecord{
		Body:         []byte("this is a debug trace message"),
		SeverityText: []byte("INFO"),
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		engine.Evaluate(snapshot, record)
	}
}

// BenchmarkEvaluateMatchSeverity benchmarks evaluation matching on severity_text.
func BenchmarkEvaluateMatchSeverity(b *testing.B) {
	_, snapshot, engine := setupBenchmark(b)

	// Matches "drop-debug-level" policy (severity_text = DEBUG)
	record := &BenchLogRecord{
		Body:         []byte("some normal message"),
		SeverityText: []byte("DEBUG"),
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		engine.Evaluate(snapshot, record)
	}
}

// BenchmarkEvaluateMatchLogAttribute benchmarks evaluation matching on log attribute.
func BenchmarkEvaluateMatchLogAttribute(b *testing.B) {
	_, snapshot, engine := setupBenchmark(b)

	// Matches "drop-echo-logs" policy (ddsource = nginx)
	record := &BenchLogRecord{
		Body:         []byte("GET /api/health 200"),
		SeverityText: []byte("INFO"),
		LogAttributes: map[string][]byte{
			"ddsource": []byte("nginx"),
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		engine.Evaluate(snapshot, record)
	}
}

// BenchmarkEvaluateMatchResourceAttribute benchmarks evaluation matching on resource attribute.
func BenchmarkEvaluateMatchResourceAttribute(b *testing.B) {
	_, snapshot, engine := setupBenchmark(b)

	// Matches "drop-edge-logs" policy (service.name ends with "edge")
	record := &BenchLogRecord{
		Body:         []byte("processing request"),
		SeverityText: []byte("INFO"),
		ResourceAttributes: map[string][]byte{
			"service.name": []byte("api-edge"),
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		engine.Evaluate(snapshot, record)
	}
}

// BenchmarkEvaluateParallel benchmarks parallel evaluation.
func BenchmarkEvaluateParallel(b *testing.B) {
	_, snapshot, engine := setupBenchmark(b)

	record := &BenchLogRecord{
		Body:         []byte("this is a debug trace message"),
		SeverityText: []byte("INFO"),
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			engine.Evaluate(snapshot, record)
		}
	})
}

// BenchmarkCompile benchmarks policy compilation.
func BenchmarkCompile(b *testing.B) {
	provider := policy.NewFileProvider(filepath.Join("..", "testdata", "policies.json"))
	policies, err := provider.Load()
	if err != nil {
		b.Fatalf("Failed to load policies: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		registry := policy.NewPolicyRegistry()
		provider := policy.NewFileProvider(filepath.Join("..", "testdata", "policies.json"))
		_, err := registry.Register(provider)
		if err != nil {
			b.Fatalf("Failed to register provider: %v", err)
		}
		_ = registry.Snapshot()
	}

	_ = policies // silence unused warning
}

// BenchmarkLoadPolicies benchmarks JSON policy file loading.
func BenchmarkLoadPolicies(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		provider := policy.NewFileProvider(filepath.Join("..", "testdata", "policies.json"))
		_, err := provider.Load()
		if err != nil {
			b.Fatalf("Failed to load policies: %v", err)
		}
	}
}

// BenchmarkEvaluateMixedWorkload benchmarks a mixed workload of different log types.
func BenchmarkEvaluateMixedWorkload(b *testing.B) {
	_, snapshot, engine := setupBenchmark(b)

	records := []*BenchLogRecord{
		// No match
		{Body: []byte("normal log"), SeverityText: []byte("INFO")},
		// Match body
		{Body: []byte("debug trace message"), SeverityText: []byte("INFO")},
		// Match severity
		{Body: []byte("some message"), SeverityText: []byte("DEBUG")},
		// Match log attribute
		{Body: []byte("request"), SeverityText: []byte("INFO"), LogAttributes: map[string][]byte{"ddsource": []byte("nginx")}},
		// Match resource attribute
		{Body: []byte("request"), SeverityText: []byte("INFO"), ResourceAttributes: map[string][]byte{"service.name": []byte("edge")}},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		for _, record := range records {
			engine.Evaluate(snapshot, record)
		}
	}
}

// BenchmarkSnapshotGetPolicy benchmarks snapshot policy lookup.
func BenchmarkSnapshotGetPolicy(b *testing.B) {
	_, snapshot, _ := setupBenchmark(b)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		snapshot.GetPolicy("drop-debug-logs")
	}
}

// BenchmarkStatsCollection benchmarks stats collection.
func BenchmarkStatsCollection(b *testing.B) {
	registry, snapshot, engine := setupBenchmark(b)

	// Generate some hits first
	record := &BenchLogRecord{
		Body:         []byte("debug trace message"),
		SeverityText: []byte("INFO"),
	}
	for i := 0; i < 1000; i++ {
		engine.Evaluate(snapshot, record)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		registry.CollectStats()
	}
}

// BenchmarkEvaluateLongBody benchmarks evaluation with a long body.
func BenchmarkEvaluateLongBody(b *testing.B) {
	_, snapshot, engine := setupBenchmark(b)

	// Create a long body with the pattern at the end
	longBody := make([]byte, 10000)
	for i := range longBody {
		longBody[i] = 'x'
	}
	copy(longBody[len(longBody)-20:], []byte("debug trace message"))

	record := &BenchLogRecord{
		Body:         longBody,
		SeverityText: []byte("INFO"),
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		engine.Evaluate(snapshot, record)
	}
}

// BenchmarkEvaluateWithManyAttributes benchmarks evaluation with many attributes.
func BenchmarkEvaluateWithManyAttributes(b *testing.B) {
	_, snapshot, engine := setupBenchmark(b)

	// Create a record with many attributes
	logAttrs := make(map[string][]byte)
	resourceAttrs := make(map[string][]byte)
	for i := 0; i < 50; i++ {
		logAttrs[fmt.Sprintf("attr_%d", i)] = []byte(fmt.Sprintf("value_%d", i))
		resourceAttrs[fmt.Sprintf("resource_%d", i)] = []byte(fmt.Sprintf("value_%d", i))
	}
	// Add the matching attribute
	logAttrs["ddsource"] = []byte("nginx")

	record := &BenchLogRecord{
		Body:               []byte("request processed"),
		SeverityText:       []byte("INFO"),
		LogAttributes:      logAttrs,
		ResourceAttributes: resourceAttrs,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		engine.Evaluate(snapshot, record)
	}
}
