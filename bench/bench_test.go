package bench

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/usetero/policy-go"
)

// BenchLogRecord is a log record for benchmarking.
type BenchLogRecord struct {
	Body               []byte
	SeverityText       []byte
	LogAttributes      map[string]any
	ResourceAttributes map[string]any
	ScopeAttributes    map[string]any
}

// BenchLogMatcher is the LogMatchFunc implementation for BenchLogRecord.
func BenchLogMatcher(r *BenchLogRecord, ref policy.LogFieldRef) []byte {
	if ref.IsField() {
		switch ref.Field {
		case policy.LogFieldBody:
			return r.Body
		case policy.LogFieldSeverityText:
			return r.SeverityText
		default:
			return nil
		}
	}

	// Attribute lookup
	var attrs map[string]any
	switch {
	case ref.IsRecordAttr():
		attrs = r.LogAttributes
	case ref.IsResourceAttr():
		attrs = r.ResourceAttributes
	case ref.IsScopeAttr():
		attrs = r.ScopeAttributes
	default:
		return nil
	}
	return traversePath(attrs, ref.AttrPath)
}

func traversePath(m map[string]any, path []string) []byte {
	if len(path) == 0 || m == nil {
		return nil
	}
	val, ok := m[path[0]]
	if !ok {
		return nil
	}
	if len(path) == 1 {
		switch v := val.(type) {
		case []byte:
			return v
		case string:
			return []byte(v)
		default:
			return nil
		}
	}
	nested, ok := val.(map[string]any)
	if !ok {
		return nil
	}
	return traversePath(nested, path[1:])
}

// setupBenchmark creates a registry with policies loaded from testdata.
func setupBenchmark(b *testing.B) (*policy.PolicyRegistry, *policy.PolicyEngine) {
	b.Helper()

	registry := policy.NewPolicyRegistry()
	provider := policy.NewFileProvider(filepath.Join("..", "testdata", "policies.json"))

	_, err := registry.Register(provider)
	if err != nil {
		b.Fatalf("Failed to register provider: %v", err)
	}

	engine := policy.NewPolicyEngine(registry)

	return registry, engine
}

// BenchmarkEvaluateNoMatch benchmarks evaluation when no policy matches.
func BenchmarkEvaluateNoMatch(b *testing.B) {
	_, engine := setupBenchmark(b)

	record := &BenchLogRecord{
		Body:         []byte("normal application log message"),
		SeverityText: []byte("INFO"),
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		policy.EvaluateLog(engine, record, BenchLogMatcher)
	}
}

// BenchmarkEvaluateMatchBody benchmarks evaluation matching on body field.
func BenchmarkEvaluateMatchBody(b *testing.B) {
	_, engine := setupBenchmark(b)

	// Matches "drop-debug-logs" policy (body contains "debug" AND "trace")
	record := &BenchLogRecord{
		Body:         []byte("this is a debug trace message"),
		SeverityText: []byte("INFO"),
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		policy.EvaluateLog(engine, record, BenchLogMatcher)
	}
}

// BenchmarkEvaluateMatchSeverity benchmarks evaluation matching on severity_text.
func BenchmarkEvaluateMatchSeverity(b *testing.B) {
	_, engine := setupBenchmark(b)

	// Matches "drop-debug-level" policy (severity_text = DEBUG)
	record := &BenchLogRecord{
		Body:         []byte("some normal message"),
		SeverityText: []byte("DEBUG"),
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		policy.EvaluateLog(engine, record, BenchLogMatcher)
	}
}

// BenchmarkEvaluateMatchLogAttribute benchmarks evaluation matching on log attribute.
func BenchmarkEvaluateMatchLogAttribute(b *testing.B) {
	_, engine := setupBenchmark(b)

	// Matches "drop-echo-logs" policy (ddsource = nginx)
	record := &BenchLogRecord{
		Body:         []byte("GET /api/health 200"),
		SeverityText: []byte("INFO"),
		LogAttributes: map[string]any{
			"ddsource": "nginx",
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		policy.EvaluateLog(engine, record, BenchLogMatcher)
	}
}

// BenchmarkEvaluateMatchResourceAttribute benchmarks evaluation matching on resource attribute.
func BenchmarkEvaluateMatchResourceAttribute(b *testing.B) {
	_, engine := setupBenchmark(b)

	// Matches "drop-edge-logs" policy (service.name ends with "edge")
	record := &BenchLogRecord{
		Body:         []byte("processing request"),
		SeverityText: []byte("INFO"),
		ResourceAttributes: map[string]any{
			"service.name": "api-edge",
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		policy.EvaluateLog(engine, record, BenchLogMatcher)
	}
}

// BenchmarkEvaluateParallel benchmarks parallel evaluation.
func BenchmarkEvaluateParallel(b *testing.B) {
	_, engine := setupBenchmark(b)

	record := &BenchLogRecord{
		Body:         []byte("this is a debug trace message"),
		SeverityText: []byte("INFO"),
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			policy.EvaluateLog(engine, record, BenchLogMatcher)
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
	_, engine := setupBenchmark(b)

	records := []*BenchLogRecord{
		// No match
		{Body: []byte("normal log"), SeverityText: []byte("INFO")},
		// Match body
		{Body: []byte("debug trace message"), SeverityText: []byte("INFO")},
		// Match severity
		{Body: []byte("some message"), SeverityText: []byte("DEBUG")},
		// Match log attribute
		{Body: []byte("request"), SeverityText: []byte("INFO"), LogAttributes: map[string]any{"ddsource": "nginx"}},
		// Match resource attribute
		{Body: []byte("request"), SeverityText: []byte("INFO"), ResourceAttributes: map[string]any{"service.name": "edge"}},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		for _, record := range records {
			policy.EvaluateLog(engine, record, BenchLogMatcher)
		}
	}
}

// BenchmarkSnapshotGetPolicy benchmarks snapshot policy lookup.
func BenchmarkSnapshotGetPolicy(b *testing.B) {
	registry, _ := setupBenchmark(b)
	snapshot := registry.Snapshot()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		snapshot.GetPolicy("drop-debug-logs")
	}
}

// BenchmarkStatsCollection benchmarks stats collection.
func BenchmarkStatsCollection(b *testing.B) {
	registry, engine := setupBenchmark(b)

	// Generate some hits first
	record := &BenchLogRecord{
		Body:         []byte("debug trace message"),
		SeverityText: []byte("INFO"),
	}
	for i := 0; i < 1000; i++ {
		policy.EvaluateLog(engine, record, BenchLogMatcher)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		registry.CollectStats()
	}
}

// BenchmarkEvaluateLongBody benchmarks evaluation with a long body.
func BenchmarkEvaluateLongBody(b *testing.B) {
	_, engine := setupBenchmark(b)

	// Create a long body with the pattern at the end
	longBody := make([]byte, 10000)
	for i := range longBody {
		longBody[i] = 'x'
	}
	copy(longBody[len(longBody)-20:], "debug trace message")

	record := &BenchLogRecord{
		Body:         longBody,
		SeverityText: []byte("INFO"),
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		policy.EvaluateLog(engine, record, BenchLogMatcher)
	}
}

// BenchmarkEvaluateWithManyAttributes benchmarks evaluation with many attributes.
func BenchmarkEvaluateWithManyAttributes(b *testing.B) {
	_, engine := setupBenchmark(b)

	// Create a record with many attributes
	logAttrs := make(map[string]any)
	resourceAttrs := make(map[string]any)
	for i := 0; i < 50; i++ {
		logAttrs[fmt.Sprintf("attr_%d", i)] = fmt.Sprintf("value_%d", i)
		resourceAttrs[fmt.Sprintf("resource_%d", i)] = fmt.Sprintf("value_%d", i)
	}
	// Add the matching attribute
	logAttrs["ddsource"] = "nginx"

	record := &BenchLogRecord{
		Body:               []byte("request processed"),
		SeverityText:       []byte("INFO"),
		LogAttributes:      logAttrs,
		ResourceAttributes: resourceAttrs,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		policy.EvaluateLog(engine, record, BenchLogMatcher)
	}
}
