package bench

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/usetero/policy-go"
	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
)

// BenchLogRecord is a log record for benchmarking.
type BenchLogRecord struct {
	Body               []byte
	SeverityText       []byte
	LogAttributes      map[string]any
	ResourceAttributes map[string]any
	ScopeAttributes    map[string]any
}

func benchGetValue(r *BenchLogRecord, ref policy.LogFieldRef) []byte {
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
	return traversePath(benchLogAttrs(r, ref), ref.AttrPath)
}

func benchHasValue(r *BenchLogRecord, ref policy.LogFieldRef) bool {
	if ref.IsField() {
		return benchGetValue(r, ref) != nil
	}
	attrs := benchLogAttrs(r, ref)
	if attrs == nil || len(ref.AttrPath) == 0 {
		return false
	}
	_, ok := attrs[ref.AttrPath[0]]
	return ok
}

func benchSetValue(r *BenchLogRecord, ref policy.LogFieldRef, value string) {
	if ref.IsField() {
		switch ref.Field {
		case policy.LogFieldBody:
			r.Body = []byte(value)
		case policy.LogFieldSeverityText:
			r.SeverityText = []byte(value)
		}
		return
	}
	attrs := benchLogEnsureAttrs(r, ref)
	if attrs == nil {
		return
	}
	attrs[ref.AttrPath[0]] = value
}

func benchDeleteValue(r *BenchLogRecord, ref policy.LogFieldRef) bool {
	if ref.IsField() {
		switch ref.Field {
		case policy.LogFieldBody:
			hit := r.Body != nil
			r.Body = nil
			return hit
		case policy.LogFieldSeverityText:
			hit := r.SeverityText != nil
			r.SeverityText = nil
			return hit
		}
		return false
	}
	attrs := benchLogAttrs(r, ref)
	if attrs == nil {
		return false
	}
	key := ref.AttrPath[0]
	_, exists := attrs[key]
	delete(attrs, key)
	return exists
}

func benchMoveValue(r *BenchLogRecord, from, to policy.LogFieldRef) {
	fromAttrs := benchLogAttrs(r, from)
	val := fromAttrs[from.AttrPath[0]]
	delete(fromAttrs, from.AttrPath[0])
	toAttrs := benchLogEnsureAttrs(r, to)
	toAttrs[to.AttrPath[0]] = val
}

// benchLogOpts wires BenchLogRecord up to the bench* accessor functions.
// Built once at init and shared across benchmarks so EvaluateLog calls don't
// allocate a fresh variadic slice per iteration — mirroring how production
// callers should reuse their option slice.
var benchLogOpts = []policy.LogOption[*BenchLogRecord]{
	policy.WithLogValue(benchGetValue),
	policy.WithLogExists(benchHasValue),
	policy.WithLogSet(benchSetValue),
	policy.WithLogDelete(benchDeleteValue),
	policy.WithLogMove(benchMoveValue),
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

	b.ReportAllocs()
	for b.Loop() {
		policy.EvaluateLog(engine, record, benchLogOpts...)
	}
}

func benchLogAttrs(r *BenchLogRecord, ref policy.LogFieldRef) map[string]any {
	switch {
	case ref.IsRecordAttr():
		return r.LogAttributes
	case ref.IsResourceAttr():
		return r.ResourceAttributes
	case ref.IsScopeAttr():
		return r.ScopeAttributes
	default:
		return nil
	}
}

func benchLogEnsureAttrs(r *BenchLogRecord, ref policy.LogFieldRef) map[string]any {
	switch {
	case ref.IsRecordAttr():
		if r.LogAttributes == nil {
			r.LogAttributes = make(map[string]any)
		}
		return r.LogAttributes
	case ref.IsResourceAttr():
		if r.ResourceAttributes == nil {
			r.ResourceAttributes = make(map[string]any)
		}
		return r.ResourceAttributes
	case ref.IsScopeAttr():
		if r.ScopeAttributes == nil {
			r.ScopeAttributes = make(map[string]any)
		}
		return r.ScopeAttributes
	default:
		return nil
	}
}

// benchStaticProvider implements PolicyProvider for benchmark transform policies.
type benchStaticProvider struct {
	policies []*policyv1.Policy
}

func (p *benchStaticProvider) Load() ([]*policyv1.Policy, error) {
	return p.policies, nil
}

func (p *benchStaticProvider) Subscribe(callback policy.PolicyCallback) error {
	callback(p.policies)
	return nil
}

func (p *benchStaticProvider) SetStatsCollector(collector policy.StatsCollector) {}

// setupTransformBenchmark creates a registry with a transform policy.
func setupTransformBenchmark(b *testing.B, transforms *policyv1.LogTransform) (*policy.PolicyRegistry, *policy.PolicyEngine) {
	b.Helper()

	registry := policy.NewPolicyRegistry()
	provider := &benchStaticProvider{
		policies: []*policyv1.Policy{
			{
				Id:      "transform-bench",
				Name:    "Transform Benchmark",
				Enabled: true,
				Target: &policyv1.Policy_Log{
					Log: &policyv1.LogTarget{
						Match: []*policyv1.LogMatcher{
							{
								Field: &policyv1.LogMatcher_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
								Match: &policyv1.LogMatcher_Contains{Contains: "request"},
							},
						},
						Keep:      "all",
						Transform: transforms,
					},
				},
			},
		},
	}

	_, err := registry.Register(provider)
	if err != nil {
		b.Fatalf("Failed to register provider: %v", err)
	}

	engine := policy.NewPolicyEngine(registry)
	return registry, engine
}

func newBenchTransformRecord() *BenchLogRecord {
	return &BenchLogRecord{
		Body:         []byte("incoming request from client"),
		SeverityText: []byte("INFO"),
		LogAttributes: map[string]any{
			"api_key":    "sk-1234567890",
			"session_id": "sess-abc-123",
			"user_agent": "Mozilla/5.0",
			"ip_address": "10.0.0.1",
			"old_name":   "legacy_value",
		},
		ResourceAttributes: map[string]any{
			"service.name": "api-gateway",
		},
	}
}

// BenchmarkTransformRemove benchmarks a single remove transform.
func BenchmarkTransformRemove(b *testing.B) {
	_, engine := setupTransformBenchmark(b, &policyv1.LogTransform{
		Remove: []*policyv1.LogRemove{
			{Field: &policyv1.LogRemove_LogAttribute{LogAttribute: &policyv1.AttributePath{Path: []string{"api_key"}}}},
		},
	})

	b.ReportAllocs()
	for b.Loop() {
		r := newBenchTransformRecord()
		policy.EvaluateLog(engine, r, benchLogOpts...)
	}
}

// BenchmarkTransformRedact benchmarks a single redact transform.
func BenchmarkTransformRedact(b *testing.B) {
	_, engine := setupTransformBenchmark(b, &policyv1.LogTransform{
		Redact: []*policyv1.LogRedact{
			{
				Field:       &policyv1.LogRedact_LogAttribute{LogAttribute: &policyv1.AttributePath{Path: []string{"api_key"}}},
				Replacement: "[REDACTED]",
			},
		},
	})

	b.ReportAllocs()
	for b.Loop() {
		r := newBenchTransformRecord()
		policy.EvaluateLog(engine, r, benchLogOpts...)
	}
}

// BenchmarkTransformRename benchmarks a single rename transform.
func BenchmarkTransformRename(b *testing.B) {
	_, engine := setupTransformBenchmark(b, &policyv1.LogTransform{
		Rename: []*policyv1.LogRename{
			{
				From:   &policyv1.LogRename_FromLogAttribute{FromLogAttribute: &policyv1.AttributePath{Path: []string{"old_name"}}},
				To:     "new_name",
				Upsert: true,
			},
		},
	})

	b.ReportAllocs()
	for b.Loop() {
		r := newBenchTransformRecord()
		policy.EvaluateLog(engine, r, benchLogOpts...)
	}
}

// BenchmarkTransformAdd benchmarks a single add transform.
func BenchmarkTransformAdd(b *testing.B) {
	_, engine := setupTransformBenchmark(b, &policyv1.LogTransform{
		Add: []*policyv1.LogAdd{
			{
				Field:  &policyv1.LogAdd_LogAttribute{LogAttribute: &policyv1.AttributePath{Path: []string{"processed"}}},
				Value:  "true",
				Upsert: false,
			},
		},
	})

	b.ReportAllocs()
	for b.Loop() {
		r := newBenchTransformRecord()
		policy.EvaluateLog(engine, r, benchLogOpts...)
	}
}

// BenchmarkTransformMixed benchmarks a policy with all four transform types.
func BenchmarkTransformMixed(b *testing.B) {
	_, engine := setupTransformBenchmark(b, &policyv1.LogTransform{
		Remove: []*policyv1.LogRemove{
			{Field: &policyv1.LogRemove_LogAttribute{LogAttribute: &policyv1.AttributePath{Path: []string{"session_id"}}}},
		},
		Redact: []*policyv1.LogRedact{
			{
				Field:       &policyv1.LogRedact_LogAttribute{LogAttribute: &policyv1.AttributePath{Path: []string{"api_key"}}},
				Replacement: "[REDACTED]",
			},
		},
		Rename: []*policyv1.LogRename{
			{
				From:   &policyv1.LogRename_FromLogAttribute{FromLogAttribute: &policyv1.AttributePath{Path: []string{"old_name"}}},
				To:     "new_name",
				Upsert: true,
			},
		},
		Add: []*policyv1.LogAdd{
			{
				Field:  &policyv1.LogAdd_LogAttribute{LogAttribute: &policyv1.AttributePath{Path: []string{"processed"}}},
				Value:  "true",
				Upsert: false,
			},
		},
	})

	b.ReportAllocs()
	for b.Loop() {
		r := newBenchTransformRecord()
		policy.EvaluateLog(engine, r, benchLogOpts...)
	}
}

// BenchmarkTransformManyRedacts benchmarks a policy with many redact operations.
func BenchmarkTransformManyRedacts(b *testing.B) {
	_, engine := setupTransformBenchmark(b, &policyv1.LogTransform{
		Redact: []*policyv1.LogRedact{
			{Field: &policyv1.LogRedact_LogAttribute{LogAttribute: &policyv1.AttributePath{Path: []string{"api_key"}}}, Replacement: "[REDACTED]"},
			{Field: &policyv1.LogRedact_LogAttribute{LogAttribute: &policyv1.AttributePath{Path: []string{"session_id"}}}, Replacement: "[REDACTED]"},
			{Field: &policyv1.LogRedact_LogAttribute{LogAttribute: &policyv1.AttributePath{Path: []string{"ip_address"}}}, Replacement: "[REDACTED]"},
			{Field: &policyv1.LogRedact_LogAttribute{LogAttribute: &policyv1.AttributePath{Path: []string{"user_agent"}}}, Replacement: "[REDACTED]"},
		},
	})

	b.ReportAllocs()
	for b.Loop() {
		r := newBenchTransformRecord()
		policy.EvaluateLog(engine, r, benchLogOpts...)
	}
}

// BenchmarkTransformParallel benchmarks transform evaluation under contention.
func BenchmarkTransformParallel(b *testing.B) {
	_, engine := setupTransformBenchmark(b, &policyv1.LogTransform{
		Remove: []*policyv1.LogRemove{
			{Field: &policyv1.LogRemove_LogAttribute{LogAttribute: &policyv1.AttributePath{Path: []string{"session_id"}}}},
		},
		Redact: []*policyv1.LogRedact{
			{
				Field:       &policyv1.LogRedact_LogAttribute{LogAttribute: &policyv1.AttributePath{Path: []string{"api_key"}}},
				Replacement: "[REDACTED]",
			},
		},
		Rename: []*policyv1.LogRename{
			{
				From:   &policyv1.LogRename_FromLogAttribute{FromLogAttribute: &policyv1.AttributePath{Path: []string{"old_name"}}},
				To:     "new_name",
				Upsert: true,
			},
		},
		Add: []*policyv1.LogAdd{
			{
				Field:  &policyv1.LogAdd_LogAttribute{LogAttribute: &policyv1.AttributePath{Path: []string{"processed"}}},
				Value:  "true",
				Upsert: false,
			},
		},
	})

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			r := newBenchTransformRecord()
			policy.EvaluateLog(engine, r, benchLogOpts...)
		}
	})
}

// BenchmarkTransformNoMatch benchmarks transform overhead when no policy matches.
func BenchmarkTransformNoMatch(b *testing.B) {
	_, engine := setupTransformBenchmark(b, &policyv1.LogTransform{
		Redact: []*policyv1.LogRedact{
			{
				Field:       &policyv1.LogRedact_LogAttribute{LogAttribute: &policyv1.AttributePath{Path: []string{"api_key"}}},
				Replacement: "[REDACTED]",
			},
		},
	})

	// This record won't match the policy (body doesn't contain "request")
	record := &BenchLogRecord{
		Body:         []byte("normal application log message"),
		SeverityText: []byte("INFO"),
		LogAttributes: map[string]any{
			"api_key": "sk-1234567890",
		},
	}

	b.ReportAllocs()
	for b.Loop() {
		policy.EvaluateLog(engine, record, benchLogOpts...)
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

	b.ReportAllocs()
	for b.Loop() {
		policy.EvaluateLog(engine, record, benchLogOpts...)
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

	b.ReportAllocs()
	for b.Loop() {
		policy.EvaluateLog(engine, record, benchLogOpts...)
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

	b.ReportAllocs()
	for b.Loop() {
		policy.EvaluateLog(engine, record, benchLogOpts...)
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

	b.ReportAllocs()
	for b.Loop() {
		policy.EvaluateLog(engine, record, benchLogOpts...)
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
			policy.EvaluateLog(engine, record, benchLogOpts...)
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

	b.ReportAllocs()
	for b.Loop() {
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
	for b.Loop() {
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

	b.ReportAllocs()
	for b.Loop() {
		for _, record := range records {
			policy.EvaluateLog(engine, record, benchLogOpts...)
		}
	}
}

// BenchmarkSnapshotGetPolicy benchmarks snapshot policy lookup.
func BenchmarkSnapshotGetPolicy(b *testing.B) {
	registry, _ := setupBenchmark(b)
	snapshot := registry.Snapshot()

	b.ReportAllocs()
	for b.Loop() {
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
		policy.EvaluateLog(engine, record, benchLogOpts...)
	}

	b.ReportAllocs()
	for b.Loop() {
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

	b.ReportAllocs()
	for b.Loop() {
		policy.EvaluateLog(engine, record, benchLogOpts...)
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

	b.ReportAllocs()
	for b.Loop() {
		policy.EvaluateLog(engine, record, benchLogOpts...)
	}
}
