// Package backendbench compares the two regex backends — teroscan (pure Go) and
// hyperscan (cgo) — across telemetry types and policy counts. Each policy is a
// distinct regex matcher, and the benchmarked record matches none of them, so the
// backend must scan every pattern (hyperscan's single-pass strength vs teroscan's
// one-regexp-per-pattern baseline).
//
// Policies are written to a temp file and loaded through the real FileProvider,
// mirroring production wiring.
//
// Run:
//
//	cd examples && go test -bench=. -benchmem ./backendbench/
//	go test -bench=BenchmarkBackends/hyperscan/log ./backendbench/   # filter
//
// This is a benchmark-only package. Because it imports the hyperscan backend it
// requires cgo and the Hyperscan/Vectorscan library; the other examples stay
// cgo-free.
package backendbench

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/usetero/policy-go/backend/hyperscan"
	"github.com/usetero/policy-go/backend/teroscan"
	"github.com/usetero/policy-go/policy"
)

var policyCounts = []int{1, 10, 100, 1000}

type namedBackend struct {
	name    string
	backend policy.RegexBackend
}

var benchBackends = []namedBackend{
	{"teroscan", teroscan.New()},
	{"hyperscan", hyperscan.New()},
}

// BenchmarkBackends times policy evaluation for each backend × telemetry type ×
// policy count. Sub-benchmark names are e.g. BenchmarkBackends/teroscan/log/100.
func BenchmarkBackends(b *testing.B) {
	for _, bk := range benchBackends {
		for _, n := range policyCounts {
			b.Run(fmt.Sprintf("%s/log/%d", bk.name, n), func(b *testing.B) { benchLog(b, bk.backend, n) })
			b.Run(fmt.Sprintf("%s/metric/%d", bk.name, n), func(b *testing.B) { benchMetric(b, bk.backend, n) })
			b.Run(fmt.Sprintf("%s/trace/%d", bk.name, n), func(b *testing.B) { benchTrace(b, bk.backend, n) })
		}
	}
}

func benchLog(b *testing.B, backend policy.RegexBackend, n int) {
	eng := buildEngine(b, backend, logPolicies(n))
	rec := &policy.SimpleLogRecord{Body: []byte("normal application log line, nothing sensitive here")}
	opts := policy.SimpleLogOptions()
	b.ReportAllocs()
	for b.Loop() {
		policy.EvaluateLog(eng, rec, opts...)
	}
}

func benchMetric(b *testing.B, backend policy.RegexBackend, n int) {
	eng := buildEngine(b, backend, metricPolicies(n))
	rec := &policy.SimpleMetricRecord{Name: []byte("http.server.request.duration")}
	opts := policy.SimpleMetricOptions()
	b.ReportAllocs()
	for b.Loop() {
		policy.EvaluateMetric(eng, rec, opts...)
	}
}

func benchTrace(b *testing.B, backend policy.RegexBackend, n int) {
	eng := buildEngine(b, backend, tracePolicies(n))
	rec := &policy.SimpleSpanRecord{Name: []byte("GET /api/v1/users")}
	opts := policy.SimpleSpanOptions()
	b.ReportAllocs()
	for b.Loop() {
		policy.EvaluateTrace(eng, rec, opts...)
	}
}

// buildEngine writes the policy document to a temp file, loads it through a real
// FileProvider, and returns a ready engine. Parsing + compilation happen here,
// outside the timed loop.
func buildEngine(b *testing.B, backend policy.RegexBackend, doc policyDoc) *policy.PolicyEngine {
	b.Helper()

	data, err := json.Marshal(doc)
	if err != nil {
		b.Fatalf("marshal policies: %v", err)
	}
	path := filepath.Join(b.TempDir(), "policies.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		b.Fatalf("write policies: %v", err)
	}

	registry := policy.NewPolicyRegistry(policy.WithRegexBackend(backend))
	var compileErr error
	registry.SetOnRecompile(func(err error) {
		if err != nil {
			compileErr = err
		}
	})
	if _, err := registry.Register(policy.NewFileProvider(path)); err != nil {
		b.Fatalf("register provider: %v", err)
	}
	if compileErr != nil {
		b.Fatalf("compile policies: %v", compileErr)
	}
	return policy.NewPolicyEngine(registry)
}

// pattern returns a distinct regex per index that the benchmark records never
// match, forcing the backend to scan all patterns.
func pattern(i int) string { return fmt.Sprintf("secret-token-%d-[0-9a-f]{16}", i) }

func logPolicies(n int) policyDoc {
	d := policyDoc{Policies: make([]jsonPolicy, n)}
	for i := range d.Policies {
		d.Policies[i] = jsonPolicy{
			ID:   fmt.Sprintf("log-%d", i),
			Name: fmt.Sprintf("log-%d", i),
			Log: &jsonLog{
				Match: []jsonMatch{{LogField: "body", Regex: pattern(i)}},
				Keep:  "all",
			},
		}
	}
	return d
}

func metricPolicies(n int) policyDoc {
	d := policyDoc{Policies: make([]jsonPolicy, n)}
	for i := range d.Policies {
		d.Policies[i] = jsonPolicy{
			ID:   fmt.Sprintf("metric-%d", i),
			Name: fmt.Sprintf("metric-%d", i),
			Metric: &jsonMetric{
				Match: []jsonMatch{{MetricField: "name", Regex: pattern(i)}},
				Keep:  true,
			},
		}
	}
	return d
}

func tracePolicies(n int) policyDoc {
	d := policyDoc{Policies: make([]jsonPolicy, n)}
	for i := range d.Policies {
		d.Policies[i] = jsonPolicy{
			ID:   fmt.Sprintf("trace-%d", i),
			Name: fmt.Sprintf("trace-%d", i),
			Trace: &jsonTrace{
				Match: []jsonMatch{{TraceField: "name", Regex: pattern(i)}},
				Keep:  jsonTraceKeep{Percentage: 100},
			},
		}
	}
	return d
}

// Minimal mirror of the FileProvider JSON schema (see policy/testdata/policies.json).
type policyDoc struct {
	Policies []jsonPolicy `json:"policies"`
}

type jsonPolicy struct {
	ID     string      `json:"id"`
	Name   string      `json:"name"`
	Log    *jsonLog    `json:"log,omitempty"`
	Metric *jsonMetric `json:"metric,omitempty"`
	Trace  *jsonTrace  `json:"trace,omitempty"`
}

type jsonLog struct {
	Match []jsonMatch `json:"match"`
	Keep  string      `json:"keep"`
}

type jsonMetric struct {
	Match []jsonMatch `json:"match"`
	Keep  bool        `json:"keep"`
}

type jsonTrace struct {
	Match []jsonMatch   `json:"match"`
	Keep  jsonTraceKeep `json:"keep"`
}

type jsonTraceKeep struct {
	Percentage float32 `json:"percentage"`
}

type jsonMatch struct {
	LogField    string `json:"log_field,omitempty"`
	MetricField string `json:"metric_field,omitempty"`
	TraceField  string `json:"trace_field,omitempty"`
	Regex       string `json:"regex,omitempty"`
}
