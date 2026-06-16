// Package main is a conformance runner for the policy-go multi-module workspace.
// It mirrors runners/go in policy-conformance but uses the local workspace modules
// and selects the regex backend via the POLICY_BACKEND env var:
//
//	POLICY_BACKEND=teroscan  (default, pure Go)
//	POLICY_BACKEND=hyperscan (cgo, requires Hyperscan/Vectorscan)
//
// Usage:
//
//	runner --policies <path> --input <path> --output <path> --stats <path> --signal <log|metric|trace>
//
// Compatible with the policy-conformance Taskfile's `conformance` task:
//
//	cd ../policy-conformance && task conformance RUNNER=../policy-go/examples/conformance/runner LANG=go
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/usetero/policy-go/backend/hyperscan"
	"github.com/usetero/policy-go/backend/teroscan"
	"github.com/usetero/policy-go/policy"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/plog/plogotlp"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/pmetric/pmetricotlp"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"
)

func selectedBackend() policy.RegexBackend {
	switch os.Getenv("POLICY_BACKEND") {
	case "hyperscan":
		return hyperscan.New()
	default:
		return teroscan.New()
	}
}

// ─── Stats output ────────────────────────────────────────────────────

type StatsOutput struct {
	Policies []PolicyHit `json:"policies"`
}

type PolicyHit struct {
	PolicyID string `json:"policy_id"`
	Hits     uint64 `json:"hits"`
	Misses   uint64 `json:"misses,omitempty"`
}

func writeStats(path string, registry *policy.PolicyRegistry) error {
	stats := registry.CollectStats()
	var output StatsOutput
	for _, s := range stats {
		if s.MatchHits > 0 || s.MatchMisses > 0 {
			output.Policies = append(output.Policies, PolicyHit{
				PolicyID: s.PolicyID,
				Hits:     s.MatchHits,
				Misses:   s.MatchMisses,
			})
		}
	}
	if output.Policies == nil {
		output.Policies = []PolicyHit{}
	}
	sort.Slice(output.Policies, func(i, j int) bool {
		return output.Policies[i].PolicyID < output.Policies[j].PolicyID
	})
	data, err := json.Marshal(output)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// ─── Signal processing ──────────────────────────────────────────────

func processLogs(eng *policy.PolicyEngine, registry *policy.PolicyRegistry, inputData []byte) ([]byte, error) {
	req := plogotlp.NewExportRequest()
	if err := req.UnmarshalJSON(inputData); err != nil {
		return nil, fmt.Errorf("unmarshal logs: %w", err)
	}

	registry.CollectStats()

	logs := req.Logs()
	for i := 0; i < logs.ResourceLogs().Len(); i++ {
		rl := logs.ResourceLogs().At(i)
		for j := 0; j < rl.ScopeLogs().Len(); j++ {
			sl := rl.ScopeLogs().At(j)
			sl.LogRecords().RemoveIf(func(rec plog.LogRecord) bool {
				ctx := &LogContext{
					Record:            rec,
					Resource:          rl.Resource(),
					Scope:             sl.Scope(),
					ResourceSchemaURL: rl.SchemaUrl(),
					ScopeSchemaURL:    sl.SchemaUrl(),
				}
				result := policy.EvaluateLog(eng, ctx, LogOpts...)
				return result == policy.ResultDrop
			})
		}
	}

	for i := 0; i < logs.ResourceLogs().Len(); i++ {
		rl := logs.ResourceLogs().At(i)
		rl.ScopeLogs().RemoveIf(func(sl plog.ScopeLogs) bool {
			return sl.LogRecords().Len() == 0
		})
	}
	logs.ResourceLogs().RemoveIf(func(rl plog.ResourceLogs) bool {
		return rl.ScopeLogs().Len() == 0
	})

	return req.MarshalJSON()
}

func processMetrics(eng *policy.PolicyEngine, registry *policy.PolicyRegistry, inputData []byte) ([]byte, error) {
	req := pmetricotlp.NewExportRequest()
	if err := req.UnmarshalJSON(inputData); err != nil {
		return nil, fmt.Errorf("unmarshal metrics: %w", err)
	}

	registry.CollectStats()

	metrics := req.Metrics()
	for i := 0; i < metrics.ResourceMetrics().Len(); i++ {
		rm := metrics.ResourceMetrics().At(i)
		for j := 0; j < rm.ScopeMetrics().Len(); j++ {
			sm := rm.ScopeMetrics().At(j)
			sm.Metrics().RemoveIf(func(m pmetric.Metric) bool {
				ctx := &MetricContext{
					Metric:              m,
					DatapointAttributes: getDatapointAttrs(m),
					Resource:            rm.Resource(),
					Scope:               sm.Scope(),
					ResourceSchemaURL:   rm.SchemaUrl(),
					ScopeSchemaURL:      sm.SchemaUrl(),
				}
				result := policy.EvaluateMetric(eng, ctx, MetricOpts...)
				return result == policy.ResultDrop
			})
		}
	}

	for i := 0; i < metrics.ResourceMetrics().Len(); i++ {
		rm := metrics.ResourceMetrics().At(i)
		rm.ScopeMetrics().RemoveIf(func(sm pmetric.ScopeMetrics) bool {
			return sm.Metrics().Len() == 0
		})
	}
	metrics.ResourceMetrics().RemoveIf(func(rm pmetric.ResourceMetrics) bool {
		return rm.ScopeMetrics().Len() == 0
	})

	return req.MarshalJSON()
}

func processTraces(eng *policy.PolicyEngine, registry *policy.PolicyRegistry, inputData []byte) ([]byte, error) {
	req := ptraceotlp.NewExportRequest()
	if err := req.UnmarshalJSON(inputData); err != nil {
		return nil, fmt.Errorf("unmarshal traces: %w", err)
	}

	registry.CollectStats()

	traces := req.Traces()
	for i := 0; i < traces.ResourceSpans().Len(); i++ {
		rs := traces.ResourceSpans().At(i)
		for j := 0; j < rs.ScopeSpans().Len(); j++ {
			ss := rs.ScopeSpans().At(j)
			ss.Spans().RemoveIf(func(span ptrace.Span) bool {
				ctx := &TraceContext{
					Span:              span,
					Resource:          rs.Resource(),
					Scope:             ss.Scope(),
					ResourceSchemaURL: rs.SchemaUrl(),
					ScopeSchemaURL:    ss.SchemaUrl(),
				}
				result := policy.EvaluateTrace(eng, ctx, TraceOpts...)
				return result == policy.ResultDrop
			})
		}
	}

	for i := 0; i < traces.ResourceSpans().Len(); i++ {
		rs := traces.ResourceSpans().At(i)
		rs.ScopeSpans().RemoveIf(func(ss ptrace.ScopeSpans) bool {
			return ss.Spans().Len() == 0
		})
	}
	traces.ResourceSpans().RemoveIf(func(rs ptrace.ResourceSpans) bool {
		return rs.ScopeSpans().Len() == 0
	})

	return req.MarshalJSON()
}

// ─── Main ────────────────────────────────────────────────────────────

func main() {
	policiesPath := flag.String("policies", "", "path to policies.json")
	serverURL := flag.String("server", "", "HTTP sync endpoint URL")
	grpcAddr := flag.String("grpc", "", "gRPC server address")
	inputPath := flag.String("input", "", "path to input.json")
	outputPath := flag.String("output", "", "path to output.json")
	statsPath := flag.String("stats", "", "path to stats.json")
	signalFlag := flag.String("signal", "", "signal type: log, metric, trace")
	flag.Parse()

	if *inputPath == "" || *outputPath == "" || *signalFlag == "" {
		fmt.Fprintf(os.Stderr, "usage: runner (--policies <path> | --server <url> | --grpc <addr>) --input <path> --output <path> --signal <log|metric|trace> [--stats <path>]\n")
		os.Exit(1)
	}

	remoteMode := *serverURL != "" || *grpcAddr != ""
	if !remoteMode && (*policiesPath == "" || *statsPath == "") {
		fmt.Fprintf(os.Stderr, "usage: runner --policies <path> --input <path> --output <path> --stats <path> --signal <log|metric|trace>\n")
		os.Exit(1)
	}

	registry := policy.NewPolicyRegistry(policy.WithRegexBackend(selectedBackend()))
	var provider policy.PolicyProvider
	switch {
	case *serverURL != "":
		provider = policy.NewHttpProvider(*serverURL,
			policy.WithContentType(policy.ContentTypeJSON),
			policy.WithHTTPPollInterval(60*time.Second),
		)
	case *grpcAddr != "":
		provider = policy.NewGrpcProvider(*grpcAddr,
			policy.WithGrpcInsecure(),
			policy.WithGrpcPollInterval(60*time.Second),
		)
	default:
		provider = policy.NewFileProvider(*policiesPath)
	}

	handle, err := registry.Register(provider)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load policies: %v\n", err)
		os.Exit(1)
	}
	defer handle.Unregister()

	inputData, err := os.ReadFile(*inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read input: %v\n", err)
		os.Exit(1)
	}

	eng := policy.NewPolicyEngine(registry)

	var output []byte
	switch *signalFlag {
	case "log":
		output, err = processLogs(eng, registry, inputData)
	case "metric":
		output, err = processMetrics(eng, registry, inputData)
	case "trace":
		output, err = processTraces(eng, registry, inputData)
	default:
		fmt.Fprintf(os.Stderr, "unknown signal: %s\n", *signalFlag)
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*outputPath, output, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write output: %v\n", err)
		os.Exit(1)
	}

	if remoteMode {
		if _, err := provider.Load(); err != nil {
			fmt.Fprintf(os.Stderr, "failed to sync stats: %v\n", err)
		}
	} else {
		if err := writeStats(*statsPath, registry); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write stats: %v\n", err)
			os.Exit(1)
		}
	}
}

func collectMatchedPolicies(registry *policy.PolicyRegistry) []string {
	stats := registry.CollectStats()
	var matched []string
	for _, s := range stats {
		if s.MatchHits > 0 {
			matched = append(matched, s.PolicyID)
		}
	}
	sort.Strings(matched)
	if matched == nil {
		matched = []string{}
	}
	return matched
}
