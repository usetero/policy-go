package main

import (
	"fmt"
	"log"

	"github.com/usetero/policy-go/backend/teroscan"
	"github.com/usetero/policy-go/policy"
)

// ExampleLogRecord is a simple log record for demonstration.
type ExampleLogRecord struct {
	Body               []byte
	SeverityText       []byte
	LogAttributes      map[string]any
	ResourceAttributes map[string]any
	ScopeAttributes    map[string]any
}

// exampleGetValue returns a field/attribute value for ExampleLogRecord.
// This example only does matching, so Set/Delete/Move aren't supplied.
func exampleGetValue(r *ExampleLogRecord, ref policy.LogFieldRef) []byte {
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
	return traversePath(exampleAttrs(r, ref), ref.AttrPath)
}

func exampleHasValue(r *ExampleLogRecord, ref policy.LogFieldRef) bool {
	if ref.IsField() {
		return exampleGetValue(r, ref) != nil
	}
	return pathExists(exampleAttrs(r, ref), ref.AttrPath)
}

func exampleAttrs(r *ExampleLogRecord, ref policy.LogFieldRef) map[string]any {
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

func traversePath(m map[string]any, path []string) []byte {
	if len(path) == 0 || m == nil {
		return nil
	}
	val, ok := m[path[0]]
	if !ok {
		return nil
	}
	if len(path) == 1 {
		if s, ok := val.(string); ok {
			return []byte(s)
		}
		return nil
	}
	nested, ok := val.(map[string]any)
	if !ok {
		return nil
	}
	return traversePath(nested, path[1:])
}

func pathExists(m map[string]any, path []string) bool {
	if len(path) == 0 || m == nil {
		return false
	}
	cur := any(m)
	for _, seg := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return false
		}
		cur, ok = m[seg]
		if !ok {
			return false
		}
	}
	return true
}

func main() {
	// Load configuration from JSON file
	config, err := policy.LoadConfig("config.json")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Create a registry to manage policies
	registry := policy.NewPolicyRegistry(policy.WithRegexBackend(teroscan.New()))

	// Create a config loader with error handling
	loader := policy.NewConfigLoader(registry).
		WithOnError(func(err error) {
			log.Printf("Provider error: %v", err)
		})

	// Load and register all providers from config
	providers, err := loader.Load(config)
	if err != nil {
		log.Fatalf("Failed to load providers: %v", err)
	}
	defer policy.StopAll(providers)
	defer policy.UnregisterAll(providers)

	fmt.Printf("Loaded %d provider(s):\n", len(providers))
	for _, p := range providers {
		fmt.Printf("   - %s\n", p.ID)
	}
	fmt.Println()

	// Reuse the option slice across evaluations.
	logOpts := []policy.LogOption[*ExampleLogRecord]{
		policy.WithLogValue(exampleGetValue),
		policy.WithLogExists(exampleHasValue),
	}

	// Create an engine for evaluation
	eng := policy.NewPolicyEngine(registry)

	// Example log records to evaluate
	examples := []struct {
		name   string
		record *ExampleLogRecord
	}{
		{
			name: "Debug log with trace (should be dropped)",
			record: &ExampleLogRecord{
				Body:         []byte("this is a debug trace message"),
				SeverityText: []byte("INFO"),
			},
		},
		{
			name: "Normal info log (no match)",
			record: &ExampleLogRecord{
				Body:         []byte("user logged in successfully"),
				SeverityText: []byte("INFO"),
			},
		},
		{
			name: "DEBUG severity log (should be dropped)",
			record: &ExampleLogRecord{
				Body:         []byte("checking database connection"),
				SeverityText: []byte("DEBUG"),
			},
		},
		{
			name: "Error log (should be kept)",
			record: &ExampleLogRecord{
				Body:         []byte("failed to connect"),
				SeverityText: []byte("ERROR"),
			},
		},
		{
			name: "Log from nginx (should be dropped)",
			record: &ExampleLogRecord{
				Body:         []byte("request processed"),
				SeverityText: []byte("INFO"),
				LogAttributes: map[string]any{
					"ddsource": "nginx",
				},
			},
		},
		{
			name: "Log from edge service (should be dropped)",
			record: &ExampleLogRecord{
				Body:         []byte("forwarding request"),
				SeverityText: []byte("INFO"),
				ResourceAttributes: map[string]any{
					"service.name": "edge",
				},
			},
		},
		// New v1.2.0 features
		{
			name: "Log starting with ERROR: (starts_with)",
			record: &ExampleLogRecord{
				Body:         []byte("ERROR: connection refused"),
				SeverityText: []byte("ERROR"),
			},
		},
		{
			name: "Service ending with -prod (ends_with)",
			record: &ExampleLogRecord{
				Body:         []byte("processing order"),
				SeverityText: []byte("INFO"),
				ResourceAttributes: map[string]any{
					"service.name": "api-prod",
				},
			},
		},
		{
			name: "Timeout message case insensitive (contains)",
			record: &ExampleLogRecord{
				Body:         []byte("Connection TIMEOUT after 30s"),
				SeverityText: []byte("WARN"),
			},
		},
		{
			name: "Nested HTTP method attribute",
			record: &ExampleLogRecord{
				Body:         []byte("handling request"),
				SeverityText: []byte("INFO"),
				LogAttributes: map[string]any{
					"http": map[string]any{
						"request": map[string]any{
							"method": "POST",
						},
					},
				},
			},
		},
	}

	// Evaluate each log record
	fmt.Println("Evaluating log records:")
	fmt.Println("========================")
	for _, ex := range examples {
		result := policy.EvaluateLog(eng, ex.record, logOpts...)
		fmt.Printf("%-45s -> %s\n", ex.name, result)
	}

	// Show stats
	fmt.Println("\nPolicy stats:")
	fmt.Println("=============")
	for _, stats := range registry.CollectStats() {
		if stats.MatchHits > 0 || stats.MatchMisses > 0 {
			fmt.Printf("%-30s match_hits=%d match_misses=%d\n", stats.PolicyID, stats.MatchHits, stats.MatchMisses)
		}
	}
}
