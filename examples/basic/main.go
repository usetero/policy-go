package main

import (
	"fmt"
	"log"

	"github.com/usetero/policy-go"
)

// ExampleLogRecord is a simple log record for demonstration.
type ExampleLogRecord struct {
	Body               []byte
	SeverityText       []byte
	LogAttributes      map[string]any
	ResourceAttributes map[string]any
	ScopeAttributes    map[string]any
}

// ExampleLogMatcher is the LogMatchFunc implementation for ExampleLogRecord.
func ExampleLogMatcher(r *ExampleLogRecord, ref policy.LogFieldRef) []byte {
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

func main() {
	// Load configuration from JSON file
	config, err := policy.LoadConfig("config.json")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Create a registry to manage policies
	registry := policy.NewPolicyRegistry()

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
		fmt.Printf("  - %s\n", p.ID)
	}
	fmt.Println()

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
		result := policy.EvaluateLog(eng, ex.record, ExampleLogMatcher)
		fmt.Printf("%-45s -> %s\n", ex.name, result)
	}

	// Show stats
	fmt.Println("\nPolicy stats:")
	fmt.Println("=============")
	for _, stats := range registry.CollectStats() {
		if stats.Hits > 0 {
			fmt.Printf("%-30s hits=%d drops=%d\n", stats.PolicyID, stats.Hits, stats.Drops)
		}
	}
}
