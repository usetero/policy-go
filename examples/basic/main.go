package main

import (
	"fmt"
	"log"

	"github.com/usetero/policy-go"
	"github.com/usetero/policy-go/internal/engine"
	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
)

// ExampleLogRecord implements policy.Matchable for demonstration.
type ExampleLogRecord struct {
	Body               []byte
	SeverityText       []byte
	LogAttributes      map[string][]byte
	ResourceAttributes map[string][]byte
}

func (r *ExampleLogRecord) GetField(selector engine.LogFieldSelector) []byte {
	// Check simple log fields first
	if selector.LogField != policyv1.LogField_LOG_FIELD_UNSPECIFIED {
		switch selector.LogField {
		case policyv1.LogField_LOG_FIELD_BODY:
			return r.Body
		case policyv1.LogField_LOG_FIELD_SEVERITY_TEXT:
			return r.SeverityText
		}
		return nil
	}

	// Check attribute selectors
	if selector.LogAttribute != "" {
		return r.LogAttributes[selector.LogAttribute]
	}
	if selector.ResourceAttribute != "" {
		return r.ResourceAttributes[selector.ResourceAttribute]
	}
	return nil
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

	// Get a snapshot for evaluation
	snapshot := registry.Snapshot()

	// Create an engine for evaluation
	eng := policy.NewPolicyEngine()

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
				LogAttributes: map[string][]byte{
					"ddsource": []byte("nginx"),
				},
			},
		},
		{
			name: "Log from edge service (should be dropped)",
			record: &ExampleLogRecord{
				Body:         []byte("forwarding request"),
				SeverityText: []byte("INFO"),
				ResourceAttributes: map[string][]byte{
					"service.name": []byte("edge"),
				},
			},
		},
	}

	// Evaluate each log record
	fmt.Println("Evaluating log records:")
	fmt.Println("========================")
	for _, ex := range examples {
		result := eng.Evaluate(snapshot, ex.record)
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
