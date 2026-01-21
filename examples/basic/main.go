package main

import (
	"fmt"
	"log"
	"path/filepath"

	"github.com/usetero/policy-go"
)

// ExampleLogRecord implements policy.Matchable for demonstration.
type ExampleLogRecord struct {
	Body               []byte
	SeverityText       []byte
	LogAttributes      map[string][]byte
	ResourceAttributes map[string][]byte
}

func (r *ExampleLogRecord) GetField(selector policy.FieldSelector) []byte {
	switch selector.Type {
	case policy.FieldTypeLogField:
		switch selector.Field {
		case policy.LogFieldBody:
			return r.Body
		case policy.LogFieldSeverityText:
			return r.SeverityText
		}
	case policy.FieldTypeLogAttribute:
		return r.LogAttributes[selector.Key]
	case policy.FieldTypeResourceAttribute:
		return r.ResourceAttributes[selector.Key]
	}
	return nil
}

func main() {
	fmt.Printf("policy-go version: %s\n\n", policy.Version())

	// Create a registry to manage policies
	registry := policy.NewPolicyRegistry()

	// Load policies from a JSON file
	provider := policy.NewFileProvider(filepath.Join("..", "..", "testdata", "policies.json"))
	_, err := registry.Register(provider)
	if err != nil {
		log.Fatalf("Failed to register provider: %v", err)
	}

	// Get a snapshot for evaluation
	snapshot := registry.Snapshot()
	defer snapshot.Release()

	// Create an engine for evaluation
	engine := policy.NewPolicyEngine()

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
		result := engine.Evaluate(snapshot, ex.record)
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
