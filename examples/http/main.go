package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/usetero/policy-go"
	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
)

// ExampleLogRecord implements policy.LogMatchable for demonstration.
type ExampleLogRecord struct {
	Body               []byte
	SeverityText       []byte
	LogAttributes      map[string]any
	ResourceAttributes map[string]any
	ScopeAttributes    map[string]any
}

func (r *ExampleLogRecord) GetField(field policyv1.LogField) []byte {
	switch field {
	case policyv1.LogField_LOG_FIELD_BODY:
		return r.Body
	case policyv1.LogField_LOG_FIELD_SEVERITY_TEXT:
		return r.SeverityText
	default:
		return nil
	}
}

func (r *ExampleLogRecord) GetAttribute(scope policy.AttrScope, path []string) []byte {
	var attrs map[string]any
	switch scope {
	case policy.AttrScopeResource:
		attrs = r.ResourceAttributes
	case policy.AttrScopeScope:
		attrs = r.ScopeAttributes
	case policy.AttrScopeRecord:
		attrs = r.LogAttributes
	default:
		return nil
	}
	return traversePath(attrs, path)
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
	// Create a registry to manage policies
	registry := policy.NewPolicyRegistry()

	// Create a gRPC provider connecting to Tero
	provider := policy.NewHttpProvider("https://sync.usetero.com/v1/policy/sync",
		policy.WithHTTPPollInterval(30*time.Second),
		policy.WithContentType(policy.ContentTypeJSON),
		policy.WithHeaders(map[string]string{
			"Authorization": "Bearer tero_sk_xBvF7OBOkM9fhwoWB3TD_mA7ayxjzyEN-acMoyfZyfw=",
		}),
		policy.WithServiceMetadata(&policy.ServiceMetadata{
			ServiceName:       "example-service",
			ServiceNamespace:  "default",
			ServiceInstanceID: "instance-001",
			ServiceVersion:    "1.0.0",
			SupportedStages: []policyv1.PolicyStage{
				policyv1.PolicyStage_POLICY_STAGE_LOG_FILTER,
			},
		}),
		policy.WithHTTPOnError(func(err error) {
			log.Printf("HTTP provider error: %v", err)
		}),
		policy.WithHTTPOnSync(func() {
			log.Println("Policy sync completed")
		}),
	)

	// Register the provider with the registry
	handle, err := registry.Register(provider)
	if err != nil {
		log.Fatalf("Failed to register provider: %v", err)
	}
	defer handle.Unregister()
	defer provider.Stop()

	fmt.Println("Connected to gRPC policy server at localhost:50051")
	fmt.Println("Waiting for policies...")
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
			name: "Debug log",
			record: &ExampleLogRecord{
				Body:         []byte("debug: checking connection"),
				SeverityText: []byte("DEBUG"),
			},
		},
		{
			name: "Info log",
			record: &ExampleLogRecord{
				Body:         []byte("user logged in"),
				SeverityText: []byte("INFO"),
			},
		},
		{
			name: "Error log",
			record: &ExampleLogRecord{
				Body:         []byte("connection failed"),
				SeverityText: []byte("ERROR"),
			},
		},
	}

	// Evaluate each log record
	fmt.Println("Evaluating log records:")
	fmt.Println("========================")
	for _, ex := range examples {
		result := eng.Evaluate(snapshot, ex.record)
		fmt.Printf("%-30s -> %s\n", ex.name, result)
	}

	// Show stats
	fmt.Println("\nPolicy stats:")
	fmt.Println("=============")
	stats := registry.CollectStats()
	if len(stats) == 0 {
		fmt.Println("No policies loaded (server may not have any policies)")
	}
	for _, s := range stats {
		fmt.Printf("%-30s hits=%d drops=%d\n", s.PolicyID, s.Hits, s.Drops)
	}

	// Wait for interrupt signal
	fmt.Println("\nPress Ctrl+C to exit...")
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\nShutting down...")
}
