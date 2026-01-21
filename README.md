# policy-go

A high-performance policy evaluation library for OpenTelemetry telemetry data in
Go. Built with [Hyperscan](https://github.com/intel/hyperscan) for fast regex
matching and designed for hot-reload support.

## Features

- **High-Performance Matching**: Uses Intel Hyperscan for vectorized regex
  evaluation
- **Hot Reload**: File-based policy providers support automatic reloading on
  change
- **Thread-Safe**: Immutable snapshots with reference counting for concurrent
  evaluation
- **Extensible**: Provider interface for custom policy sources (file, HTTP,
  gRPC)
- **Statistics**: Per-policy hit/drop/sample counters with atomic operations
- **AND Semantics**: Multiple matchers in a policy are AND'd together

## Installation

```bash
go get github.com/usetero/policy-go
```

### Requirements

- Go 1.21+
- Hyperscan library (via [gohs](https://github.com/flier/gohs))

On macOS with Homebrew:

```bash
brew install hyperscan
```

On Ubuntu/Debian:

```bash
apt-get install libhyperscan-dev
```

## Quick Start

```go
package main

import (
    "fmt"
    "log"

    "github.com/usetero/policy-go"
)

// Implement the Matchable interface for your log records
type LogRecord struct {
    Body               []byte
    SeverityText       []byte
    LogAttributes      map[string][]byte
    ResourceAttributes map[string][]byte
}

func (r *LogRecord) GetField(selector policy.FieldSelector) []byte {
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
    // Create a registry
    registry := policy.NewPolicyRegistry()

    // Create a file provider with hot reload
    provider := policy.NewFileProvider("policies.json",
        policy.WithPollInterval(30*time.Second),
        policy.WithOnError(func(err error) {
            log.Printf("Policy error: %v", err)
        }),
    )
    defer provider.Stop()

    // Register the provider
    handle, err := registry.Register(provider)
    if err != nil {
        log.Fatal(err)
    }
    defer handle.Unregister()

    // Get a snapshot for evaluation
    snapshot := registry.Snapshot()
    defer snapshot.Release()

    // Create an engine
    engine := policy.NewPolicyEngine()

    // Evaluate a log record
    record := &LogRecord{
        Body:         []byte("debug trace message"),
        SeverityText: []byte("INFO"),
    }

    result := engine.Evaluate(snapshot, record)
    fmt.Printf("Result: %s\n", result) // "drop" if matched by policy
}
```

## Core Concepts

### PolicyRegistry

The registry manages policies from multiple providers. When policies change, it
automatically recompiles the Hyperscan database and produces a new immutable
snapshot.

```go
registry := policy.NewPolicyRegistry()

// Register providers
handle, _ := registry.Register(fileProvider)
handle, _ := registry.Register(httpProvider)

// Get snapshot for evaluation (thread-safe)
snapshot := registry.Snapshot()
defer snapshot.Release()

// Collect stats
stats := registry.CollectStats()
```

### PolicySnapshot

Snapshots are immutable, reference-counted views of compiled policies. They're
safe for concurrent use across goroutines. Always call `Release()` when done.

```go
snapshot := registry.Snapshot()
defer snapshot.Release()

// Safe to use from multiple goroutines
go func() {
    snapshot.Retain() // Increment ref count
    defer snapshot.Release()
    // ... use snapshot
}()
```

### PolicyEngine

The engine evaluates records against a snapshot. It's designed to minimize
allocations in the hot path.

```go
engine := policy.NewPolicyEngine()

result := engine.Evaluate(snapshot, record)
switch result {
case policy.ResultNoMatch:
    // No policy matched - pass through
case policy.ResultKeep:
    // Matched a keep policy
case policy.ResultDrop:
    // Matched a drop policy
case policy.ResultSample:
    // Sampled (kept or dropped based on percentage)
}
```

### Matchable Interface

Implement the `Matchable` interface for your telemetry types:

```go
type Matchable interface {
    // GetField returns the value of the specified field.
    // Returns nil if the field doesn't exist.
    // Return a view into existing data to avoid allocations.
    GetField(selector FieldSelector) []byte
}
```

The `FieldSelector` contains:

- `Type`: The field type (log field, log attribute, resource attribute, scope
  attribute)
- `Field`: For log fields, which specific field (body, severity_text,
  severity_number)
- `Key`: For attributes, the attribute key

## Configuration

### Config File

Use a JSON configuration file to define providers:

```json
{
  "policy_providers": [
    {
      "type": "file",
      "id": "local-policies",
      "path": "/etc/tero/policies.json",
      "poll_interval_secs": 30
    }
  ]
}
```

### Loading Config

```go
config, err := policy.LoadConfig("config.json")
if err != nil {
    log.Fatal(err)
}

loader := policy.NewConfigLoader(registry).
    WithOnError(func(err error) {
        log.Printf("Provider error: %v", err)
    })

providers, err := loader.Load(config)
if err != nil {
    log.Fatal(err)
}
defer policy.StopAll(providers)
defer policy.UnregisterAll(providers)
```

## Policy Format

Policies are defined in JSON format following the
[Tero Policy Specification](https://buf.build/tero/policy):

```json
{
  "policies": [
    {
      "id": "drop-debug-logs",
      "name": "Drop debug logs containing trace",
      "log": {
        "match": [
          { "log_field": "body", "regex": "debug" },
          { "log_field": "body", "regex": "trace" }
        ],
        "keep": "none"
      }
    },
    {
      "id": "drop-nginx-logs",
      "name": "Drop nginx access logs",
      "log": {
        "match": [{ "log_attribute": "ddsource", "exact": "nginx" }],
        "keep": "none"
      }
    },
    {
      "id": "drop-edge-service",
      "name": "Drop logs from edge services",
      "log": {
        "match": [
          { "resource_attribute": "service.name", "regex": "^.*edge$" }
        ],
        "keep": "none"
      }
    }
  ]
}
```

### Matcher Types

| Field                | Description                                                     |
| -------------------- | --------------------------------------------------------------- |
| `log_field`          | Match on log fields: `body`, `severity_text`, `severity_number` |
| `log_attribute`      | Match on log record attributes                                  |
| `resource_attribute` | Match on resource attributes                                    |
| `scope_attribute`    | Match on scope attributes                                       |

### Match Conditions

| Condition | Description                                           |
| --------- | ----------------------------------------------------- |
| `regex`   | Match if field matches the regex pattern              |
| `exact`   | Match if field equals the exact value                 |
| `exists`  | Match if field exists (true) or doesn't exist (false) |
| `negated` | Invert the match condition                            |

### Keep Actions

| Action                | Description               |
| --------------------- | ------------------------- |
| `"all"`               | Keep all matching records |
| `"none"`              | Drop all matching records |
| `{ "percentage": N }` | Sample at N%              |

### AND Semantics

All matchers within a single policy are AND'd together. A policy only matches
when ALL of its matchers match:

```json
{
  "match": [
    { "log_field": "body", "regex": "debug" },
    { "log_field": "body", "regex": "trace" }
  ]
}
```

This policy matches logs where the body contains BOTH "debug" AND "trace".

## File Provider

The file provider loads policies from a JSON file and supports hot reload:

```go
provider := policy.NewFileProvider("policies.json",
    policy.WithPollInterval(30*time.Second),  // Check every 30 seconds
    policy.WithOnReload(func() {
        log.Println("Policies reloaded")
    }),
    policy.WithOnError(func(err error) {
        log.Printf("Error: %v", err)
    }),
)
defer provider.Stop()
```

## Statistics

The registry maintains per-policy statistics with atomic counters:

```go
stats := registry.CollectStats()
for _, s := range stats {
    fmt.Printf("Policy %s: hits=%d drops=%d samples=%d\n",
        s.PolicyID, s.Hits, s.Drops, s.Samples)
}
```

## Benchmarks

Run benchmarks with:

```bash
task bench
```

Typical results on an M1 MacBook Pro:

| Benchmark         | Time        | Allocations |
| ----------------- | ----------- | ----------- |
| EvaluateNoMatch   | ~700 ns/op  | 16 allocs   |
| EvaluateMatchBody | ~1200 ns/op | 25 allocs   |
| EvaluateParallel  | ~300 ns/op  | 25 allocs   |
| Compile           | ~2ms/op     | 342 allocs  |
| LoadPolicies      | ~50μs/op    | 200 allocs  |

The library scales well with parallel evaluation due to immutable snapshots.

## TODO

### Zero-Allocation Optimizations

The current implementation allocates ~16-25 objects per evaluation. To achieve
zero-allocation evaluation:

- [ ] Pool `matchCounts` map in `PolicyEngine.Evaluate()`
- [ ] Pool `disqualified` map in `PolicyEngine.Evaluate()`
- [ ] Pool Hyperscan scratch space per-engine (currently created per-scan)
- [ ] Pool match result maps from `db.Scan()`
- [ ] Consider bitset instead of map for policy match tracking
- [ ] Pre-allocate result slices in hot paths

### Telemetry Type Support

Currently only log policies are fully implemented:

- [x] Log policies (`log` field)
- [ ] Metric policies (`metric` field)
- [ ] Trace policies (`trace` field)

### Provider Support

- [x] File provider with hot reload
- [ ] HTTP provider (poll-based)
- [ ] gRPC provider (streaming)

### Additional Features

- [ ] Sampling with hash-based determinism (currently stubbed)
- [ ] Rate limiting support (currently stubbed)
- [ ] Transform actions (keep with modifications)
- [ ] Policy validation CLI tool
- [ ] Prometheus metrics exporter for stats

## License

Apache 2.0 - See [LICENSE](LICENSE) for details.
