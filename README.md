# policy-go

A high-performance policy evaluation library for OpenTelemetry telemetry data in
Go. Built with [Hyperscan](https://github.com/intel/hyperscan) for fast regex
matching and designed for hot-reload support.

## Features

- **High-Performance Matching**: Uses Intel Hyperscan for vectorized regex
  evaluation
- **Hot Reload**: File-based policy providers support automatic reloading on
  change
- **Thread-Safe**: Immutable snapshots for concurrent evaluation
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
    "time"

    "github.com/usetero/policy-go"
    policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
)

// Implement the LogMatchable interface for your log records
type LogRecord struct {
    Body               []byte
    SeverityText       []byte
    TraceID            []byte
    LogAttributes      map[string]any
    ResourceAttributes map[string]any
}

func (r *LogRecord) GetField(field policyv1.LogField) []byte {
    switch field {
    case policyv1.LogField_LOG_FIELD_BODY:
        return r.Body
    case policyv1.LogField_LOG_FIELD_SEVERITY_TEXT:
        return r.SeverityText
    case policyv1.LogField_LOG_FIELD_TRACE_ID:
        return r.TraceID
    default:
        return nil
    }
}

func (r *LogRecord) GetAttribute(scope policy.AttrScope, path []string) []byte {
    var attrs map[string]any
    switch scope {
    case policy.AttrScopeResource:
        attrs = r.ResourceAttributes
    case policy.AttrScopeRecord:
        attrs = r.LogAttributes
    default:
        return nil
    }
    // Traverse the path for nested attribute access
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
        if s, ok := val.(string); ok {
            return []byte(s)
        }
        if b, ok := val.([]byte); ok {
            return b
        }
        return nil
    }
    if nested, ok := val.(map[string]any); ok {
        return traversePath(nested, path[1:])
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

    // Create an engine
    engine := policy.NewPolicyEngine()

    // Evaluate a log record
    record := &LogRecord{
        Body:         []byte("debug trace message"),
        SeverityText: []byte("INFO"),
        LogAttributes: map[string]any{
            "http": map[string]any{
                "method": "GET",
            },
        },
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

// Get snapshot for evaluation (thread-safe, immutable)
snapshot := registry.Snapshot()

// Collect stats
stats := registry.CollectStats()
```

### PolicySnapshot

Snapshots are immutable, read-only views of compiled policies. They're safe for
concurrent use across goroutines. The registry manages snapshot lifecycle
automatically.

```go
snapshot := registry.Snapshot()

// Safe to use from multiple goroutines
go func() {
    // snapshot is immutable and safe to share
    result := engine.Evaluate(snapshot, record)
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
type Matchable[F FieldEnum] interface {
    // GetField returns the value of the specified field.
    // Returns nil if the field doesn't exist.
    GetField(field F) []byte

    // GetAttribute returns the value of an attribute at the specified scope and path.
    // Path is a slice of strings representing nested access (e.g., ["http", "method"]).
    // Returns nil if the attribute doesn't exist.
    GetAttribute(scope AttrScope, path []string) []byte
}
```

For logs, use `LogMatchable` (alias for `Matchable[policyv1.LogField]`):

```go
type LogRecord struct {
    Body          []byte
    LogAttributes map[string]any
}

func (r *LogRecord) GetField(field policyv1.LogField) []byte {
    switch field {
    case policyv1.LogField_LOG_FIELD_BODY:
        return r.Body
    default:
        return nil
    }
}

func (r *LogRecord) GetAttribute(scope policy.AttrScope, path []string) []byte {
    if scope != policy.AttrScopeRecord {
        return nil
    }
    // Traverse nested path in LogAttributes
    return traversePath(r.LogAttributes, path)
}
```

Attribute scopes:

- `AttrScopeResource`: Resource-level attributes
- `AttrScopeScope`: Instrumentation scope attributes
- `AttrScopeRecord`: Record-level attributes (log attributes, span attributes)

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

| Field                | Description                                                    |
| -------------------- | -------------------------------------------------------------- |
| `log_field`          | Match on log fields: `body`, `severity_text`, `trace_id`, etc. |
| `log_attribute`      | Match on log record attributes                                 |
| `resource_attribute` | Match on resource attributes                                   |
| `scope_attribute`    | Match on scope attributes                                      |

#### Nested Attribute Access

Attributes can be accessed using nested paths for structured data:

```json
{
  "log_attribute": { "path": ["http", "request", "method"] },
  "exact": "POST"
}
```

Shorthand forms are also supported:

- Array: `"log_attribute": ["http", "request", "method"]`
- String (single key): `"log_attribute": "user_id"`

### Match Conditions

| Condition          | Description                                               |
| ------------------ | --------------------------------------------------------- |
| `regex`            | Match if field matches the regex pattern                  |
| `exact`            | Match if field equals the exact value                     |
| `starts_with`      | Match if field starts with the literal prefix             |
| `ends_with`        | Match if field ends with the literal suffix               |
| `contains`         | Match if field contains the literal substring             |
| `exists`           | Match if field exists (true) or doesn't exist (false)     |
| `negated`          | Invert the match condition                                |
| `case_insensitive` | Make the match case-insensitive (works with all matchers) |

The literal matchers (`starts_with`, `ends_with`, `contains`, `exact`) are
optimized using Hyperscan and are more efficient than equivalent regex patterns.

### Keep Actions

| Action   | Description               |
| -------- | ------------------------- |
| `"all"`  | Keep all matching records |
| `"none"` | Drop all matching records |
| `"N%"`   | Sample at N%              |

### Sampling with Sample Key

For consistent sampling (same key always produces same decision), use
`sample_key`:

```json
{
  "id": "sample-by-trace",
  "name": "Sample 10% of logs by trace ID",
  "log": {
    "match": [{ "log_field": "body", "contains": "request" }],
    "keep": "10%",
    "sample_key": {
      "log_field": "trace_id"
    }
  }
}
```

The sample key can reference any field or attribute:

- `log_field`: Use a log field (body, trace_id, span_id, etc.)
- `log_attribute`: Use a log record attribute
- `resource_attribute`: Use a resource attribute
- `scope_attribute`: Use a scope attribute

When a sample key is configured:

- Records with the same key value always get the same keep/drop decision
- This ensures consistent sampling across distributed systems
- If the sample key field is empty/missing, the record is kept by default

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

## TODO

### Zero-Allocation Optimizations

The current implementation allocates ~16-25 objects per evaluation. To achieve
zero-allocation evaluation:

- [x] Pool `matchCounts` slice in `PolicyEngine.Evaluate()`
- [x] Pool `disqualified` slice in `PolicyEngine.Evaluate()`
- [x] Pool Hyperscan scratch space per-database
- [x] Pool match result slices from `db.Scan()`
- [x] Use dense index arrays instead of maps for policy match tracking
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

- [x] Nested attribute path access (e.g., `http.request.method`)
- [x] Optimized literal matchers (`starts_with`, `ends_with`, `contains`)
- [x] Case-insensitive matching via Hyperscan flags
- [x] Sampling with hash-based determinism via `sample_key`
- [ ] Rate limiting support (currently stubbed)
- [ ] Transform actions (keep with modifications)
- [ ] Policy validation CLI tool
- [ ] Prometheus metrics exporter for stats

## License

Apache 2.0 - See [LICENSE](LICENSE) for details.
