# policy-go

A high-performance policy evaluation library for OpenTelemetry telemetry data in
Go. Built with [Hyperscan](https://github.com/intel/hyperscan) for fast regex
matching and designed for hot-reload support.

## Features

- **High-Performance Matching**: Uses Intel Hyperscan for vectorized regex
  evaluation
- **Multi-Telemetry Support**: Evaluate logs, metrics, and traces with type-safe
  APIs
- **Hot Reload**: File-based policy providers support automatic reloading on
  change
- **Thread-Safe**: Immutable snapshots for concurrent evaluation
- **Extensible**: Provider interface for custom policy sources (file, HTTP,
  gRPC)
- **Statistics**: Per-policy hit/drop/sample counters with atomic operations
- **Rate Limiting**: Lock-free per-policy rate limiting with configurable
  windows
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
)

// Define your log record type
type LogRecord struct {
    Body               []byte
    SeverityText       []byte
    TraceID            []byte
    LogAttributes      map[string]any
    ResourceAttributes map[string]any
}

// Implement a match function to extract field values
func matchLog(r *LogRecord, ref policy.LogFieldRef) []byte {
    // Handle field lookups
    if ref.IsField() {
        switch ref.Field {
        case policy.LogFieldBody:
            return r.Body
        case policy.LogFieldSeverityText:
            return r.SeverityText
        case policy.LogFieldTraceID:
            return r.TraceID
        default:
            return nil
        }
    }

    // Handle attribute lookups
    var attrs map[string]any
    switch {
    case ref.IsResourceAttr():
        attrs = r.ResourceAttributes
    case ref.IsRecordAttr():
        attrs = r.LogAttributes
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
        case string:
            return []byte(v)
        case []byte:
            return v
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

    // Create an engine
    engine := policy.NewPolicyEngine(registry)

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

    result := policy.EvaluateLog(engine, record, matchLog)
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

// Collect stats
stats := registry.CollectStats()
```

### PolicyEngine

The engine evaluates telemetry against compiled policies. It holds a reference
to the registry and automatically uses the latest snapshot for each evaluation.

```go
engine := policy.NewPolicyEngine(registry)

// Evaluate logs
result := policy.EvaluateLog(engine, logRecord, matchLogFunc)

// Evaluate metrics
result := policy.EvaluateMetric(engine, metricRecord, matchMetricFunc)

// Evaluate traces/spans
result := policy.EvaluateTrace(engine, spanRecord, matchTraceFunc)

switch result {
case policy.ResultNoMatch:
    // No policy matched - pass through
case policy.ResultKeep:
    // Matched a keep policy (or under rate limit)
case policy.ResultDrop:
    // Matched a drop policy (or over rate limit)
case policy.ResultSample:
    // Sampled (for metrics without sample key)
}
```

### Match Functions

Instead of implementing an interface, you provide a match function that extracts
field values from your telemetry types. This allows maximum flexibility in how
you represent your data.

```go
// LogMatchFunc extracts values from log records
type LogMatchFunc[T any] func(record T, ref LogFieldRef) []byte

// MetricMatchFunc extracts values from metrics
type MetricMatchFunc[T any] func(record T, ref MetricFieldRef) []byte

// TraceMatchFunc extracts values from spans
type TraceMatchFunc[T any] func(record T, ref TraceFieldRef) []byte
```

Example match function for logs:

```go
func matchLog(r *MyLogRecord, ref policy.LogFieldRef) []byte {
    // Handle field lookups
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

    // Handle attribute lookups
    var attrs map[string]any
    switch {
    case ref.IsResourceAttr():
        attrs = r.ResourceAttributes
    case ref.IsRecordAttr():
        attrs = r.LogAttributes
    case ref.IsScopeAttr():
        attrs = r.ScopeAttributes
    default:
        return nil
    }
    return traversePath(attrs, ref.AttrPath)
}
```

### Field References

Field references (`LogFieldRef`, `MetricFieldRef`, `TraceFieldRef`) describe
what value to extract. Use helper methods to determine the reference type:

```go
ref.IsField()        // Is this a direct field (body, name, etc.)?
ref.IsResourceAttr() // Is this a resource attribute?
ref.IsRecordAttr()   // Is this a record/span/datapoint attribute?
ref.IsScopeAttr()    // Is this a scope attribute?
ref.IsEventAttr()    // Is this an event attribute? (traces only)
ref.IsLinkAttr()     // Is this a link attribute? (traces only)

ref.Field            // The field enum value
ref.AttrPath         // The attribute path (e.g., ["http", "method"])
```

### Attribute Scopes

- `AttrScopeResource`: Resource-level attributes (service.name, etc.)
- `AttrScopeScope`: Instrumentation scope attributes
- `AttrScopeRecord`: Record-level attributes (log attributes, span attributes,
  datapoint attributes)
- `AttrScopeEvent`: Span event attributes (traces only)
- `AttrScopeLink`: Span link attributes (traces only)

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

### Log Policies

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
    }
  ]
}
```

### Metric Policies

```json
{
  "policies": [
    {
      "id": "drop-internal-metrics",
      "name": "Drop internal metrics",
      "metric": {
        "match": [{ "metric_field": "name", "starts_with": "internal." }],
        "keep": false
      }
    },
    {
      "id": "drop-histogram-metrics",
      "name": "Drop histogram type metrics",
      "metric": {
        "match": [{ "metric_field": "type", "exact": "histogram" }],
        "keep": false
      }
    }
  ]
}
```

### Trace Policies

```json
{
  "policies": [
    {
      "id": "sample-traces",
      "name": "Sample 10% of traces",
      "trace": {
        "match": [{ "span_field": "kind", "exact": "server" }],
        "keep": { "percentage": 10 }
      }
    },
    {
      "id": "drop-health-checks",
      "name": "Drop health check spans",
      "trace": {
        "match": [{ "span_field": "name", "exact": "/health" }],
        "keep": { "percentage": 0 }
      }
    }
  ]
}
```

Trace sampling uses OTel-compliant consistent probability sampling. The same
trace ID always produces the same sampling decision, ensuring all spans in a
trace are kept or dropped together.

### Matcher Types

#### Log Matchers

| Field                | Description                                                    |
| -------------------- | -------------------------------------------------------------- |
| `log_field`          | Match on log fields: `body`, `severity_text`, `trace_id`, etc. |
| `log_attribute`      | Match on log record attributes                                 |
| `resource_attribute` | Match on resource attributes                                   |
| `scope_attribute`    | Match on scope attributes                                      |

#### Metric Matchers

| Field                 | Description                                          |
| --------------------- | ---------------------------------------------------- |
| `metric_field`        | Match on metric fields: `name`, `type`, `unit`, etc. |
| `datapoint_attribute` | Match on datapoint attributes                        |
| `resource_attribute`  | Match on resource attributes                         |
| `scope_attribute`     | Match on scope attributes                            |

#### Trace Matchers

| Field                | Description                                          |
| -------------------- | ---------------------------------------------------- |
| `span_field`         | Match on span fields: `name`, `kind`, `status`, etc. |
| `span_attribute`     | Match on span attributes                             |
| `resource_attribute` | Match on resource attributes                         |
| `scope_attribute`    | Match on scope attributes                            |
| `event_name`         | Match on span event names                            |
| `event_attribute`    | Match on span event attributes                       |
| `link_trace_id`      | Match on span link trace IDs                         |
| `link_attribute`     | Match on span link attributes                        |

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

| Action   | Description                        |
| -------- | ---------------------------------- |
| `"all"`  | Keep all matching records          |
| `"none"` | Drop all matching records          |
| `"N%"`   | Sample at N% (probabilistic)       |
| `"N/s"`  | Rate limit to N records per second |
| `"N/m"`  | Rate limit to N records per minute |

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

### Rate Limiting

Rate limiting allows you to cap the number of records kept per time window:

```json
{
  "id": "rate-limit-noisy-service",
  "name": "Rate limit logs from noisy service to 100/s",
  "log": {
    "match": [
      { "resource_attribute": "service.name", "exact": "noisy-service" }
    ],
    "keep": "100/s"
  }
}
```

Rate limiting features:

- **Lock-free implementation**: Uses atomic operations for thread-safe access
  without mutexes
- **Per-policy rate limiters**: Each policy with rate limiting gets its own
  limiter
- **Automatic window reset**: Windows reset inline on first request after expiry
- **Two time windows**: Use `/s` for per-second or `/m` for per-minute limits

When the rate limit is exceeded, records are dropped (`ResultDrop`). When under
the limit, records are kept (`ResultKeep`).

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

- [x] Log policies (`log` field)
- [x] Metric policies (`metric` field)
- [x] Trace policies (`trace` field) with OTel-compliant consistent sampling

### Provider Support

- [x] File provider with hot reload
- [ ] HTTP provider (poll-based)
- [ ] gRPC provider (streaming)

### Additional Features

- [x] Nested attribute path access (e.g., `http.request.method`)
- [x] Optimized literal matchers (`starts_with`, `ends_with`, `contains`)
- [x] Case-insensitive matching via Hyperscan flags
- [x] Sampling with hash-based determinism via `sample_key`
- [x] Rate limiting support (`N/s`, `N/m`) with lock-free implementation
- [ ] Transform actions (keep with modifications)
- [ ] Policy validation CLI tool
- [ ] Prometheus metrics exporter for stats

## License

Apache 2.0 - See [LICENSE](LICENSE) for details.
