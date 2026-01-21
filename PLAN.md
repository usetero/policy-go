# policy-go Implementation Plan

## Overview

This plan outlines the implementation of a high-performance policy evaluation
library for Go, mirroring the architecture of `policy-rs`. The library enables
hot-reloadable policy evaluation against telemetry data (OTLP logs, metrics,
traces) with constant-time, zero-allocation evaluation using Hyperscan pattern
matching.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        PolicyRegistry                           │
│  - Manages policies from multiple providers                     │
│  - Recompiles Hyperscan DB on any change                       │
│  - Produces read-only snapshots for evaluation                  │
└─────────────────────────────────────────────────────────────────┘
        ▲                                    │
        │ PolicyCallback                     │ Snapshot()
        │ (hot reload)                       ▼
┌───────┴───────┐                 ┌─────────────────────┐
│   Providers   │                 │   PolicySnapshot    │
│  (interface)  │                 │  (read-only copy)   │
├───────────────┤                 └─────────────────────┘
│ FileProvider  │                           │
│ HTTPProvider  │                           ▼
│ GRPCProvider  │                 ┌─────────────────────┐
│ CustomProvider│                 │    PolicyEngine     │
└───────────────┘                 │  - Evaluate()       │
        ▲                         │  - EvaluateTransform│
        │ StatsCollector          └─────────────────────┘
        │ (status reporting)                │
        └───────────────────────────────────┘
```

## Phase 1: Proto & Foundation

### 1.1 Proto Setup

- Add `buf` to Hermit packages
- Create `proto:export` task to pull from:
  - `buf.build/opentelemetry/opentelemetry`
  - `buf.build/tero/policy`
- Create `proto:generate` task using `protoc-gen-go`
- Generated code goes to `internal/proto/`

### 1.2 Core Types

```go
// policy.go - public wrapper
type Policy struct {
    proto *proto.Policy
}

func (p *Policy) ID() string
func (p *Policy) Name() string
func (p *Policy) Enabled() bool
func (p *Policy) Matchers() []Matcher
func (p *Policy) Keep() KeepAction
func (p *Policy) Transforms() []Transform
```

### 1.3 Error Types

```go
// error.go
type PolicyError struct {
    Kind    ErrorKind
    Message string
    Cause   error
}

type ErrorKind int
const (
    ErrInvalidPolicy ErrorKind = iota
    ErrCompilation
    ErrProvider
    ErrEvaluation
)
```

## Phase 2: Provider System

### 2.1 Provider Interface

```go
// provider.go
type PolicyCallback func(policies []Policy)

type PolicyProvider interface {
    // Load performs immediate load, returns current policies
    Load() ([]Policy, error)

    // Subscribe registers callback for policy changes
    // Callback is invoked immediately with current policies
    Subscribe(callback PolicyCallback) error

    // SetStatsCollector registers a function to collect stats for reporting
    SetStatsCollector(collector StatsCollector)
}

type StatsCollector func() []PolicyStats
```

### 2.2 File Provider

```go
// internal/provider/file.go → exported via provider/file.go
type FileProvider struct {
    path string
}

func NewFileProvider(path string) *FileProvider
func (f *FileProvider) Load() ([]Policy, error)
func (f *FileProvider) Subscribe(callback PolicyCallback) error
func (f *FileProvider) SetStatsCollector(collector StatsCollector)
```

JSON format:

```json
{
  "policies": [
    {
      "id": "drop-debug",
      "name": "Drop Debug Logs",
      "enabled": true,
      "matchers": [{ "field": "log_severity_text", "pattern": "DEBUG" }],
      "keep": "none"
    }
  ]
}
```

## Phase 3: Registry & Snapshot

### 3.1 Registry

```go
// registry.go
type PolicyRegistry struct {
    mu        sync.RWMutex
    providers map[ProviderId]*providerEntry
    compiled  *CompiledMatchers
    stats     map[string]*PolicyStats
}

type ProviderId uint64
type ProviderHandle struct {
    id       ProviderId
    registry *PolicyRegistry
}

func NewPolicyRegistry() *PolicyRegistry
func (r *PolicyRegistry) Register(provider PolicyProvider) (ProviderHandle, error)
func (r *PolicyRegistry) Unregister(handle ProviderHandle)
func (r *PolicyRegistry) Snapshot() *PolicySnapshot
```

### 3.2 Snapshot (read-only, copy-on-write)

```go
// snapshot.go
type PolicySnapshot struct {
    matchers *CompiledMatchers  // immutable reference
    stats    *StatsSnapshot     // atomic counters
}

func (s *PolicySnapshot) CompiledMatchers() *CompiledMatchers
func (s *PolicySnapshot) Get(id string) (*PolicyEntry, bool)
func (s *PolicySnapshot) Iter() iter.Seq2[string, *PolicyEntry]
```

### 3.3 Stats Collection & Reporting

The stats flow connects the engine, registry, and providers:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                            Stats Flow                                    │
│                                                                          │
│  PolicyEngine                PolicyRegistry              Providers       │
│  ───────────                 ──────────────              ─────────       │
│       │                            │                          │          │
│       │ Evaluate()                 │                          │          │
│       │ increments stats           │                          │          │
│       ▼                            │                          │          │
│  ┌─────────┐                       │                          │          │
│  │Snapshot │◄──────────────────────┤                          │          │
│  │ .stats  │  atomic counters      │                          │          │
│  └─────────┘  (shared ref)         │                          │          │
│                                    │                          │          │
│                           CollectStats()                      │          │
│                                    │                          │          │
│                                    ├─────────────────────────►│          │
│                                    │   StatsCollector func    │          │
│                                    │   registered on provider │          │
│                                    │                          │          │
│                                    │                     sync request    │
│                                    │                     includes stats  │
│                                    │                          │          │
└─────────────────────────────────────────────────────────────────────────┘
```

#### Stats Types

```go
// stats.go

// PolicyStats holds atomic counters for a single policy (mutable, shared)
type PolicyStats struct {
    Hits        atomic.Uint64
    Misses      atomic.Uint64
    Drops       atomic.Uint64
    Samples     atomic.Uint64
    RateLimited atomic.Uint64
    Transforms  atomic.Uint64
}

// PolicyStatsSnapshot is an immutable copy of stats for reporting
type PolicyStatsSnapshot struct {
    PolicyID    string
    Hits        uint64
    Misses      uint64
    Drops       uint64
    Samples     uint64
    RateLimited uint64
    Transforms  uint64
}

// StatsCollector is a function that returns current stats for all policies
// Registered with providers so they can include stats in sync requests
type StatsCollector func() []PolicyStatsSnapshot
```

#### Registry Stats Methods

```go
// registry.go

// CollectStats returns immutable snapshots of stats for all policies
// This is the StatsCollector implementation that gets registered with providers
func (r *PolicyRegistry) CollectStats() []PolicyStatsSnapshot {
    r.mu.RLock()
    defer r.mu.RUnlock()

    snapshots := make([]PolicyStatsSnapshot, 0, len(r.stats))
    for id, stats := range r.stats {
        snapshots = append(snapshots, PolicyStatsSnapshot{
            PolicyID:    id,
            Hits:        stats.Hits.Load(),
            Misses:      stats.Misses.Load(),
            Drops:       stats.Drops.Load(),
            Samples:     stats.Samples.Load(),
            RateLimited: stats.RateLimited.Load(),
            Transforms:  stats.Transforms.Load(),
        })
    }
    return snapshots
}

// Register adds a provider and wires up stats collection
func (r *PolicyRegistry) Register(provider PolicyProvider) (ProviderHandle, error) {
    // ... provider registration ...

    // Wire up stats collection - provider can now report stats to backend
    provider.SetStatsCollector(r.CollectStats)

    // ... subscribe to policy updates ...
}
```

#### Engine Stats Updates

```go
// engine.go

// Evaluate increments stats on the snapshot during evaluation
func (e *PolicyEngine) Evaluate(snapshot *PolicySnapshot, record Matchable) EvaluateResult {
    // ... pattern matching ...

    if matchedPolicy != nil {
        stats := snapshot.GetStats(matchedPolicy.ID)
        stats.Hits.Add(1)

        switch result {
        case ResultDrop:
            stats.Drops.Add(1)
        case ResultSample:
            stats.Samples.Add(1)
        case ResultRateLimit:
            stats.RateLimited.Add(1)
        }
    }

    return result
}
```

#### Provider Stats Reporting

```go
// Example: HTTP provider reporting stats in sync request
func (p *HTTPProvider) sync() error {
    var policyStatuses []PolicySyncStatus

    // Collect stats if collector is registered
    if p.statsCollector != nil {
        for _, stats := range p.statsCollector() {
            policyStatuses = append(policyStatuses, PolicySyncStatus{
                PolicyID: stats.PolicyID,
                Hits:     stats.Hits,
                Drops:    stats.Drops,
                // ... etc
            })
        }
    }

    req := &SyncRequest{
        PolicyStatuses: policyStatuses,
    }

    // Send to backend...
}
```

## Phase 4: Compilation (Hyperscan)

### 4.1 Hyperscan Integration

Using `github.com/flier/gohs` for Hyperscan bindings.

```go
// internal/engine/compiled.go
type MatchKey struct {
    Field   LogFieldSelector
    Negated bool
}

type CompiledMatchers struct {
    databases      map[MatchKey]*CompiledDatabase
    existenceChecks []ExistenceCheck
    policies       map[string]*CompiledPolicy
}

type CompiledDatabase struct {
    db           hs.BlockDatabase
    scratch      hs.Scratch
    patternIndex []PatternRef  // maps pattern ID → policy
}
```

### 4.2 Compilation Pipeline

```go
func Compile(policies []Policy) (*CompiledMatchers, error) {
    // 1. Group patterns by MatchKey
    groups := groupPatterns(policies)

    // 2. Compile each group to Hyperscan DB
    databases := make(map[MatchKey]*CompiledDatabase)
    for key, patterns := range groups {
        db, err := compilePatterns(patterns)
        if err != nil {
            return nil, err
        }
        databases[key] = db
    }

    // 3. Build policy lookup
    return &CompiledMatchers{
        databases: databases,
        policies:  buildPolicyMap(policies),
    }, nil
}
```

## Phase 5: Evaluation Engine

### 5.1 Matchable Interface (Field Access Pattern)

```go
// matchable.go
type LogFieldSelector int
const (
    FieldBody LogFieldSelector = iota
    FieldSeverityText
    FieldSeverityNumber
    FieldLogAttribute
    FieldResourceAttribute
    FieldScopeAttribute
    // ... more fields
)

type Matchable interface {
    // GetField returns field value, nil if not present
    // Zero-allocation: returns slice into existing data
    GetField(field LogFieldSelector, key string) []byte
}
```

### 5.2 Transformable Interface

```go
// transformable.go
type Transformable interface {
    Matchable

    // SetField sets a field value
    SetField(field LogFieldSelector, key string, value []byte)

    // DeleteField removes a field
    DeleteField(field LogFieldSelector, key string)

    // AddField adds a new field
    AddField(field LogFieldSelector, key string, value []byte)
}
```

### 5.3 Engine

```go
// engine.go
type PolicyEngine struct {
    rateLimiters *RateLimiters
}

type EvaluateResult int
const (
    ResultNoMatch EvaluateResult = iota
    ResultKeep
    ResultKeepWithTransform
    ResultDrop
    ResultSample
    ResultRateLimit
)

func NewPolicyEngine() *PolicyEngine

// Evaluate checks telemetry against snapshot - zero allocation
func (e *PolicyEngine) Evaluate(
    snapshot *PolicySnapshot,
    record Matchable,
) EvaluateResult

// EvaluateAndTransform evaluates and applies transforms
func (e *PolicyEngine) EvaluateAndTransform(
    snapshot *PolicySnapshot,
    record Transformable,
) EvaluateResult
```

### 5.4 Keep Actions

```go
// internal/engine/keep.go
type KeepAction int
const (
    KeepAll KeepAction = iota  // "all" or ""
    KeepNone                    // "none"
    KeepSample                  // "N%"
    KeepRatePerSecond          // "N/s"
    KeepRatePerMinute          // "N/m"
)

type CompiledKeep struct {
    Action KeepAction
    Value  int  // percentage or rate
}

// Restrictiveness for policy selection (higher = more restrictive)
func (k CompiledKeep) Restrictiveness() int
```

## Phase 6: OTLP Examples

### 6.1 Log Record Adapter

```go
// examples/otlp/logs.go
type OTLPLogRecord struct {
    record *logspb.LogRecord
    resource *resourcepb.Resource
    scope *commonpb.InstrumentationScope
}

func (r *OTLPLogRecord) GetField(field LogFieldSelector, key string) []byte {
    switch field {
    case FieldBody:
        return r.record.Body.GetStringValue()
    case FieldSeverityText:
        return []byte(r.record.SeverityText)
    case FieldLogAttribute:
        return getAttributeValue(r.record.Attributes, key)
    case FieldResourceAttribute:
        return getAttributeValue(r.resource.Attributes, key)
    // ...
    }
    return nil
}
```

### 6.2 Metric Adapter

```go
// examples/otlp/metrics.go
type OTLPMetric struct {
    metric *metricspb.Metric
    dataPoint any  // NumberDataPoint, HistogramDataPoint, etc.
    resource *resourcepb.Resource
}
```

### 6.3 Trace Span Adapter

```go
// examples/otlp/traces.go
type OTLPSpan struct {
    span *tracepb.Span
    resource *resourcepb.Resource
    scope *commonpb.InstrumentationScope
}
```

## Phase 7: Testing & Benchmarks

### 7.1 Test Data

```
testdata/
├── policies.json           # Basic policy set
├── policies_complex.json   # Complex matchers
├── policies_transforms.json # Transform operations
└── logs/
    ├── sample.json         # Sample log records
    └── otlp.json           # OTLP format logs
```

### 7.2 Benchmarks

```go
// bench_test.go
func BenchmarkEvaluate(b *testing.B)           // Single evaluation
func BenchmarkEvaluateParallel(b *testing.B)   // Concurrent evaluation
func BenchmarkCompile(b *testing.B)            // Compilation time
func BenchmarkSnapshotCreation(b *testing.B)   // Snapshot overhead
```

## File Structure

```
policy-go/
├── bin/                      # Hermit
├── proto/                    # Exported proto files (git-ignored)
├── internal/
│   ├── proto/               # Generated Go code
│   │   ├── tero/policy/v1/
│   │   └── opentelemetry/
│   ├── engine/
│   │   ├── compiled.go      # Hyperscan compilation
│   │   ├── keep.go          # Keep action logic
│   │   ├── transform.go     # Transform operations
│   │   └── ratelimiter.go   # Rate limiting
│   └── provider/
│       └── file.go          # File provider impl
├── examples/
│   ├── basic/               # Simple usage
│   └── otlp/
│       ├── logs.go          # Log adapter
│       ├── metrics.go       # Metrics adapter
│       └── traces.go        # Traces adapter
├── testdata/
│   └── policies.json
├── policy.go                # Policy type
├── error.go                 # Error types
├── field.go                 # LogFieldSelector
├── matchable.go             # Matchable interface
├── transformable.go         # Transformable interface
├── provider.go              # Provider interface
├── file_provider.go         # FileProvider (re-export)
├── registry.go              # PolicyRegistry
├── snapshot.go              # PolicySnapshot
├── engine.go                # PolicyEngine
├── stats.go                 # Stats types
├── go.mod
├── go.sum
└── Taskfile.yml
```

## Key Design Decisions

### 1. Hot Reloading

- Providers call `PolicyCallback` on any change
- Registry recompiles Hyperscan DB in background
- New snapshot is atomically swapped
- Old snapshots remain valid until released (ref counting)

### 2. Zero-Allocation Evaluation

- `Matchable.GetField()` returns `[]byte` slice into existing data
- Pre-allocated scratch space per goroutine (sync.Pool)
- No interface boxing in hot path
- Pattern IDs are sequential integers for array indexing

### 3. Stats Reporting

- Atomic counters in snapshot (lock-free reads)
- `StatsCollector` function registered with providers
- Providers include stats in sync requests to backend

### 4. Thread Safety

- Registry uses RWMutex for provider management
- Snapshots are immutable, safe for concurrent use
- Hyperscan scratch is cloned per-goroutine

## Implementation Order

1. **Week 1**: Proto setup, Policy type, Error types
2. **Week 2**: Provider interface, FileProvider, JSON parsing
3. **Week 3**: Registry, Snapshot, Stats
4. **Week 4**: Hyperscan compilation, MatchKey grouping
5. **Week 5**: PolicyEngine, Evaluate, KeepActions
6. **Week 6**: Transforms, EvaluateAndTransform
7. **Week 7**: OTLP adapters, Examples
8. **Week 8**: Benchmarks, Optimization, Documentation
