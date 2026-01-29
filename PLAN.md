# Implementation Plan: Policy Specification v1.2.0

This plan details the implementation of three new features from policy
specification v1.2.0:

1. Nested Attribute Accessors (PR #24)
2. New Optimized Matchers (PR #25)
3. Sampling Key Support for Logs (PR #27)

## Overview

The policy-go library implements a high-performance policy evaluation engine
using Hyperscan for regex matching. The implementation touches several layers:

- **Proto layer**: Generated code from buf.build/tero/policy
- **Engine layer**: `internal/engine/` - compilation and evaluation
- **Public API layer**: Root package - `Matchable` interface, `PolicyEngine`
- **JSON parsing layer**: `internal/jsonpolicy/` - JSON policy format support

---

## Task 1: Update Generated Protobuf Code

**Action**: Run proto generation to pull policy v1.2.0 from buf registry.

```bash
./bin/buf export buf.build/tero/policy:v1.2.0 -o proto
./bin/buf export buf.build/opentelemetry/opentelemetry -o proto
./bin/buf generate proto
```

**Files affected**:

- `proto/tero/policy/v1/shared.proto` - NEW: Contains `AttributePath`
- `proto/tero/policy/v1/log.proto` - Updated with new matchers and sample_key
- `internal/proto/tero/policy/v1/*.pb.go` - Regenerated Go code

**Key proto changes from v1.2.0**:

### New shared.proto with AttributePath

```protobuf
message AttributePath {
  repeated string path = 1;
}
```

### Updated LogMatcher

- Field selectors now use `AttributePath` instead of `string`:
  - `AttributePath log_attribute = 2`
  - `AttributePath resource_attribute = 3`
  - `AttributePath scope_attribute = 4`
- New match types added:
  - `string starts_with = 13`
  - `string ends_with = 14`
  - `string contains = 15`
- New flag: `bool case_insensitive = 21`

### New LogSampleKey message

```protobuf
message LogSampleKey {
  oneof field {
    LogField log_field = 1;
    AttributePath log_attribute = 2;
    AttributePath resource_attribute = 3;
    AttributePath scope_attribute = 4;
  }
}
```

### Updated LogTarget

- New field: `LogSampleKey sample_key = 4`

---

## Task 2: Implement Nested Attribute Accessor Support

**BREAKING CHANGE**: Replace the existing `GetAttribute(scope, name string)`
method with `GetAttribute(scope, path []string)`.

### 2.1 Update FieldSelector

**File**: `internal/engine/match_key.go`

```go
type FieldSelector struct {
    Field     int32
    AttrScope AttrScope
    AttrPath  []string  // CHANGED: path-based access (replaces AttrName)
}

func (s FieldSelector) IsAttribute() bool {
    return len(s.AttrPath) > 0
}
```

Update `FieldSelectorFromLogMatcher()` to extract path from `AttributePath`:

```go
func FieldSelectorFromLogMatcher(m *policyv1.LogMatcher) FieldSelector {
    switch f := m.GetField().(type) {
    case *policyv1.LogMatcher_LogField:
        return FieldSelector{Field: int32(f.LogField)}
    case *policyv1.LogMatcher_LogAttribute:
        return FieldSelector{AttrScope: AttrScopeRecord, AttrPath: f.LogAttribute.GetPath()}
    case *policyv1.LogMatcher_ResourceAttribute:
        return FieldSelector{AttrScope: AttrScopeResource, AttrPath: f.ResourceAttribute.GetPath()}
    case *policyv1.LogMatcher_ScopeAttribute:
        return FieldSelector{AttrScope: AttrScopeScope, AttrPath: f.ScopeAttribute.GetPath()}
    default:
        return FieldSelector{}
    }
}
```

### 2.2 Update Matchable Interface (BREAKING CHANGE)

**File**: `matchable.go`

```go
type Matchable[F FieldEnum] interface {
    GetField(field F) []byte
    // GetAttribute returns the value of an attribute at the specified scope and path.
    // Path is a slice of strings representing nested access (e.g., ["http", "method"]).
    // For single-segment paths, this is equivalent to the old name-based lookup.
    // Returns nil if the attribute doesn't exist or any intermediate path segment is missing.
    GetAttribute(scope AttrScope, path []string) []byte
}
```

### 2.3 Update SimpleLogRecord

**File**: `matchable.go`

```go
type SimpleLogRecord struct {
    Body               []byte
    SeverityText       []byte
    TraceID            []byte
    SpanID             []byte
    EventName          []byte
    LogAttributes      map[string]any  // CHANGED: supports nested maps
    ResourceAttributes map[string]any  // CHANGED: supports nested maps
    ScopeAttributes    map[string]any  // CHANGED: supports nested maps
}

func (r *SimpleLogRecord) GetAttribute(scope AttrScope, path []string) []byte {
    var attrs map[string]any
    switch scope {
    case AttrScopeResource:
        attrs = r.ResourceAttributes
    case AttrScopeScope:
        attrs = r.ScopeAttributes
    case AttrScopeRecord:
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
```

### 2.4 Update Engine Evaluation

**File**: `engine.go`

```go
func getFieldValue(record LogMatchable, selector engine.FieldSelector) []byte {
    if len(selector.AttrPath) > 0 {
        return record.GetAttribute(AttrScope(selector.AttrScope), selector.AttrPath)
    }
    return record.GetField(policyv1.LogField(selector.Field))
}
```

### 2.5 Update JSON Parser with Multiple Input Forms

**File**: `internal/jsonpolicy/types.go`

Per the spec, implementations MUST support three input forms:

```go
// AttributePath handles unmarshaling from three forms:
// 1. Canonical: {"path": ["http", "method"]}
// 2. Shorthand array: ["http", "method"]
// 3. Shorthand string: "user_id"
type AttributePath struct {
    Path []string
}

func (a *AttributePath) UnmarshalJSON(data []byte) error {
    // Try canonical form: {"path": [...]}
    var canonical struct {
        Path []string `json:"path"`
    }
    if err := json.Unmarshal(data, &canonical); err == nil && len(canonical.Path) > 0 {
        a.Path = canonical.Path
        return nil
    }

    // Try shorthand array: [...]
    var arr []string
    if err := json.Unmarshal(data, &arr); err == nil {
        a.Path = arr
        return nil
    }

    // Try shorthand string: "name"
    var str string
    if err := json.Unmarshal(data, &str); err == nil {
        a.Path = []string{str}
        return nil
    }

    return NewParseError("attribute_path", "must be object with path, array, or string")
}

type LogMatcher struct {
    LogField          string         `json:"log_field,omitempty"`
    LogAttribute      *AttributePath `json:"log_attribute,omitempty"`
    ResourceAttribute *AttributePath `json:"resource_attribute,omitempty"`
    ScopeAttribute    *AttributePath `json:"scope_attribute,omitempty"`

    Regex      string `json:"regex,omitempty"`
    Exact      string `json:"exact,omitempty"`
    Exists     *bool  `json:"exists,omitempty"`
    StartsWith string `json:"starts_with,omitempty"`
    EndsWith   string `json:"ends_with,omitempty"`
    Contains   string `json:"contains,omitempty"`

    Negated         bool `json:"negated,omitempty"`
    CaseInsensitive bool `json:"case_insensitive,omitempty"`
}
```

**File**: `internal/jsonpolicy/parser.go`

```go
func (p *Parser) setFieldSelector(matcher *policyv1.LogMatcher, m LogMatcher) error {
    // ... count validation ...

    if m.LogAttribute != nil {
        matcher.Field = &policyv1.LogMatcher_LogAttribute{
            LogAttribute: &policyv1.AttributePath{Path: m.LogAttribute.Path},
        }
        return nil
    }
    // ... similar for resource_attribute, scope_attribute ...
}
```

---

## Task 3: Implement New Optimized Matchers

### 3.1 New Match Types from Proto

The proto adds three new literal match types (no regex compilation):

- `starts_with` (field 13) - Literal prefix match
- `ends_with` (field 14) - Literal suffix match
- `contains` (field 15) - Literal substring match

Plus a flag:

- `case_insensitive` (field 21) - Applies to ALL match types

### 3.2 Update MatchKey for Grouping

**File**: `internal/engine/match_key.go`

```go
type MatchKey struct {
    Selector        FieldSelector
    Negated         bool
    CaseInsensitive bool  // NEW: for Hyperscan Caseless flag
}
```

### 3.3 Update Compiler

**File**: `internal/engine/compiled.go`

Add support for new match types and case-insensitive flag:

```go
type patternEntry struct {
    pattern         string
    policyID        string
    policyIndex     int
    matcherIndex    int
    caseInsensitive bool
}

// In Compile(), extract patterns with new match types:
var pattern string
switch match := m.GetMatch().(type) {
case *policyv1.LogMatcher_Regex:
    pattern = match.Regex
case *policyv1.LogMatcher_Exact:
    pattern = "^" + regexp.QuoteMeta(match.Exact) + "$"
case *policyv1.LogMatcher_StartsWith:
    pattern = "^" + regexp.QuoteMeta(match.StartsWith)
case *policyv1.LogMatcher_EndsWith:
    pattern = regexp.QuoteMeta(match.EndsWith) + "$"
case *policyv1.LogMatcher_Contains:
    pattern = regexp.QuoteMeta(match.Contains)
default:
    continue
}

key := MatchKey{
    Selector:        selector,
    Negated:         m.GetNegate(),
    CaseInsensitive: m.GetCaseInsensitive(),
}
```

Use Hyperscan's Caseless flag:

```go
func (c *Compiler) compileGroup(entries []patternEntry) (*CompiledDatabase, error) {
    for i, e := range entries {
        flags := hyperscan.SomLeftMost
        if e.caseInsensitive {
            flags |= hyperscan.Caseless
        }
        patterns[i] = hyperscan.NewPattern(e.pattern, flags)
        patterns[i].Id = i
        // ...
    }
}
```

### 3.4 Update JSON Parser

**File**: `internal/jsonpolicy/parser.go`

```go
func (p *Parser) convertLogMatcher(m LogMatcher) (*policyv1.LogMatcher, error) {
    matcher := &policyv1.LogMatcher{
        Negate:          m.Negated,
        CaseInsensitive: m.CaseInsensitive,
    }

    if err := p.setFieldSelector(matcher, m); err != nil {
        return nil, err
    }

    // Set match type (exactly one must be set)
    if m.Exists != nil {
        matcher.Match = &policyv1.LogMatcher_Exists{Exists: *m.Exists}
    } else if m.Exact != "" {
        matcher.Match = &policyv1.LogMatcher_Exact{Exact: m.Exact}
    } else if m.Regex != "" {
        if _, err := regexp.Compile(m.Regex); err != nil {
            return nil, fmt.Errorf("invalid regex: %w", err)
        }
        matcher.Match = &policyv1.LogMatcher_Regex{Regex: m.Regex}
    } else if m.StartsWith != "" {
        matcher.Match = &policyv1.LogMatcher_StartsWith{StartsWith: m.StartsWith}
    } else if m.EndsWith != "" {
        matcher.Match = &policyv1.LogMatcher_EndsWith{EndsWith: m.EndsWith}
    } else if m.Contains != "" {
        matcher.Match = &policyv1.LogMatcher_Contains{Contains: m.Contains}
    } else {
        return nil, NewParseError("matcher", "must have a match type")
    }

    return matcher, nil
}
```

---

## Task 4: Implement Sampling Key Support

### 4.1 Proto Structure

`LogSampleKey` is a separate message with the same field selector pattern:

```protobuf
message LogSampleKey {
  oneof field {
    LogField log_field = 1;
    AttributePath log_attribute = 2;
    AttributePath resource_attribute = 3;
    AttributePath scope_attribute = 4;
  }
}
```

`LogTarget` has: `LogSampleKey sample_key = 4`

### 4.2 Update CompiledPolicy

**File**: `internal/engine/compiled.go`

```go
type CompiledPolicy struct {
    ID           string
    Index        int
    Keep         Keep
    SampleKey    *FieldSelector  // NEW
    MatcherCount int
    Stats        *PolicyStats
}
```

Parse sample_key in `Compile()`:

```go
var sampleKey *FieldSelector
if sk := log.GetSampleKey(); sk != nil {
    sel := FieldSelectorFromLogSampleKey(sk)
    sampleKey = &sel
}

compiled := &CompiledPolicy{
    ID:           id,
    Index:        idx,
    Keep:         keep,
    SampleKey:    sampleKey,
    MatcherCount: len(log.GetMatch()),
    Stats:        stats[id],
}
```

Add helper function:

```go
func FieldSelectorFromLogSampleKey(sk *policyv1.LogSampleKey) FieldSelector {
    switch f := sk.GetField().(type) {
    case *policyv1.LogSampleKey_LogField:
        return FieldSelector{Field: int32(f.LogField)}
    case *policyv1.LogSampleKey_LogAttribute:
        return FieldSelector{AttrScope: AttrScopeRecord, AttrPath: f.LogAttribute.GetPath()}
    case *policyv1.LogSampleKey_ResourceAttribute:
        return FieldSelector{AttrScope: AttrScopeResource, AttrPath: f.ResourceAttribute.GetPath()}
    case *policyv1.LogSampleKey_ScopeAttribute:
        return FieldSelector{AttrScope: AttrScopeScope, AttrPath: f.ScopeAttribute.GetPath()}
    default:
        return FieldSelector{}
    }
}
```

### 4.3 Implement Hash-Based Sampling

**File**: `engine.go`

```go
import "hash/fnv"

// Update Evaluate() to pass record to applyKeepAction
return e.applyKeepAction(bestPolicy, record)

func (e *PolicyEngine) applyKeepAction(policy *engine.CompiledPolicy, record LogMatchable) EvaluateResult {
    switch policy.Keep.Action {
    case KeepSample:
        var sampleInput []byte
        if policy.SampleKey != nil {
            sampleInput = getFieldValue(record, *policy.SampleKey)
        }

        if shouldSample(sampleInput, policy.Keep.Value) {
            if policy.Stats != nil {
                policy.Stats.RecordSample()
            }
            return ResultKeep
        }
        if policy.Stats != nil {
            policy.Stats.RecordDrop()
        }
        return ResultDrop
    // ... rest unchanged
    }
}

func shouldSample(key []byte, percentage float64) bool {
    if len(key) == 0 {
        // No sample key - non-deterministic behavior
        // Could use random or time-based, for now keep all
        return true
    }

    h := fnv.New64a()
    h.Write(key)
    hashVal := h.Sum64()

    threshold := uint64(percentage * float64(^uint64(0)) / 100)
    return hashVal < threshold
}
```

### 4.4 Update JSON Parser

**File**: `internal/jsonpolicy/types.go`

```go
type SampleKey struct {
    LogField          string         `json:"log_field,omitempty"`
    LogAttribute      *AttributePath `json:"log_attribute,omitempty"`
    ResourceAttribute *AttributePath `json:"resource_attribute,omitempty"`
    ScopeAttribute    *AttributePath `json:"scope_attribute,omitempty"`
}

type Log struct {
    Match     []LogMatcher `json:"match"`
    Keep      KeepValue    `json:"keep"`
    SampleKey *SampleKey   `json:"sample_key,omitempty"`
}
```

**File**: `internal/jsonpolicy/parser.go`

```go
func (p *Parser) convertLogTarget(log *Log) (*policyv1.LogTarget, error) {
    // ... existing matcher and keep conversion ...

    target := &policyv1.LogTarget{
        Match: matchers,
        Keep:  keep,
    }

    if log.SampleKey != nil {
        sk, err := p.convertSampleKey(log.SampleKey)
        if err != nil {
            return nil, err
        }
        target.SampleKey = sk
    }

    return target, nil
}

func (p *Parser) convertSampleKey(sk *SampleKey) (*policyv1.LogSampleKey, error) {
    result := &policyv1.LogSampleKey{}

    count := 0
    if sk.LogField != "" { count++ }
    if sk.LogAttribute != nil { count++ }
    if sk.ResourceAttribute != nil { count++ }
    if sk.ScopeAttribute != nil { count++ }

    if count != 1 {
        return nil, NewParseError("sample_key", "must specify exactly one field type")
    }

    if sk.LogField != "" {
        field, ok := parseLogField(sk.LogField)
        if !ok {
            return nil, NewParseError("sample_key.log_field", "unknown field")
        }
        result.Field = &policyv1.LogSampleKey_LogField{LogField: field}
    } else if sk.LogAttribute != nil {
        result.Field = &policyv1.LogSampleKey_LogAttribute{
            LogAttribute: &policyv1.AttributePath{Path: sk.LogAttribute.Path},
        }
    } else if sk.ResourceAttribute != nil {
        result.Field = &policyv1.LogSampleKey_ResourceAttribute{
            ResourceAttribute: &policyv1.AttributePath{Path: sk.ResourceAttribute.Path},
        }
    } else if sk.ScopeAttribute != nil {
        result.Field = &policyv1.LogSampleKey_ScopeAttribute{
            ScopeAttribute: &policyv1.AttributePath{Path: sk.ScopeAttribute.Path},
        }
    }

    return result, nil
}
```

---

## Task 5: Add Tests

### 5.1 Nested Attribute Tests

```go
func TestNestedAttributeAccess(t *testing.T) {
    record := &SimpleLogRecord{
        LogAttributes: map[string]any{
            "http": map[string]any{
                "request": map[string]any{
                    "method": "GET",
                },
            },
        },
    }

    val := record.GetAttribute(AttrScopeRecord, []string{"http", "request", "method"})
    assert.Equal(t, []byte("GET"), val)

    // Missing intermediate
    val = record.GetAttribute(AttrScopeRecord, []string{"http", "missing", "field"})
    assert.Nil(t, val)

    // Single segment (backward compatible pattern)
    record2 := &SimpleLogRecord{
        LogAttributes: map[string]any{"user_id": "abc123"},
    }
    val = record2.GetAttribute(AttrScopeRecord, []string{"user_id"})
    assert.Equal(t, []byte("abc123"), val)
}

func TestAttributePathUnmarshal(t *testing.T) {
    tests := []struct {
        name     string
        json     string
        expected []string
    }{
        {"canonical", `{"path": ["http", "method"]}`, []string{"http", "method"}},
        {"shorthand array", `["http", "method"]`, []string{"http", "method"}},
        {"shorthand string", `"user_id"`, []string{"user_id"}},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            var path AttributePath
            err := json.Unmarshal([]byte(tt.json), &path)
            require.NoError(t, err)
            assert.Equal(t, tt.expected, path.Path)
        })
    }
}
```

### 5.2 New Matcher Tests

```go
func TestStartsWithMatcher(t *testing.T) {
    // Match "ERROR: something" with starts_with: "ERROR"
}

func TestEndsWithMatcher(t *testing.T) {
    // Match "file.log" with ends_with: ".log"
}

func TestContainsMatcher(t *testing.T) {
    // Match "hello world" with contains: "wor"
}

func TestCaseInsensitiveMatcher(t *testing.T) {
    // Test case_insensitive: true with exact, regex, starts_with, etc.
}
```

### 5.3 Sampling Key Tests

```go
func TestSamplingWithKey(t *testing.T) {
    key := []byte("user-123")
    percentage := 50.0

    result := shouldSample(key, percentage)
    for i := 0; i < 1000; i++ {
        assert.Equal(t, result, shouldSample(key, percentage),
            "Same key should always produce same result")
    }
}

func TestSamplingDistribution(t *testing.T) {
    percentage := 50.0
    sampled := 0
    total := 10000

    for i := 0; i < total; i++ {
        key := []byte(fmt.Sprintf("key-%d", i))
        if shouldSample(key, percentage) {
            sampled++
        }
    }

    ratio := float64(sampled) / float64(total) * 100
    assert.InDelta(t, percentage, ratio, 5.0)
}
```

### 5.4 Update testdata/policies.json

Add policies exercising new features.

---

## Task 6: Documentation Updates

Update README.md with:

- Nested attribute path syntax and three input forms
- New matcher types (starts_with, ends_with, contains)
- case_insensitive flag
- sample_key usage for consistent sampling

---

## Implementation Order

1. **Proto regeneration** - `task proto:generate` with v1.2.0
2. **Nested accessors** (BREAKING) - Update interface and implementations
3. **Optimized matchers** - Add new match types and case_insensitive
4. **Sampling key** - Add sample_key support
5. **Tests** - Comprehensive coverage
6. **Documentation** - Update README

## Breaking Changes Summary

1. **Matchable interface**: `GetAttribute(scope, name string)` →
   `GetAttribute(scope, path []string)`

2. **SimpleLogRecord**: Attribute maps change from `map[string][]byte` to
   `map[string]any`

3. **Proto attribute fields**: `string log_attribute` →
   `AttributePath log_attribute`

## Files to Modify

| File                             | Changes                                                                                  |
| -------------------------------- | ---------------------------------------------------------------------------------------- |
| `internal/engine/match_key.go`   | `FieldSelector.AttrPath`, `FieldSelectorFromLogMatcher`, `FieldSelectorFromLogSampleKey` |
| `internal/engine/compiled.go`    | New match types, `CaseInsensitive` in `MatchKey`, `SampleKey` in `CompiledPolicy`        |
| `matchable.go`                   | `GetAttribute(scope, path []string)`, `SimpleLogRecord`, `traversePath`                  |
| `engine.go`                      | `getFieldValue` with path, `applyKeepAction` with record, `shouldSample`                 |
| `internal/jsonpolicy/types.go`   | `AttributePath`, updated `LogMatcher`, `SampleKey`, `Log`                                |
| `internal/jsonpolicy/parser.go`  | Handle new match types, `convertSampleKey`                                               |
| `policy_test.go`                 | New test cases                                                                           |
| `internal/engine/engine_test.go` | New test cases                                                                           |
