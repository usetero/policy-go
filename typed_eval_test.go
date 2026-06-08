package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
)

// typedAttrLog is a record type that supports typed attribute values, mirroring
// the Rust SDK's TypedAttrLog test fixture. Each key maps to one TypedValue so
// the test setup can express any of bool/int/double/bytes/string.
type typedAttrLog struct {
	attrs map[string]TypedValue
}

func newTypedAttrLog() *typedAttrLog {
	return &typedAttrLog{attrs: make(map[string]TypedValue)}
}

func (l *typedAttrLog) withInt(k string, v int64) *typedAttrLog {
	l.attrs[k] = TypedValueOfInt(v)
	return l
}
func (l *typedAttrLog) withDouble(k string, v float64) *typedAttrLog {
	l.attrs[k] = TypedValueOfDouble(v)
	return l
}
func (l *typedAttrLog) withBool(k string, v bool) *typedAttrLog {
	l.attrs[k] = TypedValueOfBool(v)
	return l
}
func (l *typedAttrLog) withString(k, v string) *typedAttrLog {
	l.attrs[k] = TypedValueOfString(v)
	return l
}
func (l *typedAttrLog) withBytes(k string, v []byte) *typedAttrLog {
	l.attrs[k] = TypedValueOfBytes(v)
	return l
}

// typedAttrOpts wires the typedAttrLog into the engine. It implements
// LogAttribute lookups only — other field selectors are absent.
func typedAttrOpts() []LogOption[*typedAttrLog] {
	attrPath := func(ref LogFieldRef) (string, bool) {
		if ref.AttrScope == AttrScopeRecord && len(ref.AttrPath) > 0 {
			return ref.AttrPath[0], true
		}
		return "", false
	}
	return []LogOption[*typedAttrLog]{
		WithLogValue(func(r *typedAttrLog, ref LogFieldRef) []byte {
			key, ok := attrPath(ref)
			if !ok {
				return nil
			}
			v, ok := r.attrs[key]
			if !ok || v.Kind != TypedValueString {
				return nil
			}
			return []byte(v.Str)
		}),
		WithLogExists(func(r *typedAttrLog, ref LogFieldRef) bool {
			key, ok := attrPath(ref)
			if !ok {
				return false
			}
			_, present := r.attrs[key]
			return present
		}),
		WithLogTypedValue(func(r *typedAttrLog, ref LogFieldRef) TypedValue {
			key, ok := attrPath(ref)
			if !ok {
				return TypedValue{}
			}
			return r.attrs[key]
		}),
	}
}

// makeLogPolicy is a convenience for one-matcher log policies in these tests.
func makeLogPolicy(id, key string, match *policyv1.LogMatcher, keep string) *policyv1.Policy {
	match.Field = &policyv1.LogMatcher_LogAttribute{LogAttribute: &policyv1.AttributePath{Path: []string{key}}}
	return &policyv1.Policy{
		Id: id,
		Target: &policyv1.Policy_Log{
			Log: &policyv1.LogTarget{
				Match: []*policyv1.LogMatcher{match},
				Keep:  keep,
			},
		},
	}
}

func runTypedEval(t *testing.T, policy *policyv1.Policy, rec *typedAttrLog) EvaluateResult {
	t.Helper()
	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{policy})
	_, err := registry.Register(provider)
	require.NoError(t, err)
	engine := NewPolicyEngine(registry)
	return EvaluateLog(engine, rec, typedAttrOpts()...)
}

// ============================================================================
// equals
// ============================================================================

func TestTypedEqualsIntMatches(t *testing.T) {
	policy := makeLogPolicy("drop-200", "status",
		&policyv1.LogMatcher{Match: &policyv1.LogMatcher_Equals{
			Equals: &policyv1.Value{Value: &policyv1.Value_IntValue{IntValue: 200}},
		}}, "none")

	assert.Equal(t, ResultDrop, runTypedEval(t, policy, newTypedAttrLog().withInt("status", 200)),
		"int field equal to int target → match")
	assert.Equal(t, ResultNoMatch, runTypedEval(t, policy, newTypedAttrLog().withInt("status", 404)),
		"int field different from int target → no match")
}

func TestTypedEqualsBoolMatches(t *testing.T) {
	policy := makeLogPolicy("drop-cached", "cache.hit",
		&policyv1.LogMatcher{Match: &policyv1.LogMatcher_Equals{
			Equals: &policyv1.Value{Value: &policyv1.Value_BoolValue{BoolValue: true}},
		}}, "none")

	assert.Equal(t, ResultDrop, runTypedEval(t, policy, newTypedAttrLog().withBool("cache.hit", true)))
	assert.Equal(t, ResultNoMatch, runTypedEval(t, policy, newTypedAttrLog().withBool("cache.hit", false)))
}

func TestTypedEqualsHexBytesMatches(t *testing.T) {
	// hex_value gets decoded once at compile time; the runtime compares raw bytes.
	policy := makeLogPolicy("drop-trace", "trace_id_attr",
		&policyv1.LogMatcher{Match: &policyv1.LogMatcher_Equals{
			Equals: &policyv1.Value{Value: &policyv1.Value_HexValue{HexValue: "deadbeef"}},
		}}, "none")

	assert.Equal(t, ResultDrop, runTypedEval(t, policy,
		newTypedAttrLog().withBytes("trace_id_attr", []byte{0xde, 0xad, 0xbe, 0xef})))
	assert.Equal(t, ResultNoMatch, runTypedEval(t, policy,
		newTypedAttrLog().withBytes("trace_id_attr", []byte{0x01, 0x02, 0x03, 0x04})))
}

// ============================================================================
// gt / gte / lt / lte
// ============================================================================

func TestTypedRangeAndLogic(t *testing.T) {
	// duration_ms >= 500 → drop. Cover boundary, below, and above.
	policy := makeLogPolicy("drop-slow", "duration_ms",
		&policyv1.LogMatcher{Match: &policyv1.LogMatcher_Gte{
			Gte: &policyv1.NumericValue{Value: &policyv1.NumericValue_IntValue{IntValue: 500}},
		}}, "none")

	assert.Equal(t, ResultDrop, runTypedEval(t, policy, newTypedAttrLog().withInt("duration_ms", 500)),
		"500 >= 500 → match")
	assert.Equal(t, ResultDrop, runTypedEval(t, policy, newTypedAttrLog().withInt("duration_ms", 1000)),
		"1000 >= 500 → match")
	assert.Equal(t, ResultNoMatch, runTypedEval(t, policy, newTypedAttrLog().withInt("duration_ms", 100)),
		"100 < 500 → no match")
}

func TestTypedLtDouble(t *testing.T) {
	policy := makeLogPolicy("sample-fast", "duration_s",
		&policyv1.LogMatcher{Match: &policyv1.LogMatcher_Lt{
			Lt: &policyv1.NumericValue{Value: &policyv1.NumericValue_DoubleValue{DoubleValue: 0.1}},
		}}, "none")

	assert.Equal(t, ResultDrop, runTypedEval(t, policy, newTypedAttrLog().withDouble("duration_s", 0.05)))
	assert.Equal(t, ResultNoMatch, runTypedEval(t, policy, newTypedAttrLog().withDouble("duration_s", 0.5)))
}

// ============================================================================
// Type-mismatch fail-open
// ============================================================================

func TestTypedTypeMismatchIsNonMatch(t *testing.T) {
	policy := makeLogPolicy("drop-status-200", "status",
		&policyv1.LogMatcher{Match: &policyv1.LogMatcher_Equals{
			Equals: &policyv1.Value{Value: &policyv1.Value_IntValue{IntValue: 200}},
		}}, "none")

	// Field present but a string ("200"). int target ≠ string field → no match.
	assert.Equal(t, ResultNoMatch, runTypedEval(t, policy, newTypedAttrLog().withString("status", "200")),
		"string field never matches an int target")
}

func TestTypedNumericComparisonAgainstNonNumeric(t *testing.T) {
	policy := makeLogPolicy("drop-big", "size",
		&policyv1.LogMatcher{Match: &policyv1.LogMatcher_Gt{
			Gt: &policyv1.NumericValue{Value: &policyv1.NumericValue_IntValue{IntValue: 100}},
		}}, "none")

	// Bool field can't be compared numerically — no match, no error.
	assert.Equal(t, ResultNoMatch, runTypedEval(t, policy, newTypedAttrLog().withBool("size", true)))
}

// ============================================================================
// Cross-domain numeric promotion: int target matches double field and vice versa
// ============================================================================

func TestTypedNumericCrossDomainIntEqualsDouble(t *testing.T) {
	intTarget := makeLogPolicy("drop-five-int", "n",
		&policyv1.LogMatcher{Match: &policyv1.LogMatcher_Equals{
			Equals: &policyv1.Value{Value: &policyv1.Value_IntValue{IntValue: 5}},
		}}, "none")
	doubleTarget := makeLogPolicy("drop-five-dbl", "n",
		&policyv1.LogMatcher{Match: &policyv1.LogMatcher_Equals{
			Equals: &policyv1.Value{Value: &policyv1.Value_DoubleValue{DoubleValue: 5.0}},
		}}, "none")

	// int target vs double field
	assert.Equal(t, ResultDrop, runTypedEval(t, intTarget, newTypedAttrLog().withDouble("n", 5.0)))
	// double target vs int field
	assert.Equal(t, ResultDrop, runTypedEval(t, doubleTarget, newTypedAttrLog().withInt("n", 5)))
	// int target, double field with fractional value
	assert.Equal(t, ResultNoMatch, runTypedEval(t, intTarget, newTypedAttrLog().withDouble("n", 5.5)))
}

// ============================================================================
// Negation
// ============================================================================

func TestTypedNegatedEquals(t *testing.T) {
	policy := makeLogPolicy("drop-not-200", "status",
		&policyv1.LogMatcher{
			Negate: true,
			Match: &policyv1.LogMatcher_Equals{
				Equals: &policyv1.Value{Value: &policyv1.Value_IntValue{IntValue: 200}},
			},
		}, "none")

	assert.Equal(t, ResultNoMatch, runTypedEval(t, policy, newTypedAttrLog().withInt("status", 200)),
		"negated equals matches when target equals — should disqualify")
	assert.Equal(t, ResultDrop, runTypedEval(t, policy, newTypedAttrLog().withInt("status", 500)),
		"negated equals fires when target does not equal")
}

// ============================================================================
// Absent field
// ============================================================================

func TestTypedAbsentFieldIsNonMatch(t *testing.T) {
	policy := makeLogPolicy("drop-status-200", "status",
		&policyv1.LogMatcher{Match: &policyv1.LogMatcher_Equals{
			Equals: &policyv1.Value{Value: &policyv1.Value_IntValue{IntValue: 200}},
		}}, "none")

	// Field not present on record — no match (fail-open).
	assert.Equal(t, ResultNoMatch, runTypedEval(t, policy, newTypedAttrLog()))
}

// ============================================================================
// Default fallback: consumer that didn't implement TypedValue
// ============================================================================

// stringOnlyLog has a single string field and provides Value/Exists but NOT
// TypedValue — exercising the engine's fallback that wraps Value as
// TypedValue.String.
type stringOnlyLog struct{ body string }

func TestTypedFallbackToStringValueAccessor(t *testing.T) {
	// equals against a string-valued field, consumer with no TypedValue
	// accessor. The spec doesn't allow `equals: "foo"` for strings — but a
	// hex_value decoded to bytes against a string-wrapped accessor still
	// returns a TypedValue.String, which the bytes target won't match. So
	// this test just confirms the fallback path returns String without
	// crashing, and a string field with a non-string typed target produces a
	// non-match (fail-open).
	policy := makeLogPolicy("drop-200", "status",
		&policyv1.LogMatcher{Match: &policyv1.LogMatcher_Equals{
			Equals: &policyv1.Value{Value: &policyv1.Value_IntValue{IntValue: 200}},
		}}, "none")

	registry := NewPolicyRegistry()
	provider := newStaticProvider([]*policyv1.Policy{policy})
	_, err := registry.Register(provider)
	require.NoError(t, err)
	engine := NewPolicyEngine(registry)

	rec := &stringOnlyLog{body: "200"}
	result := EvaluateLog(engine, rec,
		WithLogValue(func(r *stringOnlyLog, ref LogFieldRef) []byte {
			if ref.AttrScope == AttrScopeRecord && len(ref.AttrPath) > 0 && ref.AttrPath[0] == "status" {
				return []byte(r.body)
			}
			return nil
		}),
		WithLogExists(func(r *stringOnlyLog, ref LogFieldRef) bool {
			return ref.AttrScope == AttrScopeRecord && len(ref.AttrPath) > 0 && ref.AttrPath[0] == "status"
		}),
	)
	assert.Equal(t, ResultNoMatch, result, "string field via fallback never matches an int typed target")
}
