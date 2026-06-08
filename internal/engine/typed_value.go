package engine

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"

	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
)

// TypedValueKind discriminates TypedValue variants.
type TypedValueKind uint8

const (
	// TypedValueAbsent signals the field has no value at this ref.
	TypedValueAbsent TypedValueKind = iota
	TypedValueString
	TypedValueBool
	TypedValueInt
	TypedValueDouble
	TypedValueBytes
)

// TypedValue is the typed value of a single field, returned by the consumer's
// TypedValue accessor. Mirrors the spec's set of comparable field types
// (string, bool, int, double, bytes). Only the variant selected by Kind is
// meaningful.
//
// When a consumer does not provide a TypedValue accessor, the engine falls
// back to the string Value accessor and wraps the result as Kind=String, so
// typed matchers that target strings still work.
type TypedValue struct {
	Kind   TypedValueKind
	Str    string
	Bool   bool
	Int    int64
	Double float64
	Bytes  []byte
}

// IsAbsent reports whether the field is missing.
func (v TypedValue) IsAbsent() bool { return v.Kind == TypedValueAbsent }

// CompiledValue is the target of an `equals` matcher, normalized at compile
// time. hex_value is decoded to Bytes once; the runtime path only sees raw
// bytes. There is no String variant — string equality goes through `exact`
// per the spec.
type CompiledValue struct {
	Kind   TypedValueKind // Bool, Int, Double, or Bytes
	Bool   bool
	Int    int64
	Double float64
	Bytes  []byte
}

// CompiledNumericValue is the target of a gt/gte/lt/lte matcher. Only int and
// double are admissible by the proto schema, so the runtime never has to
// reject non-numeric targets — they're unrepresentable.
type CompiledNumericValue struct {
	Kind   TypedValueKind // Int or Double
	Int    int64
	Double float64
}

// TypedOp identifies a typed-comparison matcher.
type TypedOp uint8

const (
	TypedOpEquals TypedOp = iota
	TypedOpGT
	TypedOpGTE
	TypedOpLT
	TypedOpLTE
)

// CompiledTypedMatcher is a compiled typed-comparison matcher. The Op selects
// whether Equals or Numeric carries the target; the unused one has Kind ==
// TypedValueAbsent.
type CompiledTypedMatcher struct {
	Op      TypedOp
	Equals  CompiledValue        // populated when Op == TypedOpEquals
	Numeric CompiledNumericValue // populated otherwise
}

// Evaluate returns true when the typed-comparison matcher fires against the
// given field value. A missing field, type mismatch, or non-numeric field in
// a numeric comparison all return false (fail-open per spec — never an
// error). Negate is applied by the caller.
func (m CompiledTypedMatcher) Evaluate(field TypedValue) bool {
	if field.IsAbsent() {
		return false
	}
	if m.Op == TypedOpEquals {
		return equalsMatch(field, m.Equals)
	}
	return numericCmp(field, m.Op, m.Numeric)
}

// equalsMatch implements the equals semantics: same type and same value, with
// int/double cross-domain promotion (so int 5 equals double 5.0). All other
// type pairings are non-matches.
func equalsMatch(field TypedValue, target CompiledValue) bool {
	switch target.Kind {
	case TypedValueBool:
		return field.Kind == TypedValueBool && field.Bool == target.Bool
	case TypedValueInt:
		if field.Kind == TypedValueInt {
			return field.Int == target.Int
		}
		if field.Kind == TypedValueDouble {
			return field.Double == float64(target.Int)
		}
		return false
	case TypedValueDouble:
		if field.Kind == TypedValueDouble {
			return field.Double == target.Double
		}
		if field.Kind == TypedValueInt {
			return float64(field.Int) == target.Double
		}
		return false
	case TypedValueBytes:
		return field.Kind == TypedValueBytes && bytes.Equal(field.Bytes, target.Bytes)
	}
	return false
}

// numericCmp coerces the field value to float64 for comparison against the
// target. Non-numeric field values are non-matches. Coercion to float64 loses
// precision past 2^53; equality (which needs full int precision) is handled
// separately by equalsMatch.
func numericCmp(field TypedValue, op TypedOp, target CompiledNumericValue) bool {
	fv, ok := asFloat64(field)
	if !ok {
		return false
	}
	tv := target.AsFloat64()
	switch op {
	case TypedOpGT:
		return fv > tv
	case TypedOpGTE:
		return fv >= tv
	case TypedOpLT:
		return fv < tv
	case TypedOpLTE:
		return fv <= tv
	}
	return false
}

func asFloat64(v TypedValue) (float64, bool) {
	switch v.Kind {
	case TypedValueInt:
		return float64(v.Int), true
	case TypedValueDouble:
		return v.Double, true
	}
	return 0, false
}

// AsFloat64 returns the numeric value as float64.
func (v CompiledNumericValue) AsFloat64() float64 {
	if v.Kind == TypedValueInt {
		return float64(v.Int)
	}
	return v.Double
}

// TypedCheck represents a compiled typed-comparison matcher together with the
// field it inspects and bookkeeping for the policy it belongs to.
type TypedCheck[T FieldType] struct {
	Ref         FieldRef[T]
	Matcher     CompiledTypedMatcher
	Negate      bool
	PolicyID    string
	PolicyIndex int
	MatchIndex  int
}

// typedMatcher is satisfied by *LogMatcher, *MetricMatcher, and *TraceMatcher
// — proto-generated getters return the inner value or nil, so one extraction
// helper works for all three.
type typedMatcher interface {
	GetEquals() *policyv1.Value
	GetGt() *policyv1.NumericValue
	GetGte() *policyv1.NumericValue
	GetLt() *policyv1.NumericValue
	GetLte() *policyv1.NumericValue
}

// extractTypedMatcher returns (matcher, true, nil) for a well-formed typed
// matcher, (_, true, err) for one with an invalid value, or (_, false, nil)
// when m is not a typed matcher (the string/exists path handles it).
func extractTypedMatcher(m typedMatcher) (CompiledTypedMatcher, bool, error) {
	if v := m.GetEquals(); v != nil {
		cv, err := compileValue(v)
		return CompiledTypedMatcher{Op: TypedOpEquals, Equals: cv}, true, err
	}
	if v := m.GetGt(); v != nil {
		cn, err := compileNumeric(v)
		return CompiledTypedMatcher{Op: TypedOpGT, Numeric: cn}, true, err
	}
	if v := m.GetGte(); v != nil {
		cn, err := compileNumeric(v)
		return CompiledTypedMatcher{Op: TypedOpGTE, Numeric: cn}, true, err
	}
	if v := m.GetLt(); v != nil {
		cn, err := compileNumeric(v)
		return CompiledTypedMatcher{Op: TypedOpLT, Numeric: cn}, true, err
	}
	if v := m.GetLte(); v != nil {
		cn, err := compileNumeric(v)
		return CompiledTypedMatcher{Op: TypedOpLTE, Numeric: cn}, true, err
	}
	return CompiledTypedMatcher{}, false, nil
}

// compileValue decodes a proto Value to a CompiledValue. hex_value is decoded
// to bytes at compile time so the runtime path never sees hex.
func compileValue(v *policyv1.Value) (CompiledValue, error) {
	switch x := v.GetValue().(type) {
	case *policyv1.Value_BoolValue:
		return CompiledValue{Kind: TypedValueBool, Bool: x.BoolValue}, nil
	case *policyv1.Value_IntValue:
		return CompiledValue{Kind: TypedValueInt, Int: x.IntValue}, nil
	case *policyv1.Value_DoubleValue:
		return CompiledValue{Kind: TypedValueDouble, Double: x.DoubleValue}, nil
	case *policyv1.Value_BytesValue:
		return CompiledValue{Kind: TypedValueBytes, Bytes: x.BytesValue}, nil
	case *policyv1.Value_HexValue:
		decoded, err := hex.DecodeString(x.HexValue)
		if err != nil {
			return CompiledValue{}, fmt.Errorf("invalid hex_value %q: %w", x.HexValue, err)
		}
		return CompiledValue{Kind: TypedValueBytes, Bytes: decoded}, nil
	}
	return CompiledValue{}, errors.New("equals value oneof is unset")
}

// compileNumeric decodes a proto NumericValue to a CompiledNumericValue.
func compileNumeric(v *policyv1.NumericValue) (CompiledNumericValue, error) {
	switch x := v.GetValue().(type) {
	case *policyv1.NumericValue_IntValue:
		return CompiledNumericValue{Kind: TypedValueInt, Int: x.IntValue}, nil
	case *policyv1.NumericValue_DoubleValue:
		return CompiledNumericValue{Kind: TypedValueDouble, Double: x.DoubleValue}, nil
	}
	return CompiledNumericValue{}, errors.New("numeric value oneof is unset")
}
