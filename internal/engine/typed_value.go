package engine

import (
	"encoding/hex"
	"errors"
	"fmt"

	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
)

// FieldValueKind discriminates the variants of FieldValue.
type FieldValueKind uint8

const (
	// FieldValueAbsent signals the consumer's TypedValue accessor saw no value
	// at the ref (either because the field is missing or because the consumer
	// hasn't registered a TypedValue accessor for that ref's type).
	FieldValueAbsent FieldValueKind = iota
	FieldValueString
	FieldValueBool
	FieldValueInt
	FieldValueDouble
	FieldValueBytes
)

// FieldValue is the typed value of a single field. Used as the compile-time
// representation of a Value/NumericValue literal, and as the runtime return
// type for the (not-yet-wired) TypedValue accessor.
type FieldValue struct {
	Kind   FieldValueKind
	Str    string
	Bool   bool
	Int    int64
	Double float64
	Bytes  []byte
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

// TypedCheck represents a compiled typed-comparison matcher. Target is the
// literal value to compare against, already normalized at compile time
// (e.g., hex_value decoded to Bytes).
//
// Currently the engine compiles TypedChecks but does not evaluate them — a
// policy containing one stays inert because its matchCount is unreachable. A
// follow-up will add evaluation.
type TypedCheck[T FieldType] struct {
	Ref         FieldRef[T]
	Op          TypedOp
	Target      FieldValue
	Negate      bool
	PolicyID    string
	PolicyIndex int
	MatchIndex  int
}

// compileEquals converts a proto Value into a FieldValue, decoding hex_value
// at compile time so the runtime path only deals with bytes.
func compileEquals(v *policyv1.Value) (FieldValue, error) {
	if v == nil {
		return FieldValue{}, errors.New("equals value is unset")
	}
	switch x := v.GetValue().(type) {
	case *policyv1.Value_BoolValue:
		return FieldValue{Kind: FieldValueBool, Bool: x.BoolValue}, nil
	case *policyv1.Value_IntValue:
		return FieldValue{Kind: FieldValueInt, Int: x.IntValue}, nil
	case *policyv1.Value_DoubleValue:
		return FieldValue{Kind: FieldValueDouble, Double: x.DoubleValue}, nil
	case *policyv1.Value_BytesValue:
		return FieldValue{Kind: FieldValueBytes, Bytes: x.BytesValue}, nil
	case *policyv1.Value_HexValue:
		decoded, err := hex.DecodeString(x.HexValue)
		if err != nil {
			return FieldValue{}, fmt.Errorf("invalid hex_value %q: %w", x.HexValue, err)
		}
		return FieldValue{Kind: FieldValueBytes, Bytes: decoded}, nil
	default:
		return FieldValue{}, errors.New("equals value oneof is unset")
	}
}

// compileNumeric converts a proto NumericValue into a FieldValue suitable for
// numeric comparison.
func compileNumeric(v *policyv1.NumericValue) (FieldValue, error) {
	if v == nil {
		return FieldValue{}, errors.New("numeric value is unset")
	}
	switch x := v.GetValue().(type) {
	case *policyv1.NumericValue_IntValue:
		return FieldValue{Kind: FieldValueInt, Int: x.IntValue}, nil
	case *policyv1.NumericValue_DoubleValue:
		return FieldValue{Kind: FieldValueDouble, Double: x.DoubleValue}, nil
	default:
		return FieldValue{}, errors.New("numeric value oneof is unset")
	}
}

// extractLogTypedMatch returns (op, target, true, nil) for a typed matcher
// (equals/gt/gte/lt/lte), (0, _, true, err) for a typed matcher with an
// invalid value, or (0, _, false, nil) when the matcher uses a non-typed
// match condition that the existing string/exists path handles.
func extractLogTypedMatch(m *policyv1.LogMatcher) (TypedOp, FieldValue, bool, error) {
	switch x := m.GetMatch().(type) {
	case *policyv1.LogMatcher_Equals:
		v, err := compileEquals(x.Equals)
		return TypedOpEquals, v, true, err
	case *policyv1.LogMatcher_Gt:
		v, err := compileNumeric(x.Gt)
		return TypedOpGT, v, true, err
	case *policyv1.LogMatcher_Gte:
		v, err := compileNumeric(x.Gte)
		return TypedOpGTE, v, true, err
	case *policyv1.LogMatcher_Lt:
		v, err := compileNumeric(x.Lt)
		return TypedOpLT, v, true, err
	case *policyv1.LogMatcher_Lte:
		v, err := compileNumeric(x.Lte)
		return TypedOpLTE, v, true, err
	}
	return 0, FieldValue{}, false, nil
}

func extractMetricTypedMatch(m *policyv1.MetricMatcher) (TypedOp, FieldValue, bool, error) {
	switch x := m.GetMatch().(type) {
	case *policyv1.MetricMatcher_Equals:
		v, err := compileEquals(x.Equals)
		return TypedOpEquals, v, true, err
	case *policyv1.MetricMatcher_Gt:
		v, err := compileNumeric(x.Gt)
		return TypedOpGT, v, true, err
	case *policyv1.MetricMatcher_Gte:
		v, err := compileNumeric(x.Gte)
		return TypedOpGTE, v, true, err
	case *policyv1.MetricMatcher_Lt:
		v, err := compileNumeric(x.Lt)
		return TypedOpLT, v, true, err
	case *policyv1.MetricMatcher_Lte:
		v, err := compileNumeric(x.Lte)
		return TypedOpLTE, v, true, err
	}
	return 0, FieldValue{}, false, nil
}

func extractTraceTypedMatch(m *policyv1.TraceMatcher) (TypedOp, FieldValue, bool, error) {
	switch x := m.GetMatch().(type) {
	case *policyv1.TraceMatcher_Equals:
		v, err := compileEquals(x.Equals)
		return TypedOpEquals, v, true, err
	case *policyv1.TraceMatcher_Gt:
		v, err := compileNumeric(x.Gt)
		return TypedOpGT, v, true, err
	case *policyv1.TraceMatcher_Gte:
		v, err := compileNumeric(x.Gte)
		return TypedOpGTE, v, true, err
	case *policyv1.TraceMatcher_Lt:
		v, err := compileNumeric(x.Lt)
		return TypedOpLT, v, true, err
	case *policyv1.TraceMatcher_Lte:
		v, err := compileNumeric(x.Lte)
		return TypedOpLTE, v, true, err
	}
	return 0, FieldValue{}, false, nil
}
