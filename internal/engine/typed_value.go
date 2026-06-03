package engine

import (
	"encoding/hex"
	"errors"
	"fmt"

	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
)

// TypedOp identifies a typed-comparison matcher.
type TypedOp uint8

const (
	TypedOpEquals TypedOp = iota
	TypedOpGT
	TypedOpGTE
	TypedOpLT
	TypedOpLTE
)

// TypedCheck represents a compiled typed-comparison matcher. The target value
// is held as the original proto message — exactly one of EqualsValue or
// NumericValue is set, selected by Op.
//
// The engine compiles TypedChecks but does not evaluate them yet — a policy
// containing one stays inert because its matchCount is unreachable. A
// follow-up will add evaluation; the proto pointers carry everything it needs.
type TypedCheck[T FieldType] struct {
	Ref          FieldRef[T]
	Op           TypedOp
	EqualsValue  *policyv1.Value
	NumericValue *policyv1.NumericValue
	Negate       bool
	PolicyID     string
	PolicyIndex  int
	MatchIndex   int
}

// typedMatcher is satisfied by *LogMatcher, *MetricMatcher, and *TraceMatcher
// — proto-generated getters return the inner value or nil, so the same
// extraction logic works for all three.
type typedMatcher interface {
	GetEquals() *policyv1.Value
	GetGt() *policyv1.NumericValue
	GetGte() *policyv1.NumericValue
	GetLt() *policyv1.NumericValue
	GetLte() *policyv1.NumericValue
}

// typedMatch buffers the typed-matcher data between extraction and the
// builder call. Exactly one of eq/num is non-nil.
type typedMatch struct {
	op  TypedOp
	eq  *policyv1.Value
	num *policyv1.NumericValue
}

// extractTypedMatch returns (typedMatch, true) when m is a typed matcher
// (equals/gt/gte/lt/lte), or the zero value plus false otherwise.
func extractTypedMatch(m typedMatcher) (typedMatch, bool) {
	if v := m.GetEquals(); v != nil {
		return typedMatch{op: TypedOpEquals, eq: v}, true
	}
	if v := m.GetGt(); v != nil {
		return typedMatch{op: TypedOpGT, num: v}, true
	}
	if v := m.GetGte(); v != nil {
		return typedMatch{op: TypedOpGTE, num: v}, true
	}
	if v := m.GetLt(); v != nil {
		return typedMatch{op: TypedOpLT, num: v}, true
	}
	if v := m.GetLte(); v != nil {
		return typedMatch{op: TypedOpLTE, num: v}, true
	}
	return typedMatch{}, false
}

// validate checks the typed match is well-formed: the value oneof is set, and
// any hex_value parses as hexadecimal.
func (t typedMatch) validate() error {
	if t.eq != nil {
		switch x := t.eq.GetValue().(type) {
		case *policyv1.Value_BoolValue, *policyv1.Value_IntValue, *policyv1.Value_DoubleValue, *policyv1.Value_BytesValue:
			return nil
		case *policyv1.Value_HexValue:
			if _, err := hex.DecodeString(x.HexValue); err != nil {
				return fmt.Errorf("invalid hex_value %q: %w", x.HexValue, err)
			}
			return nil
		}
		return errors.New("equals value oneof is unset")
	}
	switch t.num.GetValue().(type) {
	case *policyv1.NumericValue_IntValue, *policyv1.NumericValue_DoubleValue:
		return nil
	}
	return errors.New("numeric value oneof is unset")
}
