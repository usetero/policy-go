package engine

import (
	"errors"
	"fmt"
	"regexp"

	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
)

// TransformKind identifies the type of transform operation.
type TransformKind int

const (
	TransformRemove TransformKind = iota
	TransformRedact
	TransformRename
	TransformAdd
)

// TransformOp is a single compiled transform operation.
type TransformOp struct {
	Kind   TransformKind
	Ref    LogFieldRef    // target field (remove/redact/add) or source field (rename)
	Value  string         // replacement string (redact) or value to set (add)
	To     string         // new field name (rename only)
	Upsert bool           // overwrite if target exists (rename/add)
	Regex  *regexp.Regexp // optional compiled regex for targeted redaction (redact only)
}

// LogAccessor bundles the per-record accessor functions the engine needs to
// evaluate log policies. Callers don't construct it directly — they pass
// LogOption values to EvaluateLog, which assembles a LogAccessor internally.
type LogAccessor[T any] struct {
	// Value returns the field's string value as bytes for pattern matching.
	// Return nil when the field is absent OR when its underlying value is not a string.
	Value func(rec T, ref LogFieldRef) []byte

	// Exists returns true if the field is present regardless of value type.
	Exists func(rec T, ref LogFieldRef) bool

	// Set writes a string value at ref, creating the field if necessary.
	Set func(rec T, ref LogFieldRef, value string)

	// Delete removes the field at ref. Returns true if it existed.
	Delete func(rec T, ref LogFieldRef) bool

	// Move transfers the value at from to to, deleting from.
	Move func(rec T, from, to LogFieldRef)
}

// MetricAccessor bundles the per-record accessor functions the engine needs to
// evaluate metric policies.
type MetricAccessor[T any] struct {
	// Value returns the field's string value as bytes for pattern matching.
	Value func(rec T, ref MetricFieldRef) []byte

	// Exists returns true if the field is present regardless of value type.
	Exists func(rec T, ref MetricFieldRef) bool
}

// TraceAccessor bundles the per-record accessor functions the engine needs to
// evaluate trace policies.
type TraceAccessor[T any] struct {
	// Value returns the field's string value as bytes for pattern matching.
	Value func(rec T, ref TraceFieldRef) []byte

	// Exists returns true if the field is present regardless of value type.
	Exists func(rec T, ref TraceFieldRef) bool

	// Set writes a string value at ref, creating the field if necessary.
	Set func(rec T, ref TraceFieldRef, value string)
}

// ApplyLogTransform applies a single TransformOp using the LogAccessor accessors.
// Returns true if the operation was a hit (field present or write occurred),
// false for a miss. Required primitives (Set/Delete/Move/Exists/Value) for each
// op kind are validated at policy compile time via RequiredPrimitives; if one
// is nil at this point it means the consumer also opted out and the op
// gracefully degrades to a miss.
func ApplyLogTransform[T any](rec T, op TransformOp, a *LogAccessor[T]) bool {
	switch op.Kind {
	case TransformRemove:
		if a.Delete == nil {
			return false
		}
		return a.Delete(rec, op.Ref)

	case TransformRedact:
		if a.Value == nil || a.Set == nil {
			return false
		}
		if op.Regex != nil {
			cur := a.Value(rec, op.Ref)
			if cur == nil {
				return false
			}
			curStr := string(cur)
			if !op.Regex.MatchString(curStr) {
				return false
			}
			a.Set(rec, op.Ref, op.Regex.ReplaceAllString(curStr, op.Value))
			return true
		}
		if a.Exists == nil || !a.Exists(rec, op.Ref) {
			return false
		}
		a.Set(rec, op.Ref, op.Value)
		return true

	case TransformRename:
		if a.Exists == nil || a.Move == nil {
			return false
		}
		if op.Ref.IsField() {
			return false
		}
		if !a.Exists(rec, op.Ref) {
			return false
		}
		toRef := LogFieldRef{
			AttrScope: op.Ref.AttrScope,
			AttrPath:  []string{op.To},
		}
		if !op.Upsert && a.Exists(rec, toRef) {
			return true
		}
		a.Move(rec, op.Ref, toRef)
		return true

	case TransformAdd:
		if a.Exists == nil || a.Set == nil {
			return false
		}
		if !op.Upsert && a.Exists(rec, op.Ref) {
			return true
		}
		a.Set(rec, op.Ref, op.Value)
		return true
	}
	return false
}

// compileLogTransform converts a proto LogTransform into a flat slice of TransformOps.
// Operations are ordered: removes, redacts, renames, adds (matching proto field order).
// All per-op errors are accumulated via errors.Join so callers see every problem
// at once rather than discovering them one fix at a time.
func compileLogTransform(t *policyv1.LogTransform) ([]TransformOp, error) {
	if t == nil {
		return nil, nil
	}

	n := len(t.GetRemove()) + len(t.GetRedact()) + len(t.GetRename()) + len(t.GetAdd())
	if n == 0 {
		return nil, nil
	}

	ops := make([]TransformOp, 0, n)
	var compileErr error

	for i, r := range t.GetRemove() {
		ref, err := fieldRefFromLogRemove(r)
		if err != nil {
			compileErr = errors.Join(compileErr, fmt.Errorf("remove[%d]: %w", i, err))
			continue
		}
		ops = append(ops, TransformOp{Kind: TransformRemove, Ref: ref})
	}

	for i, r := range t.GetRedact() {
		ref, err := fieldRefFromLogRedact(r)
		if err != nil {
			compileErr = errors.Join(compileErr, fmt.Errorf("redact[%d]: %w", i, err))
			continue
		}
		op := TransformOp{Kind: TransformRedact, Ref: ref, Value: r.GetReplacement()}
		if r.Regex != nil {
			re, err := regexp.Compile(r.GetRegex())
			if err != nil {
				compileErr = errors.Join(compileErr, fmt.Errorf("redact[%d]: invalid regex %q: %w", i, r.GetRegex(), err))
				continue
			}
			op.Regex = re
		}
		ops = append(ops, op)
	}

	for i, r := range t.GetRename() {
		ref, err := fieldRefFromLogRename(r)
		if err != nil {
			compileErr = errors.Join(compileErr, fmt.Errorf("rename[%d]: %w", i, err))
			continue
		}
		if r.GetTo() == "" {
			compileErr = errors.Join(compileErr, fmt.Errorf("rename[%d]: to is empty", i))
			continue
		}
		ops = append(ops, TransformOp{
			Kind:   TransformRename,
			Ref:    ref,
			To:     r.GetTo(),
			Upsert: r.GetUpsert(),
		})
	}

	for i, a := range t.GetAdd() {
		ref, err := fieldRefFromLogAdd(a)
		if err != nil {
			compileErr = errors.Join(compileErr, fmt.Errorf("add[%d]: %w", i, err))
			continue
		}
		ops = append(ops, TransformOp{
			Kind:   TransformAdd,
			Ref:    ref,
			Value:  a.GetValue(),
			Upsert: a.GetUpsert(),
		})
	}

	if compileErr != nil {
		return nil, compileErr
	}
	return ops, nil
}

// fieldRefFromLogRemove extracts a FieldRef from a proto LogRemove.
func fieldRefFromLogRemove(r *policyv1.LogRemove) (LogFieldRef, error) {
	switch f := r.GetField().(type) {
	case *policyv1.LogRemove_LogField:
		if f.LogField == policyv1.LogField_LOG_FIELD_UNSPECIFIED {
			return LogFieldRef{}, errUnspecifiedEnum
		}
		return LogFieldRef{Field: logFieldFromProto(f.LogField)}, nil
	case *policyv1.LogRemove_LogAttribute:
		if len(f.LogAttribute.GetPath()) == 0 {
			return LogFieldRef{}, errEmptyAttrPath
		}
		return LogFieldRef{AttrScope: AttrScopeRecord, AttrPath: f.LogAttribute.GetPath()}, nil
	case *policyv1.LogRemove_ResourceAttribute:
		if len(f.ResourceAttribute.GetPath()) == 0 {
			return LogFieldRef{}, errEmptyAttrPath
		}
		return LogFieldRef{AttrScope: AttrScopeResource, AttrPath: f.ResourceAttribute.GetPath()}, nil
	case *policyv1.LogRemove_ScopeAttribute:
		if len(f.ScopeAttribute.GetPath()) == 0 {
			return LogFieldRef{}, errEmptyAttrPath
		}
		return LogFieldRef{AttrScope: AttrScopeScope, AttrPath: f.ScopeAttribute.GetPath()}, nil
	default:
		return LogFieldRef{}, errNoFieldSet
	}
}

// fieldRefFromLogRedact extracts a FieldRef from a proto LogRedact.
func fieldRefFromLogRedact(r *policyv1.LogRedact) (LogFieldRef, error) {
	switch f := r.GetField().(type) {
	case *policyv1.LogRedact_LogField:
		if f.LogField == policyv1.LogField_LOG_FIELD_UNSPECIFIED {
			return LogFieldRef{}, errUnspecifiedEnum
		}
		return LogFieldRef{Field: logFieldFromProto(f.LogField)}, nil
	case *policyv1.LogRedact_LogAttribute:
		if len(f.LogAttribute.GetPath()) == 0 {
			return LogFieldRef{}, errEmptyAttrPath
		}
		return LogFieldRef{AttrScope: AttrScopeRecord, AttrPath: f.LogAttribute.GetPath()}, nil
	case *policyv1.LogRedact_ResourceAttribute:
		if len(f.ResourceAttribute.GetPath()) == 0 {
			return LogFieldRef{}, errEmptyAttrPath
		}
		return LogFieldRef{AttrScope: AttrScopeResource, AttrPath: f.ResourceAttribute.GetPath()}, nil
	case *policyv1.LogRedact_ScopeAttribute:
		if len(f.ScopeAttribute.GetPath()) == 0 {
			return LogFieldRef{}, errEmptyAttrPath
		}
		return LogFieldRef{AttrScope: AttrScopeScope, AttrPath: f.ScopeAttribute.GetPath()}, nil
	default:
		return LogFieldRef{}, errNoFieldSet
	}
}

// fieldRefFromLogRename extracts a FieldRef from a proto LogRename's "from" field.
func fieldRefFromLogRename(r *policyv1.LogRename) (LogFieldRef, error) {
	switch f := r.GetFrom().(type) {
	case *policyv1.LogRename_FromLogField:
		if f.FromLogField == policyv1.LogField_LOG_FIELD_UNSPECIFIED {
			return LogFieldRef{}, errUnspecifiedEnum
		}
		return LogFieldRef{Field: logFieldFromProto(f.FromLogField)}, nil
	case *policyv1.LogRename_FromLogAttribute:
		if len(f.FromLogAttribute.GetPath()) == 0 {
			return LogFieldRef{}, errEmptyAttrPath
		}
		return LogFieldRef{AttrScope: AttrScopeRecord, AttrPath: f.FromLogAttribute.GetPath()}, nil
	case *policyv1.LogRename_FromResourceAttribute:
		if len(f.FromResourceAttribute.GetPath()) == 0 {
			return LogFieldRef{}, errEmptyAttrPath
		}
		return LogFieldRef{AttrScope: AttrScopeResource, AttrPath: f.FromResourceAttribute.GetPath()}, nil
	case *policyv1.LogRename_FromScopeAttribute:
		if len(f.FromScopeAttribute.GetPath()) == 0 {
			return LogFieldRef{}, errEmptyAttrPath
		}
		return LogFieldRef{AttrScope: AttrScopeScope, AttrPath: f.FromScopeAttribute.GetPath()}, nil
	default:
		return LogFieldRef{}, errNoFieldSet
	}
}

// fieldRefFromLogAdd extracts a FieldRef from a proto LogAdd.
func fieldRefFromLogAdd(a *policyv1.LogAdd) (LogFieldRef, error) {
	switch f := a.GetField().(type) {
	case *policyv1.LogAdd_LogField:
		if f.LogField == policyv1.LogField_LOG_FIELD_UNSPECIFIED {
			return LogFieldRef{}, errUnspecifiedEnum
		}
		return LogFieldRef{Field: logFieldFromProto(f.LogField)}, nil
	case *policyv1.LogAdd_LogAttribute:
		if len(f.LogAttribute.GetPath()) == 0 {
			return LogFieldRef{}, errEmptyAttrPath
		}
		return LogFieldRef{AttrScope: AttrScopeRecord, AttrPath: f.LogAttribute.GetPath()}, nil
	case *policyv1.LogAdd_ResourceAttribute:
		if len(f.ResourceAttribute.GetPath()) == 0 {
			return LogFieldRef{}, errEmptyAttrPath
		}
		return LogFieldRef{AttrScope: AttrScopeResource, AttrPath: f.ResourceAttribute.GetPath()}, nil
	case *policyv1.LogAdd_ScopeAttribute:
		if len(f.ScopeAttribute.GetPath()) == 0 {
			return LogFieldRef{}, errEmptyAttrPath
		}
		return LogFieldRef{AttrScope: AttrScopeScope, AttrPath: f.ScopeAttribute.GetPath()}, nil
	default:
		return LogFieldRef{}, errNoFieldSet
	}
}
