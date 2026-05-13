package engine

import (
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
// Returns true if the operation was a hit (field present or write occurred), false for a miss.
func ApplyLogTransform[T any](rec T, op TransformOp, a *LogAccessor[T]) bool {
	switch op.Kind {
	case TransformRemove:
		if a.Delete == nil {
			panic("Delete accessor not configured")
		}
		return a.Delete(rec, op.Ref)

	case TransformRedact:
		if a.Value == nil {
			panic("Value accessor not configured")
		}
		if a.Set == nil {
			panic("Set accessor not configured")
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
		if a.Exists == nil {
			panic("Exists accessor not configured")
		}
		if !a.Exists(rec, op.Ref) {
			return false
		}
		a.Set(rec, op.Ref, op.Value)
		return true

	case TransformRename:
		if a.Exists == nil {
			panic("Exists accessor not configured")
		}
		if a.Move == nil {
			panic("Move accessor not configured")
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
		if a.Exists == nil {
			panic("Exists accessor not configured")
		}
		if a.Set == nil {
			panic("Set accessor not configured")
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
// Returns an error if any redact regex fails to compile.
func compileLogTransform(t *policyv1.LogTransform) ([]TransformOp, error) {
	if t == nil {
		return nil, nil
	}

	n := len(t.GetRemove()) + len(t.GetRedact()) + len(t.GetRename()) + len(t.GetAdd())
	if n == 0 {
		return nil, nil
	}

	ops := make([]TransformOp, 0, n)

	for _, r := range t.GetRemove() {
		ops = append(ops, TransformOp{
			Kind: TransformRemove,
			Ref:  fieldRefFromLogRemove(r),
		})
	}

	for i, r := range t.GetRedact() {
		op := TransformOp{
			Kind:  TransformRedact,
			Ref:   fieldRefFromLogRedact(r),
			Value: r.GetReplacement(),
		}
		if r.Regex != nil {
			re, err := regexp.Compile(r.GetRegex())
			if err != nil {
				return nil, fmt.Errorf("redact[%d]: invalid regex %q: %w", i, r.GetRegex(), err)
			}
			op.Regex = re
		}
		ops = append(ops, op)
	}

	for _, r := range t.GetRename() {
		ops = append(ops, TransformOp{
			Kind:   TransformRename,
			Ref:    fieldRefFromLogRename(r),
			To:     r.GetTo(),
			Upsert: r.GetUpsert(),
		})
	}

	for _, a := range t.GetAdd() {
		ops = append(ops, TransformOp{
			Kind:   TransformAdd,
			Ref:    fieldRefFromLogAdd(a),
			Value:  a.GetValue(),
			Upsert: a.GetUpsert(),
		})
	}

	return ops, nil
}

// fieldRefFromLogRemove extracts a FieldRef from a proto LogRemove.
func fieldRefFromLogRemove(r *policyv1.LogRemove) LogFieldRef {
	switch f := r.GetField().(type) {
	case *policyv1.LogRemove_LogField:
		return LogFieldRef{Field: logFieldFromProto(f.LogField)}
	case *policyv1.LogRemove_LogAttribute:
		return LogFieldRef{AttrScope: AttrScopeRecord, AttrPath: f.LogAttribute.GetPath()}
	case *policyv1.LogRemove_ResourceAttribute:
		return LogFieldRef{AttrScope: AttrScopeResource, AttrPath: f.ResourceAttribute.GetPath()}
	case *policyv1.LogRemove_ScopeAttribute:
		return LogFieldRef{AttrScope: AttrScopeScope, AttrPath: f.ScopeAttribute.GetPath()}
	default:
		return LogFieldRef{}
	}
}

// fieldRefFromLogRedact extracts a FieldRef from a proto LogRedact.
func fieldRefFromLogRedact(r *policyv1.LogRedact) LogFieldRef {
	switch f := r.GetField().(type) {
	case *policyv1.LogRedact_LogField:
		return LogFieldRef{Field: logFieldFromProto(f.LogField)}
	case *policyv1.LogRedact_LogAttribute:
		return LogFieldRef{AttrScope: AttrScopeRecord, AttrPath: f.LogAttribute.GetPath()}
	case *policyv1.LogRedact_ResourceAttribute:
		return LogFieldRef{AttrScope: AttrScopeResource, AttrPath: f.ResourceAttribute.GetPath()}
	case *policyv1.LogRedact_ScopeAttribute:
		return LogFieldRef{AttrScope: AttrScopeScope, AttrPath: f.ScopeAttribute.GetPath()}
	default:
		return LogFieldRef{}
	}
}

// fieldRefFromLogRename extracts a FieldRef from a proto LogRename's "from" field.
func fieldRefFromLogRename(r *policyv1.LogRename) LogFieldRef {
	switch f := r.GetFrom().(type) {
	case *policyv1.LogRename_FromLogField:
		return LogFieldRef{Field: logFieldFromProto(f.FromLogField)}
	case *policyv1.LogRename_FromLogAttribute:
		return LogFieldRef{AttrScope: AttrScopeRecord, AttrPath: f.FromLogAttribute.GetPath()}
	case *policyv1.LogRename_FromResourceAttribute:
		return LogFieldRef{AttrScope: AttrScopeResource, AttrPath: f.FromResourceAttribute.GetPath()}
	case *policyv1.LogRename_FromScopeAttribute:
		return LogFieldRef{AttrScope: AttrScopeScope, AttrPath: f.FromScopeAttribute.GetPath()}
	default:
		return LogFieldRef{}
	}
}

// fieldRefFromLogAdd extracts a FieldRef from a proto LogAdd.
func fieldRefFromLogAdd(a *policyv1.LogAdd) LogFieldRef {
	switch f := a.GetField().(type) {
	case *policyv1.LogAdd_LogField:
		return LogFieldRef{Field: logFieldFromProto(f.LogField)}
	case *policyv1.LogAdd_LogAttribute:
		return LogFieldRef{AttrScope: AttrScopeRecord, AttrPath: f.LogAttribute.GetPath()}
	case *policyv1.LogAdd_ResourceAttribute:
		return LogFieldRef{AttrScope: AttrScopeResource, AttrPath: f.ResourceAttribute.GetPath()}
	case *policyv1.LogAdd_ScopeAttribute:
		return LogFieldRef{AttrScope: AttrScopeScope, AttrPath: f.ScopeAttribute.GetPath()}
	default:
		return LogFieldRef{}
	}
}
