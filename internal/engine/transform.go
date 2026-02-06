package engine

import (
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
	Ref    LogFieldRef // target field (remove/redact/add) or source field (rename)
	Value  string      // replacement string (redact) or value to set (add)
	To     string      // new field name (rename only)
	Upsert bool        // overwrite if target exists (rename/add)
}

// compileLogTransform converts a proto LogTransform into a flat slice of TransformOps.
// Operations are ordered: removes, redacts, renames, adds (matching proto field order).
func compileLogTransform(t *policyv1.LogTransform) []TransformOp {
	if t == nil {
		return nil
	}

	n := len(t.GetRemove()) + len(t.GetRedact()) + len(t.GetRename()) + len(t.GetAdd())
	if n == 0 {
		return nil
	}

	ops := make([]TransformOp, 0, n)

	for _, r := range t.GetRemove() {
		ops = append(ops, TransformOp{
			Kind: TransformRemove,
			Ref:  fieldRefFromLogRemove(r),
		})
	}

	for _, r := range t.GetRedact() {
		ops = append(ops, TransformOp{
			Kind:  TransformRedact,
			Ref:   fieldRefFromLogRedact(r),
			Value: r.GetReplacement(),
		})
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

	return ops
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
