// Package engine contains the policy evaluation engine implementation.
package engine

import (
	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
)

// AttrScope identifies the scope for attribute lookups.
type AttrScope int

const (
	// AttrScopeResource is for resource-level attributes.
	AttrScopeResource AttrScope = iota
	// AttrScopeScope is for instrumentation scope attributes.
	AttrScopeScope
	// AttrScopeRecord is for record-level attributes (log attributes, span attributes, datapoint attributes).
	AttrScopeRecord
	// AttrScopeEvent is for span event attributes (traces only).
	AttrScopeEvent
	// AttrScopeLink is for span link attributes (traces only).
	AttrScopeLink
)

// FieldSelector represents a generic field selector for any telemetry type.
// It can represent either a specific field (by enum value) or an attribute lookup.
type FieldSelector struct {
	// Field is the proto enum value for the field (LogField, MetricField, or TraceField).
	// Zero value means this is an attribute lookup.
	Field int32
	// AttrScope specifies where to look for the attribute.
	AttrScope AttrScope
	// AttrPath is the attribute path for attribute lookups.
	// Supports nested access (e.g., ["http", "request", "method"]).
	AttrPath []string
}

// IsAttribute returns true if this selector is for an attribute lookup.
func (s FieldSelector) IsAttribute() bool {
	return len(s.AttrPath) > 0
}

// FieldSelectorFromLogMatcher extracts a FieldSelector from a proto LogMatcher.
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

// FieldSelectorFromLogSampleKey extracts a FieldSelector from a proto LogSampleKey.
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

// MatchKey identifies a group of patterns that share the same field selector and negation.
// Patterns are grouped by MatchKey for efficient Hyperscan compilation.
type MatchKey struct {
	Selector FieldSelector
	Negated  bool
}

// DatabaseEntry pairs a MatchKey with its compiled database.
type DatabaseEntry struct {
	Key      MatchKey
	Database *CompiledDatabase
}
