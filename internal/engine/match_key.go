// Package engine contains the policy evaluation engine implementation.
package engine

import policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"

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
	// AttrName is the attribute name for attribute lookups.
	AttrName string
}

// IsAttribute returns true if this selector is for an attribute lookup.
func (s FieldSelector) IsAttribute() bool {
	return s.AttrName != ""
}

// LogFieldSelector represents the field to match against in a log record.
// This is a normalized representation of the proto's oneof field.
// Deprecated: Use FieldSelector instead.
type LogFieldSelector struct {
	// For simple log fields (body, severity_text, etc.)
	LogField policyv1.LogField
	// For log record attributes
	LogAttribute string
	// For resource attributes
	ResourceAttribute string
	// For scope attributes
	ScopeAttribute string
}

// ToFieldSelector converts a LogFieldSelector to the generic FieldSelector.
func (s LogFieldSelector) ToFieldSelector() FieldSelector {
	if s.LogAttribute != "" {
		return FieldSelector{AttrScope: AttrScopeRecord, AttrName: s.LogAttribute}
	}
	if s.ResourceAttribute != "" {
		return FieldSelector{AttrScope: AttrScopeResource, AttrName: s.ResourceAttribute}
	}
	if s.ScopeAttribute != "" {
		return FieldSelector{AttrScope: AttrScopeScope, AttrName: s.ScopeAttribute}
	}
	return FieldSelector{Field: int32(s.LogField)}
}

// LogFieldSelectorFromMatcher extracts a LogFieldSelector from a proto LogMatcher.
func LogFieldSelectorFromMatcher(m *policyv1.LogMatcher) LogFieldSelector {
	switch f := m.GetField().(type) {
	case *policyv1.LogMatcher_LogField:
		return LogFieldSelector{LogField: f.LogField}
	case *policyv1.LogMatcher_LogAttribute:
		return LogFieldSelector{LogAttribute: f.LogAttribute}
	case *policyv1.LogMatcher_ResourceAttribute:
		return LogFieldSelector{ResourceAttribute: f.ResourceAttribute}
	case *policyv1.LogMatcher_ScopeAttribute:
		return LogFieldSelector{ScopeAttribute: f.ScopeAttribute}
	default:
		return LogFieldSelector{}
	}
}

// FieldSelectorFromLogMatcher extracts a FieldSelector from a proto LogMatcher.
func FieldSelectorFromLogMatcher(m *policyv1.LogMatcher) FieldSelector {
	switch f := m.GetField().(type) {
	case *policyv1.LogMatcher_LogField:
		return FieldSelector{Field: int32(f.LogField)}
	case *policyv1.LogMatcher_LogAttribute:
		return FieldSelector{AttrScope: AttrScopeRecord, AttrName: f.LogAttribute}
	case *policyv1.LogMatcher_ResourceAttribute:
		return FieldSelector{AttrScope: AttrScopeResource, AttrName: f.ResourceAttribute}
	case *policyv1.LogMatcher_ScopeAttribute:
		return FieldSelector{AttrScope: AttrScopeScope, AttrName: f.ScopeAttribute}
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
