// Package engine contains the policy evaluation engine implementation.
package engine

import policyv1 "github.com/usetero/policy-go/internal/proto/tero/policy/v1"

// LogFieldSelector represents the field to match against in a log record.
// This is a normalized representation of the proto's oneof field.
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

// MatchKey identifies a group of patterns that share the same field selector and negation.
// Patterns are grouped by MatchKey for efficient Hyperscan compilation.
type MatchKey struct {
	Selector LogFieldSelector
	Negated  bool
}
