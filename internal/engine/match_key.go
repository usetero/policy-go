// Package engine contains the policy evaluation engine implementation.
package engine

// MatchKey identifies a group of patterns that share the same field selector and negation.
// Patterns are grouped by MatchKey for efficient Hyperscan compilation.
type MatchKey struct {
	Selector FieldSelector
	Negated  bool
}
