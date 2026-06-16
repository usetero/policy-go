// Package regexbackend defines the pluggable regex engine contract used by the
// policy compiler. The core module defaults to the pure-Go teroscan backend
// (github.com/usetero/policy-go/policy/backend/teroscan) and never requires cgo. The
// Hyperscan backend lives in its own module
// (github.com/usetero/policy-go/policy/backend/hyperscan) so that pulling in the core
// module never drags in cgo/gohs; opt into it via policy.WithRegexBackend.
//
// This package is a dependency-free leaf so that bindings and the core engine can
// both reference the contract without import cycles, and so implementing it pulls
// in nothing.
package regexbackend

// Backend compiles groups of regex patterns into Matchers. Each call to Compile
// receives one group of patterns that share matching semantics; the returned
// Matcher reports, per scan, which of those patterns occur in the input.
type Backend interface {
	// Compile builds a Matcher for the given patterns. caseInsensitive applies to
	// all patterns in the group. Patterns are leftmost-substring (unanchored)
	// matches; a pattern is reported at most once per scan regardless of how many
	// times it occurs.
	Compile(patterns []string, caseInsensitive bool) (Matcher, error)
}

// Matcher scans input bytes against a compiled group of patterns. Matchers must
// be safe for concurrent use by multiple goroutines.
type Matcher interface {
	// Scan sets matched[i] = true for each pattern index i that occurs in data.
	// matched is sized to the number of patterns and pre-zeroed by the caller;
	// implementations only set true and must not clear or grow it.
	Scan(data []byte, matched []bool) error
	// Close releases resources held by the matcher.
	Close() error
}
