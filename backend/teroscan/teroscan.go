// Package teroscan implements regexbackend.Backend using only the Go standard
// library (no cgo). It is policy-go's default backend, so policies compile and
// match out of the box without Hyperscan.
//
// This is a skeleton baseline: correct but naive. It runs one stdlib regexp per
// pattern, which is fine for small policy sets but does not match Hyperscan's
// single-pass throughput on large pattern groups. Replace the Matcher internals
// with a real multi-pattern engine (e.g. an Aho-Corasick literal prefilter in
// front of the regexps, or a unioned RE2/DFA) when scan throughput matters; the
// regexbackend contract does not change.
package teroscan

import (
	"fmt"
	"regexp"

	"github.com/usetero/policy-go/policy/regexbackend"
)

// New returns a pure-Go regexbackend.Backend.
func New() regexbackend.Backend {
	return backend{}
}

type backend struct{}

var _ regexbackend.Backend = backend{}

func (backend) Compile(patterns []string, caseInsensitive bool) (regexbackend.Matcher, error) {
	res := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		expr := p
		if caseInsensitive {
			expr = "(?i)" + expr
		}
		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, fmt.Errorf("teroscan: compile pattern %q: %w", p, err)
		}
		res[i] = re
	}
	return &matcher{res: res}, nil
}

type matcher struct {
	res []*regexp.Regexp
}

var _ regexbackend.Matcher = (*matcher)(nil)

// Scan reports which patterns occur in data.
//
// ponytail: naive O(patterns) scan — one unanchored regexp search per pattern.
// Correct (matches Hyperscan SingleMatch "occurs anywhere" semantics) but not
// single-pass. Swap a real multi-pattern engine in here if it shows up in profiles.
func (m *matcher) Scan(data []byte, matched []bool) error {
	for i, re := range m.res {
		if re.Match(data) {
			matched[i] = true
		}
	}
	return nil
}

func (m *matcher) Close() error { return nil }
