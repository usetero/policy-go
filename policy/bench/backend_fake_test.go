package bench

import (
	"regexp"

	"github.com/usetero/policy-go/policy"
)

// benchBackend is a stdlib-regexp backend for the benchmarks. The core module
// ships no backend, and bench can't import teroscan (that module depends on core,
// which would be a cycle), so it defines its own. It measures the policy engine,
// not Hyperscan throughput; benchmark a real backend from its own module.
type benchBackend struct{}

func (benchBackend) Compile(patterns []string, caseInsensitive bool) (policy.RegexMatcher, error) {
	res := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		expr := p
		if caseInsensitive {
			expr = "(?i)" + expr
		}
		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, err
		}
		res[i] = re
	}
	return &benchMatcher{res: res}, nil
}

type benchMatcher struct{ res []*regexp.Regexp }

func (m *benchMatcher) Scan(data []byte, matched []bool) error {
	for i, re := range m.res {
		if re.Match(data) {
			matched[i] = true
		}
	}
	return nil
}

func (m *benchMatcher) Close() error { return nil }
