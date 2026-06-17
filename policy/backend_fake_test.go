package policy

import "regexp"

// The core module ships no backend, so its tests supply a local stdlib-regexp
// fake. init wires it as testBackend so existing NewPolicyRegistry() call sites
// need no backend argument.
func init() { testBackend = fakeBackend{} }

type fakeBackend struct{}

func (fakeBackend) Compile(patterns []string, caseInsensitive bool) (RegexMatcher, error) {
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
	return &fakeMatcher{res: res}, nil
}

type fakeMatcher struct{ res []*regexp.Regexp }

func (m *fakeMatcher) Scan(data []byte, hits []int) ([]int, error) {
	for i, re := range m.res {
		if re.Match(data) {
			hits = append(hits, i)
		}
	}
	return hits, nil
}

func (m *fakeMatcher) Close() error { return nil }
