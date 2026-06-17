package engine

import (
	"regexp"

	"github.com/usetero/policy-go/policy/regexbackend"
)

// The core module ships no backend implementation, so its tests supply a local
// stdlib-regexp fake. init wires it as the default for this package's test binary
// so existing NewCompiler() call sites need no backend argument.
func init() { defaultBackend = fakeBackend{} }

type fakeBackend struct{}

func (fakeBackend) Compile(patterns []string, caseInsensitive bool) (regexbackend.Matcher, error) {
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

func (m *fakeMatcher) Scan(data []byte, matched []bool) error {
	for i, re := range m.res {
		if re.Match(data) {
			matched[i] = true
		}
	}
	return nil
}

func (m *fakeMatcher) ScanHits(data []byte, hits []int) ([]int, error) {
	for i, re := range m.res {
		if re.Match(data) {
			hits = append(hits, i)
		}
	}
	return hits, nil
}

func (m *fakeMatcher) Close() error { return nil }
