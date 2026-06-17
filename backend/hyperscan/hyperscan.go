// Package hyperscan implements regexbackend.Backend using Intel Hyperscan /
// Vectorscan via github.com/flier/gohs. It requires cgo.
//
// It is a separate Go module from the policy-go core so that depending on the
// core never pulls in cgo/gohs. Opt in by importing this module and wiring it:
//
//	registry := policy.NewPolicyRegistry(policy.WithRegexBackend(hyperscan.New()))
package hyperscan

import (
	"fmt"
	"sync"

	"github.com/flier/gohs/hyperscan"
	"github.com/usetero/policy-go/policy/regexbackend"
)

// New returns a Hyperscan-backed regexbackend.Backend.
func New() regexbackend.Backend {
	return backend{}
}

type backend struct{}

var _ regexbackend.Backend = backend{}

func (backend) Compile(patterns []string, caseInsensitive bool) (regexbackend.Matcher, error) {
	flags := hyperscan.SingleMatch
	if caseInsensitive {
		flags |= hyperscan.Caseless
	}

	pats := make([]*hyperscan.Pattern, len(patterns))
	for i, p := range patterns {
		pats[i] = hyperscan.NewPattern(p, flags)
		pats[i].Id = i
	}

	db, err := hyperscan.NewBlockDatabase(pats...)
	if err != nil {
		return nil, fmt.Errorf("failed to compile hyperscan database: %w", err)
	}

	base, err := hyperscan.NewScratch(db)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to allocate scratch: %w", err)
	}

	return &matcher{db: db, base: base}, nil
}

// matcher holds a Hyperscan block database plus a pool of scratch spaces. gohs
// scratch is not safe for concurrent scans, so each scan borrows one from the
// pool (cloning the base scratch when the pool is empty).
type matcher struct {
	db          hyperscan.BlockDatabase
	base        *hyperscan.Scratch
	scratchPool sync.Pool
}

var _ regexbackend.Matcher = (*matcher)(nil)

func (m *matcher) getScratch() (*hyperscan.Scratch, error) {
	if pooled := m.scratchPool.Get(); pooled != nil {
		return pooled.(*hyperscan.Scratch), nil
	}
	return m.base.Clone()
}

func (m *matcher) Scan(data []byte, matched []bool) error {
	s, err := m.getScratch()
	if err != nil {
		return err
	}
	err = m.db.Scan(data, s, func(id uint, from, to uint64, flags uint, context any) error {
		matched[id] = true
		return nil
	}, nil)
	m.scratchPool.Put(s)
	return err
}

func (m *matcher) ScanHits(data []byte, hits []int) ([]int, error) {
	s, err := m.getScratch()
	if err != nil {
		return hits, err
	}
	err = m.db.Scan(data, s, func(id uint, from, to uint64, flags uint, context any) error {
		hits = append(hits, int(id))
		return nil
	}, nil)
	m.scratchPool.Put(s)
	return hits, err
}

func (m *matcher) Close() error {
	if m.base != nil {
		if err := m.base.Free(); err != nil {
			return err
		}
	}
	if m.db != nil {
		return m.db.Close()
	}
	return nil
}
