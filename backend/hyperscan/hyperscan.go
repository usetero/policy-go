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

	scratch, err := hyperscan.NewScratch(db)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to allocate scratch: %w", err)
	}

	return &matcher{db: db, scratch: scratch}, nil
}

// matcher holds a Hyperscan block database plus a pool of scratch spaces. gohs
// scratch is not safe for concurrent scans, so each scan borrows one from the
// pool (cloning the base scratch when the pool is empty).
type matcher struct {
	db          hyperscan.BlockDatabase
	scratch     *hyperscan.Scratch
	scratchPool sync.Pool
}

var _ regexbackend.Matcher = (*matcher)(nil)

func (m *matcher) Scan(data []byte, matched []bool) error {
	var scratch *hyperscan.Scratch
	if pooled := m.scratchPool.Get(); pooled != nil {
		scratch = pooled.(*hyperscan.Scratch)
	} else {
		var err error
		scratch, err = m.scratch.Clone()
		if err != nil {
			return err
		}
	}

	err := m.db.Scan(data, scratch, func(id uint, from, to uint64, flags uint, context any) error {
		matched[id] = true
		return nil
	}, nil)

	m.scratchPool.Put(scratch)
	return err
}

func (m *matcher) Close() error {
	if m.scratch != nil {
		if err := m.scratch.Free(); err != nil {
			return err
		}
	}
	if m.db != nil {
		return m.db.Close()
	}
	return nil
}
