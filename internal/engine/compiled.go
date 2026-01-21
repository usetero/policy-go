package engine

import (
	"fmt"
	"regexp"
	"sync"

	"github.com/flier/gohs/hyperscan"
)

// PatternRef links a compiled pattern back to its source policy and matcher.
type PatternRef struct {
	PolicyID     string
	PolicyIndex  int // Dense index for array-based tracking
	MatcherIndex int
}

// CompiledDatabase holds a Hyperscan database and scratch space for a group of patterns.
type CompiledDatabase struct {
	db           hyperscan.BlockDatabase
	scratch      *hyperscan.Scratch
	scratchPool  sync.Pool
	matchedPool  sync.Pool    // Pool for []bool match results
	patternIndex []PatternRef // maps pattern ID → policy
}

// Close releases resources associated with the compiled database.
func (c *CompiledDatabase) Close() error {
	if c.scratch != nil {
		if err := c.scratch.Free(); err != nil {
			return err
		}
	}
	if c.db != nil {
		return c.db.Close()
	}
	return nil
}

// PatternIndex returns the pattern index mapping pattern IDs to policies.
func (c *CompiledDatabase) PatternIndex() []PatternRef {
	return c.patternIndex
}

// Scan scans the input data against the compiled database and returns which patterns matched.
// The caller must call ReleaseMatched when done with the result to return it to the pool.
func (c *CompiledDatabase) Scan(data []byte) ([]bool, error) {
	// Get or create a scratch from the pool
	var scratch *hyperscan.Scratch
	if pooled := c.scratchPool.Get(); pooled != nil {
		scratch = pooled.(*hyperscan.Scratch)
	} else {
		var err error
		scratch, err = c.scratch.Clone()
		if err != nil {
			return nil, err
		}
	}

	// Get or create matched slice from pool
	var matched []bool
	if pooled := c.matchedPool.Get(); pooled != nil {
		matched = pooled.([]bool)
		// Clear the slice
		for i := range matched {
			matched[i] = false
		}
	} else {
		matched = make([]bool, len(c.patternIndex))
	}

	err := c.db.Scan(data, scratch, func(id uint, from, to uint64, flags uint, context any) error {
		matched[id] = true
		return nil
	}, nil)

	// Return scratch to pool
	c.scratchPool.Put(scratch)

	if err != nil {
		c.matchedPool.Put(matched)
		return nil, err
	}

	return matched, nil
}

// ReleaseMatched returns a matched slice to the pool.
func (c *CompiledDatabase) ReleaseMatched(matched []bool) {
	if matched != nil {
		c.matchedPool.Put(matched)
	}
}

// ExistenceCheck represents a field existence check that can't be compiled to Hyperscan.
type ExistenceCheck struct {
	Selector    FieldSelector
	MustExist   bool
	PolicyID    string
	PolicyIndex int // Dense index for array-based tracking
	MatchIndex  int
}

// CompiledPolicy holds the compiled representation of a policy for evaluation.
type CompiledPolicy struct {
	ID           string
	Index        int // Dense index for array-based tracking (0 to N-1)
	Keep         Keep
	MatcherCount int
	Stats        *PolicyStats
}

// CompiledMatchers holds all compiled pattern databases for policy evaluation.
type CompiledMatchers struct {
	databases       map[MatchKey]*CompiledDatabase
	existenceChecks []ExistenceCheck
	policies        map[string]*CompiledPolicy
	policyList      []*CompiledPolicy // Index-ordered list for fast lookup
}

// NewCompiledMatchers creates a new empty CompiledMatchers.
func NewCompiledMatchers() *CompiledMatchers {
	return &CompiledMatchers{
		databases:       make(map[MatchKey]*CompiledDatabase),
		existenceChecks: make([]ExistenceCheck, 0),
		policies:        make(map[string]*CompiledPolicy),
	}
}

// Close releases all resources.
func (c *CompiledMatchers) Close() error {
	for _, db := range c.databases {
		if err := db.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Databases returns the compiled databases.
func (c *CompiledMatchers) Databases() map[MatchKey]*CompiledDatabase {
	return c.databases
}

// ExistenceChecks returns the existence checks.
func (c *CompiledMatchers) ExistenceChecks() []ExistenceCheck {
	return c.existenceChecks
}

// Policies returns the compiled policies.
func (c *CompiledMatchers) Policies() map[string]*CompiledPolicy {
	return c.policies
}

// GetPolicy returns a compiled policy by ID.
func (c *CompiledMatchers) GetPolicy(id string) (*CompiledPolicy, bool) {
	p, ok := c.policies[id]
	return p, ok
}

// PolicyCount returns the number of compiled policies.
func (c *CompiledMatchers) PolicyCount() int {
	return len(c.policyList)
}

// PolicyByIndex returns a compiled policy by its dense index.
func (c *CompiledMatchers) PolicyByIndex(index int) *CompiledPolicy {
	return c.policyList[index]
}

// Compiler compiles policies into Hyperscan databases.
type Compiler struct{}

// NewCompiler creates a new Compiler.
func NewCompiler() *Compiler {
	return &Compiler{}
}

// Compile compiles a set of policies into CompiledMatchers.
func (c *Compiler) Compile(policies []*Policy, stats map[string]*PolicyStats) (*CompiledMatchers, error) {
	result := NewCompiledMatchers()

	// Group patterns by MatchKey
	groups := make(map[MatchKey][]patternEntry)

	// First pass: assign dense indices to policies
	policyIndex := make(map[string]int)
	for _, p := range policies {
		if !p.IsLogPolicy() {
			continue
		}
		policyIndex[p.ID] = len(result.policyList)
		result.policyList = append(result.policyList, nil) // placeholder
	}

	for _, p := range policies {
		if !p.IsLogPolicy() {
			continue
		}

		log := p.Log
		idx := policyIndex[p.ID]

		// Create compiled policy
		compiled := &CompiledPolicy{
			ID:           p.ID,
			Index:        idx,
			Keep:         log.Keep,
			MatcherCount: len(log.Matchers),
			Stats:        stats[p.ID],
		}
		result.policies[p.ID] = compiled
		result.policyList[idx] = compiled

		// Process matchers
		for i, m := range log.Matchers {
			if m.Exists != nil {
				// Existence check - can't use Hyperscan
				result.existenceChecks = append(result.existenceChecks, ExistenceCheck{
					Selector:    m.Field,
					MustExist:   *m.Exists,
					PolicyID:    p.ID,
					PolicyIndex: idx,
					MatchIndex:  i,
				})
				continue
			}

			key := MatchKey{
				Selector: m.Field,
				Negated:  m.Negated,
			}

			groups[key] = append(groups[key], patternEntry{
				pattern:      m.Pattern,
				policyID:     p.ID,
				policyIndex:  idx,
				matcherIndex: i,
			})
		}
	}

	// Compile each group
	for key, entries := range groups {
		db, err := c.compileGroup(entries)
		if err != nil {
			return nil, fmt.Errorf("failed to compile patterns for %v: %w", key, err)
		}
		result.databases[key] = db
	}

	return result, nil
}

type patternEntry struct {
	pattern      string
	policyID     string
	policyIndex  int
	matcherIndex int
}

func (c *Compiler) compileGroup(entries []patternEntry) (*CompiledDatabase, error) {
	patterns := make([]*hyperscan.Pattern, len(entries))
	patternIndex := make([]PatternRef, len(entries))

	for i, e := range entries {
		// Validate the pattern is valid regex
		if _, err := regexp.Compile(e.pattern); err != nil {
			return nil, fmt.Errorf("invalid regex %q: %w", e.pattern, err)
		}

		patterns[i] = hyperscan.NewPattern(e.pattern, hyperscan.SomLeftMost)
		patterns[i].Id = i

		patternIndex[i] = PatternRef{
			PolicyID:     e.policyID,
			PolicyIndex:  e.policyIndex,
			MatcherIndex: e.matcherIndex,
		}
	}

	db, err := hyperscan.NewBlockDatabase(patterns...)
	if err != nil {
		return nil, fmt.Errorf("failed to compile hyperscan database: %w", err)
	}

	scratch, err := hyperscan.NewScratch(db)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to allocate scratch: %w", err)
	}

	return &CompiledDatabase{
		db:           db,
		scratch:      scratch,
		patternIndex: patternIndex,
	}, nil
}
