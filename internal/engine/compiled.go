package engine

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/flier/gohs/hyperscan"
	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
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
	databases       []DatabaseEntry
	existenceChecks []ExistenceCheck
	policies        map[string]*CompiledPolicy
	policyList      []*CompiledPolicy // Index-ordered list for fast lookup
}

// NewCompiledMatchers creates a new empty CompiledMatchers.
func NewCompiledMatchers() *CompiledMatchers {
	return &CompiledMatchers{
		databases:       make([]DatabaseEntry, 0),
		existenceChecks: make([]ExistenceCheck, 0),
		policies:        make(map[string]*CompiledPolicy),
	}
}

// Close releases all resources.
func (c *CompiledMatchers) Close() error {
	for _, entry := range c.databases {
		if err := entry.Database.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Databases returns the compiled databases.
func (c *CompiledMatchers) Databases() []DatabaseEntry {
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

// Compile compiles a set of proto policies into CompiledMatchers.
func (c *Compiler) Compile(policies []*policyv1.Policy, stats map[string]*PolicyStats) (*CompiledMatchers, error) {
	result := NewCompiledMatchers()

	// Group patterns by MatchKey (using string key for map)
	groups := make(map[matchKeyString][]patternEntry)
	groupKeys := make(map[matchKeyString]MatchKey)

	// First pass: assign dense indices to log policies
	policyIndex := make(map[string]int)
	for _, p := range policies {
		if p.GetLog() == nil {
			continue
		}
		policyIndex[p.GetId()] = len(result.policyList)
		result.policyList = append(result.policyList, nil) // placeholder
	}

	for _, p := range policies {
		log := p.GetLog()
		if log == nil {
			continue
		}

		id := p.GetId()
		idx := policyIndex[id]

		// Parse keep string
		keep, err := ParseKeep(log.GetKeep())
		if err != nil {
			return nil, fmt.Errorf("policy %s: %w", id, err)
		}

		// Create compiled policy
		compiled := &CompiledPolicy{
			ID:           id,
			Index:        idx,
			Keep:         keep,
			MatcherCount: len(log.GetMatch()),
			Stats:        stats[id],
		}
		result.policies[id] = compiled
		result.policyList[idx] = compiled

		// Process matchers
		for i, m := range log.GetMatch() {
			selector := FieldSelectorFromLogMatcher(m)

			// Check if this is an existence check
			if _, ok := m.GetMatch().(*policyv1.LogMatcher_Exists); ok {
				result.existenceChecks = append(result.existenceChecks, ExistenceCheck{
					Selector:    selector,
					MustExist:   m.GetExists(),
					PolicyID:    id,
					PolicyIndex: idx,
					MatchIndex:  i,
				})
				continue
			}

			// Get the pattern (regex or exact)
			var pattern string
			switch match := m.GetMatch().(type) {
			case *policyv1.LogMatcher_Regex:
				pattern = match.Regex
			case *policyv1.LogMatcher_Exact:
				// Escape for literal match
				pattern = regexp.QuoteMeta(match.Exact)
			default:
				continue
			}

			key := MatchKey{
				Selector: selector,
				Negated:  m.GetNegate(),
			}
			keyStr := makeMatchKeyString(key)

			groups[keyStr] = append(groups[keyStr], patternEntry{
				pattern:      pattern,
				policyID:     id,
				policyIndex:  idx,
				matcherIndex: i,
			})
			groupKeys[keyStr] = key
		}
	}

	// Compile each group
	for keyStr, entries := range groups {
		db, err := c.compileGroup(entries)
		if err != nil {
			return nil, fmt.Errorf("failed to compile patterns for %v: %w", keyStr, err)
		}
		result.databases = append(result.databases, DatabaseEntry{
			Key:      groupKeys[keyStr],
			Database: db,
		})
	}

	return result, nil
}

type patternEntry struct {
	pattern      string
	policyID     string
	policyIndex  int
	matcherIndex int
}

// matchKeyString is used only during compilation for grouping patterns.
// It creates a hashable string from a MatchKey for use as map keys.
type matchKeyString string

func makeMatchKeyString(k MatchKey) matchKeyString {
	// Format: "field|scope|path[0].path[1]...|negated"
	var s strings.Builder
	fmt.Fprintf(&s, "%d|%d|", k.Selector.Field, k.Selector.AttrScope)
	for i, p := range k.Selector.AttrPath {
		if i > 0 {
			s.WriteString(".")
		}
		s.WriteString(p)
	}
	fmt.Fprintf(&s, "|%t", k.Negated)
	return matchKeyString(s.String())
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
