package engine

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/flier/gohs/hyperscan"
)

// matchersBuilder accumulates matchers and builds a CompiledMatchers.
type matchersBuilder[T FieldType] struct {
	groups          map[matchKeyString][]patternEntry
	groupKeys       map[matchKeyString]MatchKey[T]
	existenceChecks []ExistenceCheck[T]
	policies        map[string]*CompiledPolicy[T]
	policyList      []*CompiledPolicy[T]
	policyIndices   map[string]int
}

// newMatchersBuilder creates a new builder.
func newMatchersBuilder[T FieldType]() *matchersBuilder[T] {
	return &matchersBuilder[T]{
		groups:        make(map[matchKeyString][]patternEntry),
		groupKeys:     make(map[matchKeyString]MatchKey[T]),
		policies:      make(map[string]*CompiledPolicy[T]),
		policyIndices: make(map[string]int),
	}
}

// reservePolicy reserves a slot for a policy and returns its index.
// This must be called before adding matchers for the policy.
func (b *matchersBuilder[T]) reservePolicy(policyID string) int {
	if idx, ok := b.policyIndices[policyID]; ok {
		return idx
	}
	idx := len(b.policyList)
	b.policyIndices[policyID] = idx
	b.policyList = append(b.policyList, nil) // placeholder
	return idx
}

// addMatcher adds a matcher to the builder.
func (b *matchersBuilder[T]) addMatcher(ref FieldRef[T], pattern string, isExistence bool, mustExist bool, negated bool, caseInsensitive bool, policyID string, policyIndex int, matcherIndex int) {
	if isExistence {
		b.existenceChecks = append(b.existenceChecks, ExistenceCheck[T]{
			Ref:         ref,
			MustExist:   mustExist,
			PolicyID:    policyID,
			PolicyIndex: policyIndex,
			MatchIndex:  matcherIndex,
		})
		return
	}

	if pattern == "" {
		return
	}

	key := MatchKey[T]{
		Ref:             ref,
		Negated:         negated,
		CaseInsensitive: caseInsensitive,
	}
	keyStr := makeMatchKeyString(key)

	b.groups[keyStr] = append(b.groups[keyStr], patternEntry{
		pattern:      pattern,
		policyID:     policyID,
		policyIndex:  policyIndex,
		matcherIndex: matcherIndex,
	})
	b.groupKeys[keyStr] = key
}

// finalizePolicy completes the policy with its keep action and other metadata.
func (b *matchersBuilder[T]) finalizePolicy(policyID string, policyIndex int, keep Keep, matcherCount int, sampleKey *FieldRef[T], stats *PolicyStats, transforms []TransformOp) {
	// Create rate limiter if needed
	var rateLimiter *RateLimiter
	switch keep.Action {
	case KeepRatePerSecond:
		rateLimiter = NewRateLimiterPerSecond(uint32(keep.Value))
	case KeepRatePerMinute:
		rateLimiter = NewRateLimiterPerMinute(uint32(keep.Value))
	}

	compiled := &CompiledPolicy[T]{
		ID:           policyID,
		Index:        policyIndex,
		Keep:         keep,
		MatcherCount: matcherCount,
		SampleKey:    sampleKey,
		RateLimiter:  rateLimiter,
		Stats:        stats,
		Transforms:   transforms,
	}
	b.policies[policyID] = compiled
	b.policyList[policyIndex] = compiled
}

// build compiles all the patterns and returns the CompiledMatchers.
func (b *matchersBuilder[T]) build() (*CompiledMatchers[T], error) {
	result := &CompiledMatchers[T]{
		databases:       make([]DatabaseEntry[T], 0, len(b.groups)),
		existenceChecks: b.existenceChecks,
		policies:        b.policies,
		policyList:      b.policyList,
	}

	// Compile each group
	for keyStr, entries := range b.groups {
		key := b.groupKeys[keyStr]
		db, err := compileGroup(entries, key.CaseInsensitive)
		if err != nil {
			return nil, fmt.Errorf("failed to compile patterns for %v: %w", keyStr, err)
		}
		result.databases = append(result.databases, DatabaseEntry[T]{
			Key:      key,
			Database: db,
		})
	}

	return result, nil
}

// patternEntry holds a pattern and its source information.
type patternEntry struct {
	pattern      string
	policyID     string
	policyIndex  int
	matcherIndex int
}

// matchKeyString is used only during compilation for grouping patterns.
type matchKeyString string

func makeMatchKeyString[T FieldType](k MatchKey[T]) matchKeyString {
	var s strings.Builder
	fmt.Fprintf(&s, "%d|%d|", k.Ref.Field, k.Ref.AttrScope)
	for i, p := range k.Ref.AttrPath {
		if i > 0 {
			s.WriteString(".")
		}
		s.WriteString(p)
	}
	fmt.Fprintf(&s, "|%t|%t", k.Negated, k.CaseInsensitive)
	return matchKeyString(s.String())
}

// compileGroup compiles a group of patterns into a Hyperscan database.
func compileGroup(entries []patternEntry, caseInsensitive bool) (*CompiledDatabase, error) {
	patterns := make([]*hyperscan.Pattern, len(entries))
	patternIndex := make([]PatternRef, len(entries))

	flags := hyperscan.SomLeftMost
	if caseInsensitive {
		flags |= hyperscan.Caseless
	}

	for i, e := range entries {
		if _, err := regexp.Compile(e.pattern); err != nil {
			return nil, fmt.Errorf("invalid regex %q: %w", e.pattern, err)
		}

		patterns[i] = hyperscan.NewPattern(e.pattern, flags)
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
