package engine

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/usetero/policy-go/policy/regexbackend"
)

// matchersBuilder accumulates matchers and builds a CompiledMatchers.
type matchersBuilder[T FieldType] struct {
	backend         regexbackend.Backend
	groups          map[matchKeyString][]patternEntry
	groupKeys       map[matchKeyString]MatchKey[T]
	existenceChecks []ExistenceCheck[T]
	typedChecks     []TypedCheck[T]
	policies        map[string]*CompiledPolicy[T]
	policyList      []*CompiledPolicy[T]
	policyIndices   map[string]int
}

// newMatchersBuilder creates a new builder using the given regex backend.
func newMatchersBuilder[T FieldType](backend regexbackend.Backend) *matchersBuilder[T] {
	return &matchersBuilder[T]{
		backend:       backend,
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
			MustExist:   mustExist != negated, // XOR: negate inverts the existence requirement
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

// pendingMatcher records an addMatcher call buffered in a policyStaging until
// the policy is committed.
type pendingMatcher[T FieldType] struct {
	ref             FieldRef[T]
	pattern         string
	isExistence     bool
	mustExist       bool
	negated         bool
	caseInsensitive bool
	matcherIndex    int
}

// pendingTypedCheck records an addTypedCheck call buffered in a policyStaging
// until the policy is committed.
type pendingTypedCheck[T FieldType] struct {
	ref          FieldRef[T]
	matcher      CompiledTypedMatcher
	negate       bool
	matcherIndex int
}

// policyStaging buffers one policy's matchers so the whole policy can be
// committed to the builder atomically — or discarded entirely if any part of it
// (action or matcher) fails to compile. Discarding keeps a broken policy out of
// the matcher index so it is never reserved, evaluated, or counted, matching
// policy-rs/policy-zig. Buffering also means a policy's dense index is only
// claimed at commit time, so excluded policies leave no gap in the index space.
type policyStaging[T FieldType] struct {
	matchers []pendingMatcher[T]
	typed    []pendingTypedCheck[T]
}

// addMatcher buffers a matcher; see matchersBuilder.addMatcher for semantics.
func (s *policyStaging[T]) addMatcher(ref FieldRef[T], pattern string, isExistence bool, mustExist bool, negated bool, caseInsensitive bool, matcherIndex int) {
	s.matchers = append(s.matchers, pendingMatcher[T]{
		ref:             ref,
		pattern:         pattern,
		isExistence:     isExistence,
		mustExist:       mustExist,
		negated:         negated,
		caseInsensitive: caseInsensitive,
		matcherIndex:    matcherIndex,
	})
}

// addTypedCheck buffers a typed check; see matchersBuilder.addTypedCheck.
func (s *policyStaging[T]) addTypedCheck(ref FieldRef[T], matcher CompiledTypedMatcher, negate bool, matcherIndex int) {
	s.typed = append(s.typed, pendingTypedCheck[T]{
		ref:          ref,
		matcher:      matcher,
		negate:       negate,
		matcherIndex: matcherIndex,
	})
}

// commitPolicy reserves a dense index for the staged policy, replays its
// buffered matchers against the builder, and finalizes it. Call this only for a
// policy that compiled cleanly; a policy with any compile error should have its
// staging dropped (simply not committed) so it never enters the index.
func (b *matchersBuilder[T]) commitPolicy(policyID string, staging *policyStaging[T], keep Keep, matcherCount int, sampleKey *FieldRef[T], stats *PolicyStats, transforms []TransformOp) {
	idx := b.reservePolicy(policyID)
	for _, m := range staging.matchers {
		b.addMatcher(m.ref, m.pattern, m.isExistence, m.mustExist, m.negated, m.caseInsensitive, policyID, idx, m.matcherIndex)
	}
	for _, t := range staging.typed {
		b.addTypedCheck(t.ref, t.matcher, t.negate, policyID, idx, t.matcherIndex)
	}
	b.finalizePolicy(policyID, idx, keep, matcherCount, sampleKey, stats, transforms)
}

// addTypedCheck registers a typed comparison (equals/gt/gte/lt/lte). These
// bypass Hyperscan entirely — the comparison runs at eval time against the
// consumer's TypedValue accessor (with a string-Value fallback when the
// consumer hasn't provided one).
func (b *matchersBuilder[T]) addTypedCheck(ref FieldRef[T], matcher CompiledTypedMatcher, negate bool, policyID string, policyIndex int, matcherIndex int) {
	b.typedChecks = append(b.typedChecks, TypedCheck[T]{
		Ref:         ref,
		Matcher:     matcher,
		Negate:      negate,
		PolicyID:    policyID,
		PolicyIndex: policyIndex,
		MatchIndex:  matcherIndex,
	})
}

// finalizePolicy completes the policy with its keep action and other metadata.
func (b *matchersBuilder[T]) finalizePolicy(policyID string, policyIndex int, keep Keep, matcherCount int, sampleKey *FieldRef[T], stats *PolicyStats, transforms []TransformOp) {
	// Create rate limiter if needed
	var rateLimiter *RateLimiter
	duration := keep.Duration
	if duration == 0 {
		duration = 1
	}
	switch keep.Action {
	case KeepRatePerSecond:
		rateLimiter = NewRateLimiter(uint32(keep.Value), duration*1_000)
	case KeepRatePerMinute:
		rateLimiter = NewRateLimiter(uint32(keep.Value), duration*60_000)
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
		typedChecks:     b.typedChecks,
		policies:        b.policies,
		policyList:      b.policyList,
	}

	// Compile each group
	for keyStr, entries := range b.groups {
		key := b.groupKeys[keyStr]
		db, err := compileGroup(b.backend, entries, key.CaseInsensitive)
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

// compileGroup compiles a group of patterns into a CompiledDatabase using the
// configured regex backend.
func compileGroup(backend regexbackend.Backend, entries []patternEntry, caseInsensitive bool) (*CompiledDatabase, error) {
	if backend == nil {
		return nil, fmt.Errorf("no regex backend configured: build with cgo for the default Hyperscan backend, or supply one via policy.WithRegexBackend")
	}

	patterns := make([]string, len(entries))
	patternIndex := make([]PatternRef, len(entries))

	for i, e := range entries {
		if _, err := regexp.Compile(e.pattern); err != nil {
			return nil, fmt.Errorf("invalid regex %q: %w", e.pattern, err)
		}

		patterns[i] = e.pattern
		patternIndex[i] = PatternRef{
			PolicyID:     e.policyID,
			PolicyIndex:  e.policyIndex,
			MatcherIndex: e.matcherIndex,
		}
	}

	matcher, err := backend.Compile(patterns, caseInsensitive)
	if err != nil {
		return nil, err
	}

	return &CompiledDatabase{
		matcher:      matcher,
		patternIndex: patternIndex,
	}, nil
}
