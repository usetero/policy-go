package engine

import (
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"

	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
)

// KeepAction represents what to do with matched telemetry.
// This is a parsed representation of the proto's keep string field.
type KeepAction int

const (
	KeepAll KeepAction = iota
	KeepNone
	KeepSample
	KeepRatePerSecond
	KeepRatePerMinute
)

// Keep represents a compiled keep action with its parameters.
// Parsed from the proto's keep string field (e.g., "all", "none", "50%", "100/s", "10/5m")
// or from TraceSamplingConfig for trace policies.
type Keep struct {
	Action            KeepAction
	Value             float64
	Duration          uint32 // duration multiplier for rate limits (default 1)
	SamplingMode      policyv1.SamplingMode
	HashSeed          uint32
	SamplingPrecision uint32 // 1-14, default 4
	FailClosed        bool   // default true
}

// Restrictiveness returns a score indicating how restrictive this keep action is.
func (k Keep) Restrictiveness() int {
	switch k.Action {
	case KeepNone:
		return 1000
	case KeepSample:
		return int(1000 - k.Value*10)
	case KeepRatePerSecond, KeepRatePerMinute:
		return 500
	case KeepAll:
		return 0
	default:
		return 0
	}
}

// ParseKeep parses a keep string from the proto into a Keep struct.
// Valid values: "all", "none", "N%", "N/s", "N/m"
func ParseKeep(s string) (Keep, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "all" {
		return Keep{Action: KeepAll}, nil
	}
	if s == "none" {
		return Keep{Action: KeepNone}, nil
	}
	if strings.HasSuffix(s, "%") {
		val, err := strconv.ParseFloat(strings.TrimSuffix(s, "%"), 64)
		if err != nil {
			return Keep{}, fmt.Errorf("invalid keep percentage %q: %w", s, err)
		}
		if val < 0 || val > 100 {
			return Keep{}, fmt.Errorf("keep percentage must be between 0 and 100, got %v", val)
		}
		return Keep{Action: KeepSample, Value: val}, nil
	}
	// Rate limit: N/s, N/m, N/Ds, N/Dm
	if idx := strings.Index(s, "/"); idx > 0 {
		countStr := s[:idx]
		windowStr := s[idx+1:]
		if len(windowStr) == 0 {
			return Keep{}, fmt.Errorf("invalid keep value %q: missing window unit", s)
		}

		unit := windowStr[len(windowStr)-1]
		if unit != 's' && unit != 'm' {
			return Keep{}, fmt.Errorf("invalid keep value %q: window must end with 's' or 'm'", s)
		}

		// Parse count — must be a positive integer
		count, err := strconv.ParseUint(countStr, 10, 32)
		if err != nil {
			return Keep{}, fmt.Errorf("invalid keep rate %q: count must be a positive integer: %w", s, err)
		}
		if count == 0 {
			return Keep{}, fmt.Errorf("invalid keep rate %q: count must be a positive integer", s)
		}

		// Parse duration multiplier (the part between '/' and the unit)
		var duration uint32 = 1
		durStr := windowStr[:len(windowStr)-1]
		if len(durStr) > 0 {
			dur, err := strconv.ParseUint(durStr, 10, 32)
			if err != nil {
				return Keep{}, fmt.Errorf("invalid keep rate %q: duration must be a positive integer: %w", s, err)
			}
			if dur == 0 {
				return Keep{}, fmt.Errorf("invalid keep rate %q: duration must be a positive integer", s)
			}
			duration = uint32(dur)
		}

		action := KeepRatePerSecond
		if unit == 'm' {
			action = KeepRatePerMinute
		}
		return Keep{Action: action, Value: float64(count), Duration: duration}, nil
	}
	return Keep{}, fmt.Errorf("invalid keep value %q", s)
}

// transformStageStats holds atomic hit/miss counters for a single transform stage.
type transformStageStats struct {
	hits   atomic.Uint64
	misses atomic.Uint64
}

// PolicyStats holds atomic counters for a single policy.
type PolicyStats struct {
	MatchHits   atomic.Uint64
	MatchMisses atomic.Uint64

	RemoveStats transformStageStats
	RedactStats transformStageStats
	RenameStats transformStageStats
	AddStats    transformStageStats
}

// RecordMatchHit increments the match hit counter.
// A match hit means the policy matched and the final outcome was consistent with its intent.
func (s *PolicyStats) RecordMatchHit() {
	s.MatchHits.Add(1)
}

// RecordMatchMiss increments the match miss counter.
// A match miss means the policy matched but a more restrictive policy overrode the outcome.
func (s *PolicyStats) RecordMatchMiss() {
	s.MatchMisses.Add(1)
}

// RecordTransformHit increments the hit counter for the given transform kind.
func (s *PolicyStats) RecordTransformHit(kind TransformKind) {
	switch kind {
	case TransformRemove:
		s.RemoveStats.hits.Add(1)
	case TransformRedact:
		s.RedactStats.hits.Add(1)
	case TransformRename:
		s.RenameStats.hits.Add(1)
	case TransformAdd:
		s.AddStats.hits.Add(1)
	}
}

// RecordTransformMiss increments the miss counter for the given transform kind.
func (s *PolicyStats) RecordTransformMiss(kind TransformKind) {
	switch kind {
	case TransformRemove:
		s.RemoveStats.misses.Add(1)
	case TransformRedact:
		s.RedactStats.misses.Add(1)
	case TransformRename:
		s.RenameStats.misses.Add(1)
	case TransformAdd:
		s.AddStats.misses.Add(1)
	}
}

// PolicyStatsSnapshot is an immutable copy of stats for reporting.
type PolicyStatsSnapshot struct {
	PolicyID string

	MatchHits   uint64
	MatchMisses uint64

	RemoveHits   uint64
	RemoveMisses uint64
	RedactHits   uint64
	RedactMisses uint64
	RenameHits   uint64
	RenameMisses uint64
	AddHits      uint64
	AddMisses    uint64
}

// Snapshot atomically reads and resets all counters, returning an immutable snapshot.
// Each call returns the delta since the last Snapshot call.
func (s *PolicyStats) Snapshot(policyID string) PolicyStatsSnapshot {
	return PolicyStatsSnapshot{
		PolicyID:     policyID,
		MatchHits:    s.MatchHits.Swap(0),
		MatchMisses:  s.MatchMisses.Swap(0),
		RemoveHits:   s.RemoveStats.hits.Swap(0),
		RemoveMisses: s.RemoveStats.misses.Swap(0),
		RedactHits:   s.RedactStats.hits.Swap(0),
		RedactMisses: s.RedactStats.misses.Swap(0),
		RenameHits:   s.RenameStats.hits.Swap(0),
		RenameMisses: s.RenameStats.misses.Swap(0),
		AddHits:      s.AddStats.hits.Swap(0),
		AddMisses:    s.AddStats.misses.Swap(0),
	}
}
