package engine

import (
	"sync/atomic"
	"time"
)

// RateLimiter provides lock-free rate limiting for telemetry policies.
//
// Uses atomic operations for thread-safe access without locks.
// Designed to be embedded directly in policy structs.
//
// Window reset happens inline on first request after expiry via CAS,
// eliminating the need for a background reset task.
//
// # Memory Ordering
//
// Uses atomic operations with appropriate memory ordering:
//   - windowStart: load/store with atomic semantics to synchronize window boundaries
//   - count: atomic add for increment
//
// # Race Conditions
//
// At window boundaries, there's a brief race where:
//  1. Multiple goroutines may attempt reset simultaneously (CAS ensures only one wins)
//  2. Goroutines may increment the old counter after reset (acceptable over-admission)
//
// The maximum over-admission is bounded by limit + num_concurrent_goroutines - 1.
type RateLimiter struct {
	// count is the current request count in this window.
	count atomic.Uint32

	// windowStart is the window start timestamp in milliseconds since epoch.
	windowStart atomic.Int64

	// limit is the maximum requests allowed per window.
	limit uint32

	// windowMs is the window duration in milliseconds.
	windowMs uint32

	// timeSource is an injectable time source for testing.
	// Returns current time in milliseconds since epoch.
	timeSource func() int64
}

// defaultTimeSource returns the current time in milliseconds since epoch.
func defaultTimeSource() int64 {
	return time.Now().UnixMilli()
}

// NewRateLimiter creates a rate limiter with custom window duration.
func NewRateLimiter(limit uint32, windowMs uint32) *RateLimiter {
	return newRateLimiterWithTimeSource(limit, windowMs, defaultTimeSource)
}

// newRateLimiterWithTimeSource creates a rate limiter with injectable time source (for testing).
func newRateLimiterWithTimeSource(limit uint32, windowMs uint32, timeSource func() int64) *RateLimiter {
	now := timeSource()
	r := &RateLimiter{
		limit:      limit,
		windowMs:   windowMs,
		timeSource: timeSource,
	}
	r.windowStart.Store(now)
	return r
}

// NewRateLimiterPerSecond creates a rate limiter with per-second window.
func NewRateLimiterPerSecond(limit uint32) *RateLimiter {
	return NewRateLimiter(limit, 1000)
}

// NewRateLimiterPerMinute creates a rate limiter with per-minute window.
func NewRateLimiterPerMinute(limit uint32) *RateLimiter {
	return NewRateLimiter(limit, 60_000)
}

// ShouldKeep checks if request should be allowed and increments counter atomically.
//
// Returns true if under the rate limit, false if limit exceeded.
// Automatically resets window when expired.
func (r *RateLimiter) ShouldKeep() bool {
	now := r.timeSource()

	// Fast path: check if window might be expired
	windowStart := r.windowStart.Load()
	elapsed := now - windowStart

	if elapsed >= int64(r.windowMs) {
		// Window expired - try to reset
		r.tryResetWindow(windowStart, now)
	}

	// Increment and check limit
	// Add returns new value, so we check if prev (new-1) < limit
	newCount := r.count.Add(1)
	return newCount-1 < r.limit
}

// tryResetWindow attempts to reset the window. Only one goroutine wins the CAS race.
func (r *RateLimiter) tryResetWindow(expectedStart, now int64) {
	// CAS to claim the reset - only one goroutine succeeds
	if r.windowStart.CompareAndSwap(expectedStart, now) {
		// We won the race, reset the counter
		r.count.Store(0)
	}
	// If CAS failed, another goroutine already reset - that's fine
}

// CurrentCount returns current count (for testing/debugging only).
func (r *RateLimiter) CurrentCount() uint32 {
	return r.count.Load()
}

// CurrentWindowStart returns window start (for testing/debugging only).
func (r *RateLimiter) CurrentWindowStart() int64 {
	return r.windowStart.Load()
}

// Reset forces a reset (for testing only).
func (r *RateLimiter) Reset() {
	r.count.Store(0)
	r.windowStart.Store(r.timeSource())
}
