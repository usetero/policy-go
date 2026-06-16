package engine

import (
	"sync"
	"sync/atomic"
	"testing"
)

// =============================================================================
// Test Helpers
// =============================================================================

// mockTime provides a thread-safe mock time source for testing.
type mockTime struct {
	value atomic.Int64
}

func newMockTime(start int64) *mockTime {
	m := &mockTime{}
	m.value.Store(start)
	return m
}

func (m *mockTime) get() int64 {
	return m.value.Load()
}

func (m *mockTime) set(t int64) {
	m.value.Store(t)
}

func (m *mockTime) advance(delta int64) {
	m.value.Add(delta)
}

// =============================================================================
// Tests - Basic Functionality
// =============================================================================

func TestRateLimiterInit(t *testing.T) {
	limiter := NewRateLimiter(100, 1000)

	if limiter.limit != 100 {
		t.Errorf("expected limit 100, got %d", limiter.limit)
	}
	if limiter.windowMs != 1000 {
		t.Errorf("expected windowMs 1000, got %d", limiter.windowMs)
	}
	if limiter.CurrentCount() != 0 {
		t.Errorf("expected count 0, got %d", limiter.CurrentCount())
	}
}

func TestRateLimiterPerSecond(t *testing.T) {
	limiter := NewRateLimiterPerSecond(50)

	if limiter.limit != 50 {
		t.Errorf("expected limit 50, got %d", limiter.limit)
	}
	if limiter.windowMs != 1000 {
		t.Errorf("expected windowMs 1000, got %d", limiter.windowMs)
	}
}

func TestRateLimiterPerMinute(t *testing.T) {
	limiter := NewRateLimiterPerMinute(1000)

	if limiter.limit != 1000 {
		t.Errorf("expected limit 1000, got %d", limiter.limit)
	}
	if limiter.windowMs != 60_000 {
		t.Errorf("expected windowMs 60000, got %d", limiter.windowMs)
	}
}

func TestRateLimiterAllowsRequestsUnderLimit(t *testing.T) {
	limiter := NewRateLimiterPerSecond(5)

	for i := 0; i < 5; i++ {
		if !limiter.ShouldKeep() {
			t.Errorf("request %d should have been allowed", i+1)
		}
	}

	if limiter.CurrentCount() != 5 {
		t.Errorf("expected count 5, got %d", limiter.CurrentCount())
	}
}

func TestRateLimiterBlocksAtLimit(t *testing.T) {
	limiter := NewRateLimiterPerSecond(3)

	if !limiter.ShouldKeep() {
		t.Error("request 1 should have been allowed")
	}
	if !limiter.ShouldKeep() {
		t.Error("request 2 should have been allowed")
	}
	if !limiter.ShouldKeep() {
		t.Error("request 3 should have been allowed")
	}
	if limiter.ShouldKeep() {
		t.Error("request 4 should have been blocked")
	}

	if limiter.CurrentCount() != 4 {
		t.Errorf("expected count 4, got %d", limiter.CurrentCount())
	}
}

func TestRateLimiterLimitOfOne(t *testing.T) {
	limiter := NewRateLimiterPerSecond(1)

	if !limiter.ShouldKeep() {
		t.Error("first request should have been allowed")
	}
	if limiter.ShouldKeep() {
		t.Error("second request should have been blocked")
	}
	if limiter.ShouldKeep() {
		t.Error("third request should have been blocked")
	}
}

func TestRateLimiterLimitOfZero(t *testing.T) {
	limiter := NewRateLimiterPerSecond(0)

	if limiter.ShouldKeep() {
		t.Error("request should have been blocked with limit 0")
	}
	if limiter.ShouldKeep() {
		t.Error("request should have been blocked with limit 0")
	}
}

func TestRateLimiterHighLimit(t *testing.T) {
	limiter := NewRateLimiterPerSecond(1_000_000)

	for i := 0; i < 10000; i++ {
		if !limiter.ShouldKeep() {
			t.Errorf("request %d should have been allowed with high limit", i+1)
		}
	}
}

func TestRateLimiterReset(t *testing.T) {
	limiter := NewRateLimiterPerSecond(5)

	limiter.ShouldKeep()
	limiter.ShouldKeep()
	if limiter.CurrentCount() != 2 {
		t.Errorf("expected count 2, got %d", limiter.CurrentCount())
	}

	limiter.Reset()
	if limiter.CurrentCount() != 0 {
		t.Errorf("expected count 0 after reset, got %d", limiter.CurrentCount())
	}

	// Should allow again
	if !limiter.ShouldKeep() {
		t.Error("request should be allowed after reset")
	}
}

// =============================================================================
// Tests - Window Expiry (using injectable time)
// =============================================================================

func TestRateLimiterWindowExpiry(t *testing.T) {
	mt := newMockTime(1000)
	limiter := newRateLimiterWithTimeSource(3, 100, mt.get)

	// Use up limit
	if !limiter.ShouldKeep() {
		t.Error("request 1 should have been allowed")
	}
	if !limiter.ShouldKeep() {
		t.Error("request 2 should have been allowed")
	}
	if !limiter.ShouldKeep() {
		t.Error("request 3 should have been allowed")
	}
	if limiter.ShouldKeep() {
		t.Error("request 4 should have been blocked")
	}

	// Advance time past window
	mt.set(1150)

	// Should allow again
	if !limiter.ShouldKeep() {
		t.Error("request should be allowed after window expiry")
	}
	if limiter.CurrentCount() != 1 {
		t.Errorf("expected count 1 after window reset, got %d", limiter.CurrentCount())
	}
}

func TestRateLimiterWindowExpiryAtBoundary(t *testing.T) {
	mt := newMockTime(0)
	limiter := newRateLimiterWithTimeSource(2, 100, mt.get)

	limiter.ShouldKeep()
	limiter.ShouldKeep()
	if limiter.ShouldKeep() {
		t.Error("third request should have been blocked")
	}

	// Exactly at window boundary
	mt.set(100)
	if !limiter.ShouldKeep() {
		t.Error("request should be allowed at window boundary")
	}
}

func TestRateLimiterMultipleWindowRollovers(t *testing.T) {
	mt := newMockTime(0)
	limiter := newRateLimiterWithTimeSource(2, 100, mt.get)

	// Window 1
	if !limiter.ShouldKeep() {
		t.Error("window 1, request 1 should be allowed")
	}
	if !limiter.ShouldKeep() {
		t.Error("window 1, request 2 should be allowed")
	}
	if limiter.ShouldKeep() {
		t.Error("window 1, request 3 should be blocked")
	}

	// Window 2
	mt.set(100)
	if !limiter.ShouldKeep() {
		t.Error("window 2, request 1 should be allowed")
	}
	if !limiter.ShouldKeep() {
		t.Error("window 2, request 2 should be allowed")
	}
	if limiter.ShouldKeep() {
		t.Error("window 2, request 3 should be blocked")
	}

	// Window 3
	mt.set(200)
	if !limiter.ShouldKeep() {
		t.Error("window 3, request 1 should be allowed")
	}
	if !limiter.ShouldKeep() {
		t.Error("window 3, request 2 should be allowed")
	}
	if limiter.ShouldKeep() {
		t.Error("window 3, request 3 should be blocked")
	}

	// Skip to window 10
	mt.set(900)
	if !limiter.ShouldKeep() {
		t.Error("window 10, request 1 should be allowed")
	}
}

func TestRateLimiterTimeGoingBackwards(t *testing.T) {
	mt := newMockTime(1000)
	limiter := newRateLimiterWithTimeSource(3, 100, mt.get)

	limiter.ShouldKeep()
	limiter.ShouldKeep()

	// Time goes backwards (NTP adjustment, etc.)
	mt.set(500)

	// Should still work - elapsed will be negative, won't trigger reset
	if !limiter.ShouldKeep() {
		t.Error("request 3 should be allowed")
	}
	if limiter.ShouldKeep() {
		t.Error("request 4 should be blocked")
	}

	// When time catches up, normal operation resumes
	mt.set(1100)
	if !limiter.ShouldKeep() {
		t.Error("request should be allowed after time catches up")
	}
}

func TestRateLimiterVeryShortWindow(t *testing.T) {
	mt := newMockTime(0)
	limiter := newRateLimiterWithTimeSource(5, 1, mt.get) // 1ms window

	// Should allow 5, then block
	for i := 0; i < 5; i++ {
		if !limiter.ShouldKeep() {
			t.Errorf("request %d should have been allowed", i+1)
		}
	}
	if limiter.ShouldKeep() {
		t.Error("6th request should have been blocked")
	}

	// Advance time past window
	mt.set(2)
	if !limiter.ShouldKeep() {
		t.Error("request should be allowed after window expires")
	}
}

func TestRateLimiterVeryLongWindow(t *testing.T) {
	mt := newMockTime(0)
	// 1 hour window
	limiter := newRateLimiterWithTimeSource(100, 3_600_000, mt.get)

	for i := 0; i < 100; i++ {
		if !limiter.ShouldKeep() {
			t.Errorf("request %d should have been allowed", i+1)
		}
	}
	if limiter.ShouldKeep() {
		t.Error("101st request should have been blocked")
	}

	// Advance 30 minutes - still blocked
	mt.set(1_800_000)
	if limiter.ShouldKeep() {
		t.Error("request should still be blocked at 30 minutes")
	}

	// Advance to 1 hour - reset
	mt.set(3_600_000)
	if !limiter.ShouldKeep() {
		t.Error("request should be allowed after 1 hour")
	}
}

// =============================================================================
// Tests - Concurrent Access
// =============================================================================

func TestRateLimiterConcurrentIncrementsRespectLimit(t *testing.T) {
	// Use a high limit that won't expire during test
	limiter := NewRateLimiterPerSecond(1000)
	var kept atomic.Uint32

	const threadCount = 8
	const iterationsPerThread = 200
	var wg sync.WaitGroup

	for i := 0; i < threadCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterationsPerThread; j++ {
				if limiter.ShouldKeep() {
					kept.Add(1)
				}
			}
		}()
	}

	wg.Wait()

	// Should keep exactly 1000 (the limit)
	keptCount := kept.Load()
	if keptCount != 1000 {
		t.Errorf("expected exactly 1000 kept, got %d", keptCount)
	}
}

func TestRateLimiterConcurrentAccessWithWindowReset(t *testing.T) {
	// Shared mock time that goroutines will advance
	mt := newMockTime(0)
	limiter := newRateLimiterWithTimeSource(10, 100, mt.get)
	var totalKept atomic.Uint32
	var windowsProcessed atomic.Uint32

	const threadCount = 4
	var wg sync.WaitGroup

	for i := 0; i < threadCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Each goroutine processes multiple "windows"
			for w := 0; w < 5; w++ {
				// Try to get through limit
				for j := 0; j < 20; j++ {
					if limiter.ShouldKeep() {
						totalKept.Add(1)
					}
				}
				windowsProcessed.Add(1)
				// Advance time (all goroutines do this, but that's fine)
				mt.advance(100)
			}
		}()
	}

	wg.Wait()

	// Each window allows 10, we have 5 windows per thread, 4 threads
	// Due to races at window boundaries, we allow some variance
	kept := totalKept.Load()
	// Should be roughly 10 * 5 = 50 (per logical window advance)
	// But with concurrent advances and races, bounds are wider
	if kept < 40 {
		t.Errorf("expected at least 40 kept, got %d", kept)
	}
	if kept > 200 {
		t.Errorf("expected at most 200 kept, got %d", kept)
	}
}

func TestRateLimiterNoDataRacesUnderContention(t *testing.T) {
	limiter := NewRateLimiterPerSecond(1000)
	var iterations atomic.Uint32

	const threadCount = 8
	var wg sync.WaitGroup

	for i := 0; i < threadCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				limiter.ShouldKeep()
				iterations.Add(1)
			}
		}()
	}

	wg.Wait()

	// All iterations should complete
	if iterations.Load() != threadCount*1000 {
		t.Errorf("expected %d iterations, got %d", threadCount*1000, iterations.Load())
	}

	// Count should be exactly threadCount * 1000
	if limiter.CurrentCount() != threadCount*1000 {
		t.Errorf("expected count %d, got %d", threadCount*1000, limiter.CurrentCount())
	}
}

func TestRateLimiterCASRaceAtWindowBoundary(t *testing.T) {
	// Test that CAS correctly handles multiple goroutines trying to reset
	mt := newMockTime(0)
	limiter := newRateLimiterWithTimeSource(5, 100, mt.get)
	var resetObserved atomic.Uint32

	// Exhaust limit
	for i := 0; i < 5; i++ {
		limiter.ShouldKeep()
	}

	// Advance time to trigger reset
	mt.set(100)

	// Spawn goroutines that all try to trigger reset simultaneously
	const threadCount = 8
	var wg sync.WaitGroup

	for i := 0; i < threadCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			before := limiter.CurrentWindowStart()
			limiter.ShouldKeep()
			after := limiter.CurrentWindowStart()
			// If window changed, we observed a reset
			if after != before {
				resetObserved.Add(1)
			}
		}()
	}

	wg.Wait()

	// Window should have been reset (new start time)
	if limiter.CurrentWindowStart() != 100 {
		t.Errorf("expected window start 100, got %d", limiter.CurrentWindowStart())
	}

	// Count should be threadCount (all goroutines incremented after reset)
	if limiter.CurrentCount() != threadCount {
		t.Errorf("expected count %d, got %d", threadCount, limiter.CurrentCount())
	}
}

// =============================================================================
// Tests - Edge Cases
// =============================================================================

func TestRateLimiterMaxUint32Limit(t *testing.T) {
	limiter := NewRateLimiterPerSecond(^uint32(0)) // max uint32

	for i := 0; i < 10000; i++ {
		if !limiter.ShouldKeep() {
			t.Errorf("request %d should have been allowed with max limit", i+1)
		}
	}
}

func TestRateLimiterCountOverflowProtection(t *testing.T) {
	limiter := NewRateLimiterPerSecond(5)

	// Exhaust limit
	for i := 0; i < 5; i++ {
		limiter.ShouldKeep()
	}

	// Hammer it many times past limit
	for i := 0; i < 10000; i++ {
		if limiter.ShouldKeep() {
			t.Error("request should be blocked after limit reached")
		}
	}

	// Count will be high but ShouldKeep still works correctly
	if limiter.CurrentCount() <= 5 {
		t.Errorf("expected count > 5, got %d", limiter.CurrentCount())
	}
}

func TestRateLimiterWindowMsOfZero(t *testing.T) {
	mt := newMockTime(0)
	// Edge case: 0ms window means always expired
	limiter := newRateLimiterWithTimeSource(2, 0, mt.get)

	// First two should be allowed (reset happens, then increment)
	if !limiter.ShouldKeep() {
		t.Error("first request should be allowed")
	}
	if !limiter.ShouldKeep() {
		t.Error("second request should be allowed")
	}
	// Third triggers reset again since elapsed >= 0 is always true
	if !limiter.ShouldKeep() {
		t.Error("third request should be allowed with 0ms window")
	}
}
