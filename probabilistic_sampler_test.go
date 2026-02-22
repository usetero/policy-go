package policy

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/usetero/policy-go/internal/engine"
	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
)

func TestExtractRandomnessFromTraceID_Hex32(t *testing.T) {
	// 32-char hex trace ID: last 14 hex chars = 56 bits of randomness
	traceID := []byte("0123456789abcdef0123456789abcdef")
	r := extractRandomnessFromTraceID(traceID)
	assert.NotZero(t, r)
	// Should be masked to 56 bits
	assert.Less(t, r, maxThreshold)
}

func TestExtractRandomnessFromTraceID_Binary(t *testing.T) {
	// 16-byte binary trace ID
	traceID := make([]byte, 16)
	traceID[15] = 0x42
	r := extractRandomnessFromTraceID(traceID)
	assert.Equal(t, uint64(0x42), r)
}

func TestExtractRandomnessFromTraceID_Short(t *testing.T) {
	traceID := []byte{0x01, 0x02}
	r := extractRandomnessFromTraceID(traceID)
	assert.Equal(t, uint64(0x0102), r)
}

func TestExtractRandomnessFromTraceID_Empty(t *testing.T) {
	r := extractRandomnessFromTraceID(nil)
	assert.Zero(t, r)
}

func TestCalculateRejectionThreshold(t *testing.T) {
	tests := []struct {
		pct      float64
		expected uint64
	}{
		{100, 0},
		{0, maxThreshold},
		{50, maxThreshold / 2},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%.0f%%", tt.pct), func(t *testing.T) {
			got := calculateRejectionThreshold(tt.pct)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestParseTracestateRandomness(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		wantRV uint64
		wantOK bool
	}{
		{"valid rv", "ot=rv:80000000000000", 0x80000000000000, true},
		{"no ot entry", "foo=bar", 0, false},
		{"no rv subkey", "ot=th:50", 0, false},
		{"rv with other keys", "ot=th:50;rv:ff000000000000", 0xff000000000000, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rv, ok := parseTracestateRandomness([]byte(tt.input))
			assert.Equal(t, tt.wantOK, ok)
			if ok {
				assert.Equal(t, tt.wantRV, rv)
			}
		})
	}
}

func TestProbabilisticSample_EdgeCases(t *testing.T) {
	traceID := []byte("0123456789abcdef0123456789abcdef")

	// 100% always keeps
	assert.True(t, probabilisticSample(traceID, 100))

	// 0% always drops
	assert.False(t, probabilisticSample(traceID, 0))
}

func TestProbabilisticSample_Deterministic(t *testing.T) {
	traceID := []byte("0123456789abcdef0123456789abcdef")
	result1 := probabilisticSample(traceID, 50)
	result2 := probabilisticSample(traceID, 50)
	assert.Equal(t, result1, result2, "same input should produce same result")
}

func TestProbabilisticSample_Distribution(t *testing.T) {
	kept := 0
	total := 1000

	for i := 0; i < total; i++ {
		traceID := []byte(fmt.Sprintf("%018x%014x", uint64(0), uint64(i)*72057594037927))
		if probabilisticSample(traceID, 50) {
			kept++
		}
	}

	keepRate := float64(kept) / float64(total) * 100
	assert.InDelta(t, 50.0, keepRate, 15.0, "sampling rate should be roughly 50%% (got %.1f%%)", keepRate)
}

func TestHexDecode(t *testing.T) {
	dst := make([]byte, 3)
	hexDecode(dst, []byte("ff00ab"))
	assert.Equal(t, []byte{0xff, 0x00, 0xab}, dst)
}

func TestFindOTelEntry(t *testing.T) {
	assert.Equal(t, 3, findOTelEntry([]byte("ot=rv:abc")))
	assert.Equal(t, -1, findOTelEntry([]byte("foo=bar")))
}

func TestFindSubKey(t *testing.T) {
	assert.Equal(t, 0, findSubKey([]byte("rv:abc"), []byte("rv:")))
	assert.Equal(t, 6, findSubKey([]byte("th:50;rv:abc"), []byte("rv:")))
	assert.Equal(t, -1, findSubKey([]byte("th:50"), []byte("rv:")))
}

// ============================================================================
// Threshold/Probability conversion helpers
// ============================================================================

func TestThresholdToProbability(t *testing.T) {
	tests := []struct {
		name      string
		threshold uint64
		expected  float64
	}{
		{"zero threshold = probability 1.0", 0, 1.0},
		{"max threshold = probability 0.0", maxThreshold, 0.0},
		{"half threshold = probability 0.5", maxThreshold / 2, 0.5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := thresholdToProbability(tt.threshold)
			assert.InDelta(t, tt.expected, got, 1e-10)
		})
	}
}

func TestProbabilityToThreshold(t *testing.T) {
	tests := []struct {
		name     string
		prob     float64
		expected uint64
	}{
		{"probability 1.0 = zero threshold", 1.0, 0},
		{"probability 0.0 = max threshold", 0.0, maxThreshold},
		{"probability 0.5 = half threshold", 0.5, maxThreshold / 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := probabilityToThreshold(tt.prob)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestThresholdProbabilityRoundTrip(t *testing.T) {
	// Converting probability → threshold → probability should be close to original
	for _, p := range []float64{0.1, 0.25, 0.5, 0.75, 0.9, 1.0} {
		th := probabilityToThreshold(p)
		got := thresholdToProbability(th)
		assert.InDelta(t, p, got, 1e-6, "round trip for p=%f", p)
	}
}

// ============================================================================
// parseTracestateThreshold
// ============================================================================

func TestParseTracestateThreshold(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		wantTH uint64
		wantOK bool
	}{
		{"full 14 hex digits", "ot=th:80000000000000", 0x80000000000000, true},
		{"short threshold (4 digits, padded right)", "ot=th:8000", 0x80000000000000, true},
		{"single digit", "ot=th:8", 0x80000000000000, true},
		{"zero threshold", "ot=th:0", 0, true},
		{"with rv", "ot=th:8000;rv:ff000000000000", 0x80000000000000, true},
		{"no ot entry", "foo=bar", 0, false},
		{"no th subkey", "ot=rv:ff000000000000", 0, false},
		{"empty th value", "ot=th:", 0, false},
		{"th with comma separator", "ot=th:8000,other=val", 0x80000000000000, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			th, ok := parseTracestateThreshold([]byte(tt.input))
			assert.Equal(t, tt.wantOK, ok)
			if ok {
				assert.Equal(t, tt.wantTH, th, "threshold mismatch")
			}
		})
	}
}

// ============================================================================
// shouldSampleTrace mode tests
// ============================================================================

// makeTracePolicy creates a CompiledPolicy with the given sampling configuration.
func makeTracePolicy(percentage float64, mode policyv1.SamplingMode, seed uint32, failClosed bool) *engine.CompiledPolicy[engine.TraceField] {
	return &engine.CompiledPolicy[engine.TraceField]{
		Keep: engine.Keep{
			Action:            engine.KeepSample,
			Value:             percentage,
			SamplingMode:      mode,
			HashSeed:          seed,
			SamplingPrecision: 4,
			FailClosed:        failClosed,
		},
	}
}

func TestShouldSampleTraceHashSeedZero(t *testing.T) {
	// seed=0 should behave like the default (extract R from trace ID)
	policy := makeTracePolicy(50, policyv1.SamplingMode_SAMPLING_MODE_HASH_SEED, 0, true)
	span := &SimpleSpanRecord{
		TraceID: []byte("0123456789abcdef0123456789abcdef"),
	}

	result1, _, _ := shouldSampleTrace(policy, span, SimpleSpanMatcher)
	result2, _, _ := shouldSampleTrace(policy, span, SimpleSpanMatcher)
	assert.Equal(t, result1, result2, "deterministic for same trace ID")
}

func TestShouldSampleTraceHashSeedNonZero(t *testing.T) {
	// Non-zero seed should produce deterministic, potentially different results
	policy1 := makeTracePolicy(50, policyv1.SamplingMode_SAMPLING_MODE_HASH_SEED, 42, true)
	policy2 := makeTracePolicy(50, policyv1.SamplingMode_SAMPLING_MODE_HASH_SEED, 99, true)
	span := &SimpleSpanRecord{
		TraceID: []byte("0123456789abcdef0123456789abcdef"),
	}

	// Same seed → same result
	r1a, _, _ := shouldSampleTrace(policy1, span, SimpleSpanMatcher)
	r1b, _, _ := shouldSampleTrace(policy1, span, SimpleSpanMatcher)
	assert.Equal(t, r1a, r1b, "same seed should be deterministic")

	// Different seeds may produce different results (test with many trace IDs)
	differentCount := 0
	for i := 0; i < 100; i++ {
		s := &SimpleSpanRecord{
			TraceID: []byte(fmt.Sprintf("%032x", i)),
		}
		r1, _, _ := shouldSampleTrace(policy1, s, SimpleSpanMatcher)
		r2, _, _ := shouldSampleTrace(policy2, s, SimpleSpanMatcher)
		if r1 != r2 {
			differentCount++
		}
	}
	assert.Greater(t, differentCount, 0, "different seeds should produce some different results")
}

func TestShouldSampleTraceHashSeedDistribution(t *testing.T) {
	policy := makeTracePolicy(50, policyv1.SamplingMode_SAMPLING_MODE_HASH_SEED, 12345, true)
	kept := 0
	total := 1000
	for i := 0; i < total; i++ {
		span := &SimpleSpanRecord{
			TraceID: []byte(fmt.Sprintf("%032x", i)),
		}
		if keep, _, _ := shouldSampleTrace(policy, span, SimpleSpanMatcher); keep {
			kept++
		}
	}
	keepRate := float64(kept) / float64(total) * 100
	assert.InDelta(t, 50.0, keepRate, 15.0, "hash_seed sampling rate should be roughly 50%% (got %.1f%%)", keepRate)
}

func TestShouldSampleTraceProportional(t *testing.T) {
	// Incoming spans already sampled at 50% (th for 50% = 0x80000000000000, encoded as "8")
	// Target: 10% overall → product probability = 0.1 * 0.5 = 0.05
	// T_o = ProbabilityToThreshold(0.05) ≈ 0.95 * 2^56
	// Should keep ~5% of uniform randomness, or ~10% of spans that already passed 50% threshold
	policy := makeTracePolicy(10, policyv1.SamplingMode_SAMPLING_MODE_PROPORTIONAL, 0, true)

	kept := 0
	total := 1000
	traceState := []byte("ot=th:8")

	for i := 0; i < total; i++ {
		// Distribute trace IDs across the full 56-bit space
		span := &SimpleSpanRecord{
			TraceID:    []byte(fmt.Sprintf("%018x%014x", uint64(0), uint64(i)*uint64(maxThreshold/uint64(total)))),
			TraceState: traceState,
		}
		if keep, _, _ := shouldSampleTrace(policy, span, SimpleSpanMatcher); keep {
			kept++
		}
	}

	// With incoming at 50% and target at 10%, product probability is 5%.
	// Of 1000 uniformly distributed spans, ~50 should be kept.
	keepRate := float64(kept) / float64(total) * 100
	assert.InDelta(t, 5.0, keepRate, 10.0, "proportional should keep ~5%% of uniform input (got %.1f%%)", keepRate)
}

func TestShouldSampleTraceProportionalNoThreshold(t *testing.T) {
	// No th in tracestate → treat as p=1.0 (no prior sampling)
	// Should behave like hash_seed at the target percentage
	policy := makeTracePolicy(50, policyv1.SamplingMode_SAMPLING_MODE_PROPORTIONAL, 0, true)

	kept := 0
	total := 1000
	for i := 0; i < total; i++ {
		span := &SimpleSpanRecord{
			TraceID: []byte(fmt.Sprintf("%018x%014x", uint64(0), uint64(i)*uint64(maxThreshold/uint64(total)))),
		}
		if keep, _, _ := shouldSampleTrace(policy, span, SimpleSpanMatcher); keep {
			kept++
		}
	}

	keepRate := float64(kept) / float64(total) * 100
	assert.InDelta(t, 50.0, keepRate, 15.0, "proportional with no th should keep ~50%% (got %.1f%%)", keepRate)
}

func TestShouldSampleTraceEqualizing(t *testing.T) {
	// Target 50% sampling. Incoming spans have no threshold (T_s=0, p=1.0).
	// Should apply the 50% threshold: keep if R >= T_d.
	policy := makeTracePolicy(50, policyv1.SamplingMode_SAMPLING_MODE_EQUALIZING, 0, true)

	kept := 0
	total := 1000
	for i := 0; i < total; i++ {
		span := &SimpleSpanRecord{
			TraceID: []byte(fmt.Sprintf("%018x%014x", uint64(0), uint64(i)*uint64(maxThreshold/uint64(total)))),
		}
		if keep, _, _ := shouldSampleTrace(policy, span, SimpleSpanMatcher); keep {
			kept++
		}
	}

	keepRate := float64(kept) / float64(total) * 100
	assert.InDelta(t, 50.0, keepRate, 15.0, "equalizing should keep ~50%% (got %.1f%%)", keepRate)
}

func TestShouldSampleTraceEqualizingHigherIncoming(t *testing.T) {
	// Incoming spans already sampled at 10% (threshold is MORE restrictive than target 50%)
	// Equalizing should KEEP all these spans since T_s > T_d
	policy := makeTracePolicy(50, policyv1.SamplingMode_SAMPLING_MODE_EQUALIZING, 0, true)

	// th for 10%: T = (1-0.1)*2^56 = 0.9 * 2^56 ≈ 0xe6666666666666
	traceState := []byte("ot=th:e6666666666666")

	kept := 0
	total := 100
	for i := 0; i < total; i++ {
		span := &SimpleSpanRecord{
			TraceID:    []byte(fmt.Sprintf("%018x%014x", uint64(0), uint64(i)*uint64(maxThreshold/uint64(total)))),
			TraceState: traceState,
		}
		if keep, _, _ := shouldSampleTrace(policy, span, SimpleSpanMatcher); keep {
			kept++
		}
	}

	assert.Equal(t, total, kept, "equalizing should keep ALL spans when T_s > T_d")
}

func TestShouldSampleTraceFailClosed(t *testing.T) {
	// No trace ID → can't get randomness → should drop with fail_closed=true
	policy := makeTracePolicy(50, policyv1.SamplingMode_SAMPLING_MODE_HASH_SEED, 0, true)
	span := &SimpleSpanRecord{} // no TraceID

	keep, _, _ := shouldSampleTrace(policy, span, SimpleSpanMatcher)
	assert.False(t, keep, "fail_closed should drop when no randomness")
}

func TestShouldSampleTraceFailOpen(t *testing.T) {
	// No trace ID → can't get randomness → should keep with fail_closed=false
	policy := makeTracePolicy(50, policyv1.SamplingMode_SAMPLING_MODE_HASH_SEED, 0, false)
	span := &SimpleSpanRecord{} // no TraceID

	keep, _, _ := shouldSampleTrace(policy, span, SimpleSpanMatcher)
	assert.True(t, keep, "fail_open should keep when no randomness")
}

func TestShouldSampleTraceProportionalFailClosed(t *testing.T) {
	// Proportional mode with no trace ID → fail_closed=true should drop
	policy := makeTracePolicy(50, policyv1.SamplingMode_SAMPLING_MODE_PROPORTIONAL, 0, true)
	span := &SimpleSpanRecord{} // no TraceID

	keep, _, _ := shouldSampleTrace(policy, span, SimpleSpanMatcher)
	assert.False(t, keep, "proportional fail_closed should drop when no randomness")
}

func TestShouldSampleTraceEqualizingFailOpen(t *testing.T) {
	// Equalizing mode with no trace ID → fail_closed=false should keep
	policy := makeTracePolicy(50, policyv1.SamplingMode_SAMPLING_MODE_EQUALIZING, 0, false)
	span := &SimpleSpanRecord{} // no TraceID

	keep, _, _ := shouldSampleTrace(policy, span, SimpleSpanMatcher)
	assert.True(t, keep, "equalizing fail_open should keep when no randomness")
}

// ============================================================================
// encodeThreshold tests
// ============================================================================

func TestEncodeThreshold(t *testing.T) {
	tests := []struct {
		name      string
		threshold uint64
		precision uint32
		expected  string
	}{
		{"zero threshold", 0, 4, "0"},
		{"50% threshold", 0x80000000000000, 4, "8"},
		{"50% threshold precision 1", 0x80000000000000, 1, "8"},
		{"50% threshold precision 14", 0x80000000000000, 14, "8"},
		{"10% threshold", calculateRejectionThreshold(10), 4, "e666"},
		{"full precision threshold", 0x123456789abcde, 4, "1234"},
		{"precision 0 defaults to 4", 0x80000000000000, 0, "8"},
		{"precision > 14 clamped", 0x80000000000000, 20, "8"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := encodeThreshold(tt.threshold, tt.precision)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// ============================================================================
// shouldSampleTrace threshold return value tests
// ============================================================================

func TestShouldSampleTraceReturnsThreshold(t *testing.T) {
	// hash_seed mode should return calculateRejectionThreshold(percentage)
	policy := makeTracePolicy(50, policyv1.SamplingMode_SAMPLING_MODE_HASH_SEED, 0, true)
	span := &SimpleSpanRecord{
		TraceID: []byte("0123456789abcdef0123456789abcdef"),
	}

	_, threshold, _ := shouldSampleTrace(policy, span, SimpleSpanMatcher)
	assert.Equal(t, calculateRejectionThreshold(50), threshold)
}

func TestShouldSampleTrace100PercentReturnsZeroThreshold(t *testing.T) {
	policy := makeTracePolicy(100, policyv1.SamplingMode_SAMPLING_MODE_HASH_SEED, 0, true)
	span := &SimpleSpanRecord{
		TraceID: []byte("0123456789abcdef0123456789abcdef"),
	}

	keep, threshold, _ := shouldSampleTrace(policy, span, SimpleSpanMatcher)
	assert.True(t, keep)
	assert.Equal(t, uint64(0), threshold)
}

func TestShouldSampleTraceEqualizingReturnsIncomingThreshold(t *testing.T) {
	// When T_s > T_d, equalizing should return the incoming threshold
	policy := makeTracePolicy(50, policyv1.SamplingMode_SAMPLING_MODE_EQUALIZING, 0, true)
	traceState := []byte("ot=th:e6666666666666") // T_s for 10%

	span := &SimpleSpanRecord{
		TraceID:    []byte("0123456789abcdef0123456789abcdef"),
		TraceState: traceState,
	}

	keep, threshold, _ := shouldSampleTrace(policy, span, SimpleSpanMatcher)
	assert.True(t, keep)
	assert.Equal(t, uint64(0xe6666666666666), threshold, "should return incoming threshold when T_s > T_d")
}
