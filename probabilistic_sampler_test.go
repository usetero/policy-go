package policy

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
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
