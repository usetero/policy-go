package engine

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeepRestrictiveness(t *testing.T) {
	tests := []struct {
		name     string
		keep     Keep
		expected int
	}{
		{"KeepNone is most restrictive", Keep{Action: KeepNone}, 1000},
		{"KeepAll is least restrictive", Keep{Action: KeepAll}, 0},
		{"KeepSample 0% is very restrictive", Keep{Action: KeepSample, Value: 0}, 1000},
		{"KeepSample 50% is medium", Keep{Action: KeepSample, Value: 50}, 500},
		{"KeepSample 100% is least restrictive", Keep{Action: KeepSample, Value: 100}, 0},
		{"KeepRatePerSecond is medium", Keep{Action: KeepRatePerSecond, Value: 10}, 500},
		{"KeepRatePerMinute is medium", Keep{Action: KeepRatePerMinute, Value: 100}, 500},
		{"Unknown action defaults to 0", Keep{Action: KeepAction(99)}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.keep.Restrictiveness()
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestParseKeep(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected Keep
		hasError bool
	}{
		{"empty is all", "", Keep{Action: KeepAll}, false},
		{"all", "all", Keep{Action: KeepAll}, false},
		{"none", "none", Keep{Action: KeepNone}, false},
		{"50%", "50%", Keep{Action: KeepSample, Value: 50}, false},
		{"100%", "100%", Keep{Action: KeepSample, Value: 100}, false},
		{"0%", "0%", Keep{Action: KeepSample, Value: 0}, false},
		{"100/s", "100/s", Keep{Action: KeepRatePerSecond, Value: 100}, false},
		{"1000/m", "1000/m", Keep{Action: KeepRatePerMinute, Value: 1000}, false},
		{"invalid", "invalid", Keep{}, true},
		{"negative percentage", "-10%", Keep{}, true},
		{"over 100%", "150%", Keep{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseKeep(tt.input)
			if tt.hasError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, got)
			}
		})
	}
}

func TestPolicyStats(t *testing.T) {
	stats := &PolicyStats{}

	// Test initial values
	snapshot := stats.Snapshot("test-policy")
	assert.Equal(t, uint64(0), snapshot.MatchHits)
	assert.Equal(t, uint64(0), snapshot.MatchMisses)
	assert.Equal(t, "test-policy", snapshot.PolicyID)

	// Test incrementing
	stats.RecordMatchHit()
	stats.RecordMatchHit()
	stats.RecordMatchMiss()

	snapshot = stats.Snapshot("test-policy")
	assert.Equal(t, uint64(2), snapshot.MatchHits)
	assert.Equal(t, uint64(1), snapshot.MatchMisses)

	// Snapshot resets counters
	snapshot = stats.Snapshot("test-policy")
	assert.Equal(t, uint64(0), snapshot.MatchHits)
	assert.Equal(t, uint64(0), snapshot.MatchMisses)
}

func TestNewMatchersBuilder(t *testing.T) {
	builder := newMatchersBuilder[LogField]()

	assert.NotNil(t, builder.groups)
	assert.NotNil(t, builder.policies)
}
