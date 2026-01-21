package policy

import "github.com/usetero/policy-go/internal/engine"

// Re-export types from internal/engine.
type (
	KeepAction = engine.KeepAction
	Keep       = engine.Keep
)

// KeepAction constants.
const (
	KeepAll           = engine.KeepAll
	KeepNone          = engine.KeepNone
	KeepSample        = engine.KeepSample
	KeepRatePerSecond = engine.KeepRatePerSecond
	KeepRatePerMinute = engine.KeepRatePerMinute
)

// KeepAllAction returns a Keep that keeps all telemetry.
func KeepAllAction() Keep {
	return Keep{Action: KeepAll}
}

// KeepNoneAction returns a Keep that drops all telemetry.
func KeepNoneAction() Keep {
	return Keep{Action: KeepNone}
}

// KeepSampleAction returns a Keep that samples at the given percentage.
func KeepSampleAction(percentage float64) Keep {
	return Keep{Action: KeepSample, Value: percentage}
}

// KeepRatePerSecondAction returns a Keep that rate limits per second.
func KeepRatePerSecondAction(rate float64) Keep {
	return Keep{Action: KeepRatePerSecond, Value: rate}
}

// KeepRatePerMinuteAction returns a Keep that rate limits per minute.
func KeepRatePerMinuteAction(rate float64) Keep {
	return Keep{Action: KeepRatePerMinute, Value: rate}
}
