package policy

import (
	"github.com/usetero/policy-go/internal/engine"
	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
)

// Re-export proto types for convenience.
type (
	// Policy is the proto policy type.
	Policy = policyv1.Policy
	// LogTarget is the proto log target type.
	LogTarget = policyv1.LogTarget
	// LogMatcher is the proto log matcher type.
	LogMatcher = policyv1.LogMatcher
)

// Re-export engine types.
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

// ParseKeep parses a keep string into a Keep struct.
var ParseKeep = engine.ParseKeep
