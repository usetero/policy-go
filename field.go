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

// LogField constants.
const (
	LogFieldUnspecified       = policyv1.LogField_LOG_FIELD_UNSPECIFIED
	LogFieldBody              = policyv1.LogField_LOG_FIELD_BODY
	LogFieldSeverityText      = policyv1.LogField_LOG_FIELD_SEVERITY_TEXT
	LogFieldTraceID           = policyv1.LogField_LOG_FIELD_TRACE_ID
	LogFieldSpanID            = policyv1.LogField_LOG_FIELD_SPAN_ID
	LogFieldEventName         = policyv1.LogField_LOG_FIELD_EVENT_NAME
	LogFieldResourceSchemaURL = policyv1.LogField_LOG_FIELD_RESOURCE_SCHEMA_URL
	LogFieldScopeSchemaURL    = policyv1.LogField_LOG_FIELD_SCOPE_SCHEMA_URL
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
