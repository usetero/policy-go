package policy

import (
	"hash/fnv"

	"github.com/usetero/policy-go/internal/engine"
)

// maxThreshold is 2^56, the maximum value for the 56-bit threshold/randomness space
const maxThreshold uint64 = 1 << 56

// probabilisticSample determines if a record should be kept using OTel consistent
// probability sampling. It extracts 56-bit randomness from the input (treating it
// as a trace ID) and compares against the rejection threshold.
//
// This is used by both log sampling (when sample_key is configured) and trace
// sampling to ensure consistent keep/drop decisions for the same trace ID at the
// same percentage.
//
// Returns true if the record should be kept.
func probabilisticSample(input []byte, percentage float64) bool {
	if percentage >= 100 {
		return true
	}
	if percentage <= 0 {
		return false
	}

	randomness := extractRandomnessFromTraceID(input)
	threshold := calculateRejectionThreshold(percentage)
	return randomness >= threshold
}

// shouldSampleTrace determines if a span should be kept based on the sampling configuration.
// It implements consistent probability sampling per the OpenTelemetry specification:
// https://opentelemetry.io/docs/specs/otel/trace/tracestate-probability-sampling/
//
// The decision is: if R >= T, keep the span, else drop it.
// Where R is a 56-bit randomness value and T is the rejection threshold.
func shouldSampleTrace[T any](policy *engine.CompiledPolicy[engine.TraceField], span T, match TraceMatchFunc[T]) bool {
	percentage := policy.Keep.Value
	if percentage >= 100 {
		return true
	}
	if percentage <= 0 {
		return false
	}

	// Get the randomness value (R) - 56 bits
	// First try to get explicit randomness from tracestate rv sub-key
	// Fall back to least-significant 56 bits of trace ID
	randomness, ok := getTraceRandomness(span, match)
	if !ok {
		// If no randomness source is available, keep the span (fail open)
		return true
	}

	// Calculate rejection threshold (T) from percentage
	// T = (1 - percentage/100) * 2^56
	// Using integer math to avoid floating point precision issues
	threshold := calculateRejectionThreshold(percentage)

	// OTel consistent sampling decision: if R >= T, keep the span
	return randomness >= threshold
}

// shouldSampleLog determines if a log record should be kept based on the sampling configuration.
// When the sample key is the trace_id field, it uses OTel consistent probability sampling
// (same algorithm as trace sampling) for consistent keep/drop decisions across logs and traces.
// For other sample keys, it hashes the value first to produce well-distributed randomness.
func shouldSampleLog[T any](policy *engine.CompiledPolicy[engine.LogField], record T, match LogMatchFunc[T]) bool {
	percentage := policy.Keep.Value
	if percentage >= 100 {
		return true
	}
	if percentage <= 0 {
		return false
	}

	// Get the value to sample on
	var sampleInput []byte
	if policy.SampleKey != nil {
		sampleInput = match(record, *policy.SampleKey)
	}

	// If no sample key or the field is empty, we can't do consistent sampling
	// Fall back to not sampling (treat as keep all for this record)
	if len(sampleInput) == 0 {
		return true
	}

	// When sample key is trace_id, use the OTel algorithm directly so that
	// log and trace sampling produce identical decisions for the same trace ID.
	if policy.SampleKey != nil && !policy.SampleKey.IsAttribute() && policy.SampleKey.Field == engine.LogFieldTraceID {
		return probabilisticSample(sampleInput, percentage)
	}

	// For other sample keys, hash the value to get well-distributed 56-bit randomness,
	// then apply the OTel threshold comparison.
	return hashProbabilisticSample(sampleInput, percentage)
}

// hashProbabilisticSample hashes arbitrary input into 56-bit randomness and applies
// the OTel consistent probability threshold. Used for non-trace-ID sample keys.
func hashProbabilisticSample(input []byte, percentage float64) bool {
	h := fnv.New64a()
	h.Write(input)
	randomness := h.Sum64() & (maxThreshold - 1) // mask to 56 bits
	threshold := calculateRejectionThreshold(percentage)
	return randomness >= threshold
}

// getTraceRandomness extracts the 56-bit randomness value for sampling.
// It first checks for explicit randomness in tracestate (rv sub-key),
// then falls back to the least-significant 56 bits of the trace ID.
func getTraceRandomness[T any](span T, match TraceMatchFunc[T]) (uint64, bool) {
	// Try to get explicit randomness from tracestate first
	traceStateRef := engine.SpanTraceState()
	traceState := match(span, traceStateRef)
	if len(traceState) > 0 {
		if rv, ok := parseTracestateRandomness(traceState); ok {
			return rv, true
		}
	}

	// Fall back to trace ID
	traceIDRef := engine.SpanTraceID()
	traceID := match(span, traceIDRef)
	if len(traceID) == 0 {
		return 0, false
	}

	// Extract least-significant 56 bits from trace ID
	// Trace IDs are typically 16 bytes (128 bits), we want the last 7 bytes (56 bits)
	return extractRandomnessFromTraceID(traceID), true
}

// extractRandomnessFromTraceID extracts the least-significant 56 bits from a trace ID.
// Per OTel spec, this is the source of randomness when explicit rv is not present.
func extractRandomnessFromTraceID(traceID []byte) uint64 {
	// Handle both binary (16 bytes) and hex-encoded (32 bytes) trace IDs
	var raw []byte
	if len(traceID) == 32 {
		// Hex-encoded, decode the last 14 hex chars (7 bytes = 56 bits)
		raw = make([]byte, 7)
		hexDecode(raw, traceID[len(traceID)-14:])
	} else if len(traceID) >= 7 {
		// Binary format, take last 7 bytes
		raw = traceID[len(traceID)-7:]
	} else if len(traceID) > 0 {
		// Short trace ID, use what we have
		raw = traceID
	} else {
		return 0
	}

	// Convert to uint64 (big-endian)
	var result uint64
	for _, b := range raw {
		result = (result << 8) | uint64(b)
	}

	// Mask to 56 bits
	return result & (maxThreshold - 1)
}

// hexDecode decodes hex bytes into dst. Simple implementation for trace ID parsing.
func hexDecode(dst, src []byte) {
	for i := 0; i < len(dst) && i*2+1 < len(src); i++ {
		dst[i] = hexVal(src[i*2])<<4 | hexVal(src[i*2+1])
	}
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	default:
		return 0
	}
}

// parseTracestateRandomness extracts the rv (randomness) value from OTel tracestate.
// Format: "ot=...;rv:XXXXXXXXXXXXXX;..." where rv is exactly 14 hex digits.
func parseTracestateRandomness(traceState []byte) (uint64, bool) {
	// Look for "ot=" vendor entry
	otStart := findOTelEntry(traceState)
	if otStart < 0 {
		return 0, false
	}

	// Find rv sub-key within the ot entry
	// Format: rv:XXXXXXXXXXXXXX (14 hex digits)
	rvStart := findSubKey(traceState[otStart:], []byte("rv:"))
	if rvStart < 0 {
		return 0, false
	}

	rvStart += otStart + 3 // Skip "rv:"

	// Extract 14 hex digits
	if rvStart+14 > len(traceState) {
		return 0, false
	}

	rvHex := traceState[rvStart : rvStart+14]

	// Parse as 56-bit hex value
	var rv uint64
	for _, c := range rvHex {
		rv = (rv << 4) | uint64(hexVal(c))
	}

	return rv, true
}

// findOTelEntry finds the start of "ot=" in tracestate, returns index after "ot="
func findOTelEntry(traceState []byte) int {
	for i := 0; i <= len(traceState)-3; i++ {
		if traceState[i] == 'o' && traceState[i+1] == 't' && traceState[i+2] == '=' {
			return i + 3
		}
	}
	return -1
}

// findSubKey finds a sub-key like "rv:" within an OTel tracestate entry
func findSubKey(data, key []byte) int {
	for i := 0; i <= len(data)-len(key); i++ {
		// Check if we're at start or after a separator (semicolon)
		if i == 0 || data[i-1] == ';' {
			match := true
			for j := 0; j < len(key); j++ {
				if data[i+j] != key[j] {
					match = false
					break
				}
			}
			if match {
				return i
			}
		}
	}
	return -1
}

// calculateRejectionThreshold calculates the 56-bit rejection threshold from a percentage.
// Per OTel spec: T = (1 - percentage/100) * 2^56
func calculateRejectionThreshold(percentage float64) uint64 {
	if percentage >= 100 {
		return 0 // 0 threshold means keep everything (R >= 0 is always true)
	}
	if percentage <= 0 {
		return maxThreshold // Max threshold means drop everything
	}

	// T = (1 - p/100) * 2^56
	// Using float64 for the calculation, then convert to uint64
	rejectionProbability := 1.0 - (percentage / 100.0)
	threshold := uint64(rejectionProbability * float64(maxThreshold))

	return threshold
}
