package policy

import (
	"github.com/usetero/policy-go/policy/internal/engine"
	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
)

// VolumeSnapshot is an immutable copy of total observed telemetry volume.
type VolumeSnapshot = engine.VolumeSnapshot

// VolumeCollector returns the total telemetry volume observed since the last
// call, resetting the counters. Registered with providers so they can include it
// in sync requests.
type VolumeCollector func() VolumeSnapshot

// volumeProvider is implemented by providers that report observed volume in
// their sync requests. Optional interface rather than a PolicyProvider method
// so external provider implementations don't break.
type volumeProvider interface {
	SetVolumeCollector(collector VolumeCollector)
}

// AddLogBytes adds to the reported log byte volume. Records are counted
// automatically by EvaluateLog; bytes are optional and must be the uncompressed
// OTLP protobuf serialized size of the records as received (an estimate is
// fine). Leave it unreported rather than reporting another encoding's size.
func (r *PolicyRegistry) AddLogBytes(n int64) { r.volume.AddLogBytes(n) }

// AddMetricBytes adds to the reported metric byte volume. See AddLogBytes.
func (r *PolicyRegistry) AddMetricBytes(n int64) { r.volume.AddMetricBytes(n) }

// AddSpanBytes adds to the reported span byte volume. See AddLogBytes.
func (r *PolicyRegistry) AddSpanBytes(n int64) { r.volume.AddSpanBytes(n) }

// CollectVolume atomically reads and resets the volume counters, returning the
// delta since the last call. This is the VolumeCollector implementation
// registered with providers.
func (r *PolicyRegistry) CollectVolume() VolumeSnapshot { return r.volume.Snapshot() }

// collectVolume drains the collector into a proto message for the sync request.
// The counters reset on read whether or not the sync succeeds, matching
// collectPolicyStatuses: a failed sync drops its interval from the numerator and
// the denominator alike, and replaying it would double count.
//
// A nil collector or an all-zero snapshot returns nil, since the spec says an
// implementation that doesn't track volume should omit the message rather than
// send a zero-valued one.
func collectVolume(collector VolumeCollector) *policyv1.VolumeStats {
	if collector == nil {
		return nil
	}
	s := collector()
	if s.IsZero() {
		return nil
	}
	return &policyv1.VolumeStats{
		LogRecords:       s.LogRecords,
		LogBytes:         s.LogBytes,
		MetricDataPoints: s.MetricDataPoints,
		MetricBytes:      s.MetricBytes,
		Spans:            s.Spans,
		SpanBytes:        s.SpanBytes,
	}
}
