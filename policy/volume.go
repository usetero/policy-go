package policy

import (
	"github.com/usetero/policy-go/policy/internal/engine"
	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
)

// VolumeSnapshot is an immutable copy of total observed telemetry volume.
type VolumeSnapshot = engine.VolumeSnapshot

// VolumeReporter is the seam between the registry's counters and a provider's
// sync requests: the provider drains the counters into each request and returns
// them if the sync fails. *PolicyRegistry implements it.
type VolumeReporter interface {
	// CollectVolume returns the volume observed since the last call, resetting
	// the counters.
	CollectVolume() VolumeSnapshot
	// AddVolume folds a snapshot back into the counters.
	AddVolume(VolumeSnapshot)
}

// volumeProvider is implemented by providers that report observed volume in
// their sync requests. Optional interface rather than a PolicyProvider method
// so external provider implementations don't break.
type volumeProvider interface {
	SetVolumeReporter(reporter VolumeReporter)
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
// delta since the last call.
func (r *PolicyRegistry) CollectVolume() VolumeSnapshot { return r.volume.Snapshot() }

// AddVolume folds a snapshot back into the volume counters, so a delta taken by
// CollectVolume for a sync that then failed is reported by the next one.
func (r *PolicyRegistry) AddVolume(s VolumeSnapshot) { r.volume.Add(s) }

// volumeToProto converts a snapshot for the sync request. An all-zero snapshot
// returns nil: the spec says implementations that don't track volume should
// omit the message rather than send a zero-valued one.
func volumeToProto(s VolumeSnapshot) *policyv1.VolumeStats {
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
