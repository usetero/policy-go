package engine

import "sync/atomic"

// VolumeStats counts all telemetry entering policy evaluation, regardless of
// whether any policy matched it. Counting happens before the keep and transform
// stages, so dropped, sampled-out and redacted records are all included.
//
// Byte counts are optional and are only populated by consumers that call
// AddLogBytes/AddMetricBytes/AddSpanBytes; a zero byte count means "not
// tracked" as much as it means "none seen".
type VolumeStats struct {
	logRecords       atomic.Int64
	logBytes         atomic.Int64
	metricDataPoints atomic.Int64
	metricBytes      atomic.Int64
	spans            atomic.Int64
	spanBytes        atomic.Int64
}

// VolumeSnapshot is an immutable copy of volume counters for reporting.
type VolumeSnapshot struct {
	LogRecords       int64
	LogBytes         int64
	MetricDataPoints int64
	MetricBytes      int64
	Spans            int64
	SpanBytes        int64
}

// IsZero reports whether every counter is zero, so callers can omit the
// message entirely rather than send a zero-valued one.
func (s VolumeSnapshot) IsZero() bool {
	return s == VolumeSnapshot{}
}

func (v *VolumeStats) RecordLog()             { v.logRecords.Add(1) }
func (v *VolumeStats) RecordMetric()          { v.metricDataPoints.Add(1) }
func (v *VolumeStats) RecordSpan()            { v.spans.Add(1) }
func (v *VolumeStats) AddLogBytes(n int64)    { v.logBytes.Add(n) }
func (v *VolumeStats) AddMetricBytes(n int64) { v.metricBytes.Add(n) }
func (v *VolumeStats) AddSpanBytes(n int64)   { v.spanBytes.Add(n) }

// Snapshot atomically reads and resets all counters, returning the delta since
// the last call. Reset-on-read is the spec's rule: a delta read into a sync that
// then fails is lost rather than replayed, so reported volume is a lower bound.
func (v *VolumeStats) Snapshot() VolumeSnapshot {
	return VolumeSnapshot{
		LogRecords:       v.logRecords.Swap(0),
		LogBytes:         v.logBytes.Swap(0),
		MetricDataPoints: v.metricDataPoints.Swap(0),
		MetricBytes:      v.metricBytes.Swap(0),
		Spans:            v.spans.Swap(0),
		SpanBytes:        v.spanBytes.Swap(0),
	}
}
