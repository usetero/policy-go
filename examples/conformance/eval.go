package main

import (
	"encoding/hex"
	"strings"

	"github.com/usetero/policy-go/policy"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

// ─── Context types ───────────────────────────────────────────────────

type LogContext struct {
	Record            plog.LogRecord
	Resource          pcommon.Resource
	Scope             pcommon.InstrumentationScope
	ResourceSchemaURL string
	ScopeSchemaURL    string
}

type MetricContext struct {
	Metric              pmetric.Metric
	DatapointAttributes pcommon.Map
	Resource            pcommon.Resource
	Scope               pcommon.InstrumentationScope
	ResourceSchemaURL   string
	ScopeSchemaURL      string
}

type TraceContext struct {
	Span              ptrace.Span
	Resource          pcommon.Resource
	Scope             pcommon.InstrumentationScope
	ResourceSchemaURL string
	ScopeSchemaURL    string
}

// ─── Attribute helpers ───────────────────────────────────────────────

func findAttributePath(attrs pcommon.Map, path []string) []byte {
	if len(path) == 0 {
		return nil
	}
	v, ok := attrs.Get(path[0])
	if !ok {
		return nil
	}
	if len(path) == 1 {
		return valueBytes(v)
	}
	if v.Type() == pcommon.ValueTypeMap {
		return findAttributePath(v.Map(), path[1:])
	}
	return nil
}

func existsAttributePath(attrs pcommon.Map, path []string) bool {
	if len(path) == 0 {
		return false
	}
	v, ok := attrs.Get(path[0])
	if !ok {
		return false
	}
	if len(path) == 1 {
		return true
	}
	if v.Type() == pcommon.ValueTypeMap {
		return existsAttributePath(v.Map(), path[1:])
	}
	return false
}

func valueBytes(v pcommon.Value) []byte {
	if v.Type() != pcommon.ValueTypeStr {
		return nil
	}
	s := v.Str()
	if s == "" {
		return nil
	}
	return []byte(s)
}

func findAttributeValue(attrs pcommon.Map, path []string) (pcommon.Value, bool) {
	if len(path) == 0 {
		return pcommon.Value{}, false
	}
	v, ok := attrs.Get(path[0])
	if !ok {
		return pcommon.Value{}, false
	}
	if len(path) == 1 {
		return v, true
	}
	if v.Type() == pcommon.ValueTypeMap {
		return findAttributeValue(v.Map(), path[1:])
	}
	return pcommon.Value{}, false
}

func typedValueOf(v pcommon.Value) policy.TypedValue {
	switch v.Type() {
	case pcommon.ValueTypeStr:
		return policy.TypedValueOfString(v.Str())
	case pcommon.ValueTypeBool:
		return policy.TypedValueOfBool(v.Bool())
	case pcommon.ValueTypeInt:
		return policy.TypedValueOfInt(v.Int())
	case pcommon.ValueTypeDouble:
		return policy.TypedValueOfDouble(v.Double())
	case pcommon.ValueTypeBytes:
		return policy.TypedValueOfBytes(v.Bytes().AsRaw())
	default:
		return policy.TypedValue{}
	}
}

func attrPath(ref policy.LogFieldRef) string {
	if len(ref.AttrPath) > 0 {
		return ref.AttrPath[0]
	}
	return ""
}

// ─── Log accessor primitives ─────────────────────────────────────────

func logValue(ctx *LogContext, ref policy.LogFieldRef) []byte {
	if ref.IsField() {
		switch ref.Field {
		case policy.LogFieldBody:
			return valueBytes(ctx.Record.Body())
		case policy.LogFieldSeverityText:
			if ctx.Record.SeverityText() == "" {
				return nil
			}
			return []byte(ctx.Record.SeverityText())
		case policy.LogFieldTraceID:
			id := ctx.Record.TraceID()
			if id.IsEmpty() {
				return nil
			}
			return []byte(hex.EncodeToString(id[:]))
		case policy.LogFieldSpanID:
			id := ctx.Record.SpanID()
			if id.IsEmpty() {
				return nil
			}
			return []byte(hex.EncodeToString(id[:]))
		case policy.LogFieldEventName:
			if ctx.Record.EventName() == "" {
				return nil
			}
			return []byte(ctx.Record.EventName())
		case policy.LogFieldResourceSchemaURL:
			if ctx.ResourceSchemaURL == "" {
				return nil
			}
			return []byte(ctx.ResourceSchemaURL)
		case policy.LogFieldScopeSchemaURL:
			if ctx.ScopeSchemaURL == "" {
				return nil
			}
			return []byte(ctx.ScopeSchemaURL)
		default:
			return nil
		}
	}

	attrs, ok := logAttrs(ctx, ref)
	if !ok {
		return nil
	}
	return findAttributePath(attrs, ref.AttrPath)
}

func logExists(ctx *LogContext, ref policy.LogFieldRef) bool {
	if ref.IsField() {
		switch ref.Field {
		case policy.LogFieldBody:
			body := ctx.Record.Body()
			switch body.Type() {
			case pcommon.ValueTypeEmpty:
				return false
			case pcommon.ValueTypeStr:
				return body.Str() != ""
			default:
				return true
			}
		case policy.LogFieldSeverityText:
			return ctx.Record.SeverityText() != ""
		case policy.LogFieldTraceID:
			return !ctx.Record.TraceID().IsEmpty()
		case policy.LogFieldSpanID:
			return !ctx.Record.SpanID().IsEmpty()
		case policy.LogFieldEventName:
			return ctx.Record.EventName() != ""
		case policy.LogFieldResourceSchemaURL:
			return ctx.ResourceSchemaURL != ""
		case policy.LogFieldScopeSchemaURL:
			return ctx.ScopeSchemaURL != ""
		default:
			return false
		}
	}

	attrs, ok := logAttrs(ctx, ref)
	if !ok {
		return false
	}
	return existsAttributePath(attrs, ref.AttrPath)
}

func logTypedValue(ctx *LogContext, ref policy.LogFieldRef) policy.TypedValue {
	if ref.IsField() {
		switch ref.Field {
		case policy.LogFieldBody:
			return typedValueOf(ctx.Record.Body())
		case policy.LogFieldSeverityText:
			if ctx.Record.SeverityText() == "" {
				return policy.TypedValue{}
			}
			return policy.TypedValueOfString(ctx.Record.SeverityText())
		case policy.LogFieldTraceID:
			id := ctx.Record.TraceID()
			if id.IsEmpty() {
				return policy.TypedValue{}
			}
			return policy.TypedValueOfBytes(id[:])
		case policy.LogFieldSpanID:
			id := ctx.Record.SpanID()
			if id.IsEmpty() {
				return policy.TypedValue{}
			}
			return policy.TypedValueOfBytes(id[:])
		case policy.LogFieldEventName:
			if ctx.Record.EventName() == "" {
				return policy.TypedValue{}
			}
			return policy.TypedValueOfString(ctx.Record.EventName())
		case policy.LogFieldResourceSchemaURL:
			if ctx.ResourceSchemaURL == "" {
				return policy.TypedValue{}
			}
			return policy.TypedValueOfString(ctx.ResourceSchemaURL)
		case policy.LogFieldScopeSchemaURL:
			if ctx.ScopeSchemaURL == "" {
				return policy.TypedValue{}
			}
			return policy.TypedValueOfString(ctx.ScopeSchemaURL)
		default:
			return policy.TypedValue{}
		}
	}

	attrs, ok := logAttrs(ctx, ref)
	if !ok {
		return policy.TypedValue{}
	}
	v, ok := findAttributeValue(attrs, ref.AttrPath)
	if !ok {
		return policy.TypedValue{}
	}
	return typedValueOf(v)
}

func logSet(ctx *LogContext, ref policy.LogFieldRef, value string) {
	if ref.IsField() {
		switch ref.Field {
		case policy.LogFieldBody:
			ctx.Record.Body().SetStr(value)
		case policy.LogFieldSeverityText:
			ctx.Record.SetSeverityText(value)
		case policy.LogFieldTraceID:
			ctx.Record.SetTraceID(traceIDFromString(value))
		case policy.LogFieldSpanID:
			ctx.Record.SetSpanID(spanIDFromString(value))
		case policy.LogFieldEventName:
			ctx.Record.SetEventName(value)
		}
		return
	}
	attrs, ok := logAttrs(ctx, ref)
	if !ok {
		return
	}
	key := attrPath(ref)
	if key == "" {
		return
	}
	attrs.PutStr(key, value)
}

func logDelete(ctx *LogContext, ref policy.LogFieldRef) bool {
	if ref.IsField() {
		switch ref.Field {
		case policy.LogFieldBody:
			hit := ctx.Record.Body().Type() != pcommon.ValueTypeEmpty
			ctx.Record.Body().SetStr("")
			return hit
		case policy.LogFieldSeverityText:
			hit := ctx.Record.SeverityText() != ""
			ctx.Record.SetSeverityText("")
			return hit
		case policy.LogFieldTraceID:
			hit := !ctx.Record.TraceID().IsEmpty()
			ctx.Record.SetTraceID(pcommon.NewTraceIDEmpty())
			return hit
		case policy.LogFieldSpanID:
			hit := !ctx.Record.SpanID().IsEmpty()
			ctx.Record.SetSpanID(pcommon.NewSpanIDEmpty())
			return hit
		case policy.LogFieldEventName:
			hit := ctx.Record.EventName() != ""
			ctx.Record.SetEventName("")
			return hit
		}
		return false
	}
	attrs, ok := logAttrs(ctx, ref)
	if !ok {
		return false
	}
	key := attrPath(ref)
	if key == "" {
		return false
	}
	if _, ok := attrs.Get(key); !ok {
		return false
	}
	attrs.RemoveIf(func(k string, _ pcommon.Value) bool {
		return k == key
	})
	return true
}

func logMove(ctx *LogContext, from, to policy.LogFieldRef) {
	attrs, ok := logAttrs(ctx, from)
	if !ok {
		return
	}
	fromKey := attrPath(from)
	toKey := attrPath(to)
	if fromKey == "" || toKey == "" {
		return
	}
	src, ok := attrs.Get(fromKey)
	if !ok {
		return
	}
	dst := attrs.PutEmpty(toKey)
	src.CopyTo(dst)
	attrs.RemoveIf(func(k string, _ pcommon.Value) bool {
		return k == fromKey
	})
}

func logAttrs(ctx *LogContext, ref policy.LogFieldRef) (pcommon.Map, bool) {
	switch {
	case ref.IsRecordAttr():
		return ctx.Record.Attributes(), true
	case ref.IsResourceAttr():
		return ctx.Resource.Attributes(), true
	case ref.IsScopeAttr():
		return ctx.Scope.Attributes(), true
	}
	return pcommon.Map{}, false
}

// ─── Metric accessor primitives ──────────────────────────────────────

func metricValue(ctx *MetricContext, ref policy.MetricFieldRef) []byte {
	if ref.IsField() {
		switch ref.Field {
		case policy.MetricFieldName:
			if ctx.Metric.Name() == "" {
				return nil
			}
			return []byte(ctx.Metric.Name())
		case policy.MetricFieldDescription:
			if ctx.Metric.Description() == "" {
				return nil
			}
			return []byte(ctx.Metric.Description())
		case policy.MetricFieldUnit:
			if ctx.Metric.Unit() == "" {
				return nil
			}
			return []byte(ctx.Metric.Unit())
		case policy.MetricFieldType:
			return []byte(metricType(ctx.Metric))
		case policy.MetricFieldAggregationTemporality:
			return []byte(aggregationTemporality(ctx.Metric))
		case policy.MetricFieldScopeName:
			if ctx.Scope.Name() == "" {
				return nil
			}
			return []byte(ctx.Scope.Name())
		case policy.MetricFieldScopeVersion:
			if ctx.Scope.Version() == "" {
				return nil
			}
			return []byte(ctx.Scope.Version())
		case policy.MetricFieldResourceSchemaURL:
			if ctx.ResourceSchemaURL == "" {
				return nil
			}
			return []byte(ctx.ResourceSchemaURL)
		case policy.MetricFieldScopeSchemaURL:
			if ctx.ScopeSchemaURL == "" {
				return nil
			}
			return []byte(ctx.ScopeSchemaURL)
		default:
			return nil
		}
	}

	attrs, ok := metricAttrs(ctx, ref)
	if !ok {
		return nil
	}
	return findAttributePath(attrs, ref.AttrPath)
}

func metricExists(ctx *MetricContext, ref policy.MetricFieldRef) bool {
	if ref.IsField() {
		switch ref.Field {
		case policy.MetricFieldName:
			return ctx.Metric.Name() != ""
		case policy.MetricFieldDescription:
			return ctx.Metric.Description() != ""
		case policy.MetricFieldUnit:
			return ctx.Metric.Unit() != ""
		case policy.MetricFieldType:
			return metricType(ctx.Metric) != ""
		case policy.MetricFieldAggregationTemporality:
			return aggregationTemporality(ctx.Metric) != ""
		case policy.MetricFieldScopeName:
			return ctx.Scope.Name() != ""
		case policy.MetricFieldScopeVersion:
			return ctx.Scope.Version() != ""
		case policy.MetricFieldResourceSchemaURL:
			return ctx.ResourceSchemaURL != ""
		case policy.MetricFieldScopeSchemaURL:
			return ctx.ScopeSchemaURL != ""
		default:
			return false
		}
	}

	attrs, ok := metricAttrs(ctx, ref)
	if !ok {
		return false
	}
	return existsAttributePath(attrs, ref.AttrPath)
}

func metricTypedValue(ctx *MetricContext, ref policy.MetricFieldRef) policy.TypedValue {
	if ref.IsField() {
		b := metricValue(ctx, ref)
		if b == nil {
			return policy.TypedValue{}
		}
		return policy.TypedValueOfString(string(b))
	}
	attrs, ok := metricAttrs(ctx, ref)
	if !ok {
		return policy.TypedValue{}
	}
	v, ok := findAttributeValue(attrs, ref.AttrPath)
	if !ok {
		return policy.TypedValue{}
	}
	return typedValueOf(v)
}

func metricAttrs(ctx *MetricContext, ref policy.MetricFieldRef) (pcommon.Map, bool) {
	switch {
	case ref.IsRecordAttr():
		return ctx.DatapointAttributes, true
	case ref.IsResourceAttr():
		return ctx.Resource.Attributes(), true
	case ref.IsScopeAttr():
		return ctx.Scope.Attributes(), true
	}
	return pcommon.Map{}, false
}

func metricType(m pmetric.Metric) string {
	switch m.Type() {
	case pmetric.MetricTypeGauge:
		return "gauge"
	case pmetric.MetricTypeSum:
		return "sum"
	case pmetric.MetricTypeHistogram:
		return "histogram"
	case pmetric.MetricTypeExponentialHistogram:
		return "exponential_histogram"
	case pmetric.MetricTypeSummary:
		return "summary"
	default:
		return ""
	}
}

func aggregationTemporality(m pmetric.Metric) string {
	switch m.Type() {
	case pmetric.MetricTypeSum:
		return temporalityString(m.Sum().AggregationTemporality())
	case pmetric.MetricTypeHistogram:
		return temporalityString(m.Histogram().AggregationTemporality())
	case pmetric.MetricTypeExponentialHistogram:
		return temporalityString(m.ExponentialHistogram().AggregationTemporality())
	default:
		return ""
	}
}

func temporalityString(t pmetric.AggregationTemporality) string {
	switch t {
	case pmetric.AggregationTemporalityDelta:
		return "delta"
	case pmetric.AggregationTemporalityCumulative:
		return "cumulative"
	default:
		return ""
	}
}

// ─── Trace accessor primitives ───────────────────────────────────────

func traceValue(ctx *TraceContext, ref policy.TraceFieldRef) []byte {
	if ref.IsField() {
		switch ref.Field {
		case policy.TraceFieldName:
			if ctx.Span.Name() == "" {
				return nil
			}
			return []byte(ctx.Span.Name())
		case policy.TraceFieldTraceID:
			id := ctx.Span.TraceID()
			if id.IsEmpty() {
				return nil
			}
			return []byte(hex.EncodeToString(id[:]))
		case policy.TraceFieldSpanID:
			id := ctx.Span.SpanID()
			if id.IsEmpty() {
				return nil
			}
			return []byte(hex.EncodeToString(id[:]))
		case policy.TraceFieldParentSpanID:
			id := ctx.Span.ParentSpanID()
			if id.IsEmpty() {
				return nil
			}
			return []byte(hex.EncodeToString(id[:]))
		case policy.TraceFieldTraceState:
			ts := ctx.Span.TraceState().AsRaw()
			if ts == "" {
				return nil
			}
			return []byte(ts)
		case policy.TraceFieldKind:
			return []byte(spanKindString(ctx.Span.Kind()))
		case policy.TraceFieldStatus:
			return []byte(statusCodeString(ctx.Span.Status().Code()))
		case policy.TraceFieldEventName:
			for i := 0; i < ctx.Span.Events().Len(); i++ {
				name := ctx.Span.Events().At(i).Name()
				if name != "" {
					return []byte(name)
				}
			}
			return nil
		case policy.TraceFieldScopeName:
			if ctx.Scope.Name() == "" {
				return nil
			}
			return []byte(ctx.Scope.Name())
		case policy.TraceFieldScopeVersion:
			if ctx.Scope.Version() == "" {
				return nil
			}
			return []byte(ctx.Scope.Version())
		case policy.TraceFieldResourceSchemaURL:
			if ctx.ResourceSchemaURL == "" {
				return nil
			}
			return []byte(ctx.ResourceSchemaURL)
		case policy.TraceFieldScopeSchemaURL:
			if ctx.ScopeSchemaURL == "" {
				return nil
			}
			return []byte(ctx.ScopeSchemaURL)
		default:
			return nil
		}
	}

	attrs, ok := traceAttrs(ctx, ref)
	if !ok {
		return nil
	}
	return findAttributePath(attrs, ref.AttrPath)
}

func traceExists(ctx *TraceContext, ref policy.TraceFieldRef) bool {
	if ref.IsField() {
		switch ref.Field {
		case policy.TraceFieldName:
			return ctx.Span.Name() != ""
		case policy.TraceFieldTraceID:
			return !ctx.Span.TraceID().IsEmpty()
		case policy.TraceFieldSpanID:
			return !ctx.Span.SpanID().IsEmpty()
		case policy.TraceFieldParentSpanID:
			return !ctx.Span.ParentSpanID().IsEmpty()
		case policy.TraceFieldTraceState:
			return ctx.Span.TraceState().AsRaw() != ""
		case policy.TraceFieldKind:
			return ctx.Span.Kind() != ptrace.SpanKindUnspecified
		case policy.TraceFieldStatus:
			return true
		case policy.TraceFieldEventName:
			for i := 0; i < ctx.Span.Events().Len(); i++ {
				if ctx.Span.Events().At(i).Name() != "" {
					return true
				}
			}
			return false
		case policy.TraceFieldScopeName:
			return ctx.Scope.Name() != ""
		case policy.TraceFieldScopeVersion:
			return ctx.Scope.Version() != ""
		case policy.TraceFieldResourceSchemaURL:
			return ctx.ResourceSchemaURL != ""
		case policy.TraceFieldScopeSchemaURL:
			return ctx.ScopeSchemaURL != ""
		default:
			return false
		}
	}

	attrs, ok := traceAttrs(ctx, ref)
	if !ok {
		return false
	}
	return existsAttributePath(attrs, ref.AttrPath)
}

func traceTypedValue(ctx *TraceContext, ref policy.TraceFieldRef) policy.TypedValue {
	if ref.IsField() {
		switch ref.Field {
		case policy.TraceFieldTraceID:
			id := ctx.Span.TraceID()
			if id.IsEmpty() {
				return policy.TypedValue{}
			}
			return policy.TypedValueOfBytes(id[:])
		case policy.TraceFieldSpanID:
			id := ctx.Span.SpanID()
			if id.IsEmpty() {
				return policy.TypedValue{}
			}
			return policy.TypedValueOfBytes(id[:])
		case policy.TraceFieldParentSpanID:
			id := ctx.Span.ParentSpanID()
			if id.IsEmpty() {
				return policy.TypedValue{}
			}
			return policy.TypedValueOfBytes(id[:])
		default:
			b := traceValue(ctx, ref)
			if b == nil {
				return policy.TypedValue{}
			}
			return policy.TypedValueOfString(string(b))
		}
	}
	attrs, ok := traceAttrs(ctx, ref)
	if !ok {
		return policy.TypedValue{}
	}
	v, ok := findAttributeValue(attrs, ref.AttrPath)
	if !ok {
		return policy.TypedValue{}
	}
	return typedValueOf(v)
}

func traceSet(ctx *TraceContext, ref policy.TraceFieldRef, value string) {
	if ref.Field == policy.SpanSamplingThreshold().Field {
		ctx.Span.TraceState().FromRaw(mergeOTTracestate(ctx.Span.TraceState().AsRaw(), "th:"+value))
	}
}

func traceAttrs(ctx *TraceContext, ref policy.TraceFieldRef) (pcommon.Map, bool) {
	switch {
	case ref.IsRecordAttr():
		return ctx.Span.Attributes(), true
	case ref.IsResourceAttr():
		return ctx.Resource.Attributes(), true
	case ref.IsScopeAttr():
		return ctx.Scope.Attributes(), true
	}
	return pcommon.Map{}, false
}

func spanKindString(k ptrace.SpanKind) string {
	switch k {
	case ptrace.SpanKindInternal:
		return "internal"
	case ptrace.SpanKindServer:
		return "server"
	case ptrace.SpanKindClient:
		return "client"
	case ptrace.SpanKindProducer:
		return "producer"
	case ptrace.SpanKindConsumer:
		return "consumer"
	default:
		return ""
	}
}

func statusCodeString(c ptrace.StatusCode) string {
	switch c {
	case ptrace.StatusCodeOk:
		return "ok"
	case ptrace.StatusCodeError:
		return "error"
	case ptrace.StatusCodeUnset:
		return "unset"
	default:
		return ""
	}
}

// ─── Accessor option sets ────────────────────────────────────────────

var (
	LogOpts = []policy.LogOption[*LogContext]{
		policy.WithLogValue(logValue),
		policy.WithLogExists(logExists),
		policy.WithLogTypedValue(logTypedValue),
		policy.WithLogSet(logSet),
		policy.WithLogDelete(logDelete),
		policy.WithLogMove(logMove),
	}

	MetricOpts = []policy.MetricOption[*MetricContext]{
		policy.WithMetricValue(metricValue),
		policy.WithMetricExists(metricExists),
		policy.WithMetricTypedValue(metricTypedValue),
	}

	TraceOpts = []policy.TraceOption[*TraceContext]{
		policy.WithTraceValue(traceValue),
		policy.WithTraceExists(traceExists),
		policy.WithTraceTypedValue(traceTypedValue),
		policy.WithTraceSet(traceSet),
	}
)

// ─── Tracestate merge ────────────────────────────────────────────────

func mergeOTTracestate(tracestate, subkv string) string {
	subKey := subkv
	if idx := strings.Index(subkv, ":"); idx >= 0 {
		subKey = subkv[:idx]
	}

	var otParts []string
	var otherVendors []string

	if tracestate != "" {
		for _, vendor := range strings.Split(tracestate, ",") {
			vendor = strings.TrimSpace(vendor)
			if vendor == "" {
				continue
			}
			if strings.HasPrefix(vendor, "ot=") {
				otValue := vendor[3:]
				for _, part := range strings.Split(otValue, ";") {
					part = strings.TrimSpace(part)
					if part == "" {
						continue
					}
					partKey := part
					if idx := strings.Index(part, ":"); idx >= 0 {
						partKey = part[:idx]
					}
					if partKey != subKey {
						otParts = append(otParts, part)
					}
				}
			} else {
				otherVendors = append(otherVendors, vendor)
			}
		}
	}

	otParts = append(otParts, subkv)
	result := "ot=" + strings.Join(otParts, ";")
	if len(otherVendors) > 0 {
		result += "," + strings.Join(otherVendors, ",")
	}
	return result
}

// ─── Datapoint attribute helpers ─────────────────────────────────────

func getDatapointAttrs(m pmetric.Metric) pcommon.Map {
	switch m.Type() {
	case pmetric.MetricTypeGauge:
		if m.Gauge().DataPoints().Len() > 0 {
			return m.Gauge().DataPoints().At(0).Attributes()
		}
	case pmetric.MetricTypeSum:
		if m.Sum().DataPoints().Len() > 0 {
			return m.Sum().DataPoints().At(0).Attributes()
		}
	case pmetric.MetricTypeHistogram:
		if m.Histogram().DataPoints().Len() > 0 {
			return m.Histogram().DataPoints().At(0).Attributes()
		}
	case pmetric.MetricTypeExponentialHistogram:
		if m.ExponentialHistogram().DataPoints().Len() > 0 {
			return m.ExponentialHistogram().DataPoints().At(0).Attributes()
		}
	case pmetric.MetricTypeSummary:
		if m.Summary().DataPoints().Len() > 0 {
			return m.Summary().DataPoints().At(0).Attributes()
		}
	}
	return pcommon.NewMap()
}

// ─── ID conversion helpers ──────────────────────────────────────────

func traceIDFromString(s string) pcommon.TraceID {
	var id pcommon.TraceID
	b, err := hex.DecodeString(s)
	if err == nil && len(b) == 16 {
		copy(id[:], b)
	}
	return id
}

func spanIDFromString(s string) pcommon.SpanID {
	var id pcommon.SpanID
	b, err := hex.DecodeString(s)
	if err == nil && len(b) == 8 {
		copy(id[:], b)
	}
	return id
}
