package policy

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// simpleLogTransform is a tiny shim that exercises ApplyLogTransform against
// the reference SimpleLog* accessor functions. Tests use it to verify the
// engine's transform orchestration end-to-end without going through
// EvaluateLog.
func simpleLogTransform(r *SimpleLogRecord, op TransformOp) bool {
	return ApplyLogTransform(r, op, SimpleLogOptions()...)
}

// ============================================================================
// Matchers — field/attribute extraction
// ============================================================================

func TestSimpleMetricGetValue(t *testing.T) {
	record := &SimpleMetricRecord{
		Name:                   []byte("http.request.duration"),
		Description:            []byte("Duration of HTTP requests"),
		Unit:                   []byte("ms"),
		Type:                   []byte("histogram"),
		AggregationTemporality: []byte("cumulative"),
		DatapointAttributes:    map[string]any{"http.method": "GET"},
		ResourceAttributes:     map[string]any{"service.name": "api-gateway"},
		ScopeAttributes:        map[string]any{"scope.version": "1.0.0"},
	}

	cases := []struct {
		name string
		ref  MetricFieldRef
		want []byte
	}{
		{"name", MetricFieldRef{Field: MetricFieldName}, []byte("http.request.duration")},
		{"description", MetricFieldRef{Field: MetricFieldDescription}, []byte("Duration of HTTP requests")},
		{"unit", MetricFieldRef{Field: MetricFieldUnit}, []byte("ms")},
		{"type", MetricFieldRef{Field: MetricFieldType}, []byte("histogram")},
		{"aggregation_temporality", MetricFieldRef{Field: MetricFieldAggregationTemporality}, []byte("cumulative")},
		{"unknown fixed field returns nil", MetricFieldRef{Field: MetricField(999)}, nil},
		{"datapoint attribute", DatapointAttr("http.method"), []byte("GET")},
		{"resource attribute", MetricResourceAttr("service.name"), []byte("api-gateway")},
		{"scope attribute", MetricScopeAttr("scope.version"), []byte("1.0.0")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, SimpleMetricGetValue(record, tc.ref))
		})
	}
}

func TestSimpleSpanGetValue(t *testing.T) {
	record := &SimpleSpanRecord{
		Name:         []byte("GET /api/users"),
		TraceID:      []byte("trace-abc123"),
		SpanID:       []byte("span-def456"),
		ParentSpanID: []byte("span-parent"),
		TraceState:   []byte("vendor=value"),
		Kind:         []byte("server"),
		Status:       []byte("ok"),
		EventNames:   [][]byte{[]byte("exception"), []byte("log")},
		EventAttributes: []map[string]any{
			{"exception.type": "NullPointerException"},
			{"log.message": "Request received"},
		},
		LinkTraceIDs:       [][]byte{[]byte("linked-trace-1"), []byte("linked-trace-2")},
		LinkAttributes:     []map[string]any{{"link.reason": "caused_by"}},
		SpanAttributes:     map[string]any{"http.method": "GET"},
		ResourceAttributes: map[string]any{"service.name": "user-service"},
		ScopeAttributes:    map[string]any{"scope.name": "http"},
	}

	cases := []struct {
		name string
		ref  TraceFieldRef
		want []byte
	}{
		{"name", TraceFieldRef{Field: TraceFieldName}, []byte("GET /api/users")},
		{"trace_id", TraceFieldRef{Field: TraceFieldTraceID}, []byte("trace-abc123")},
		{"span_id", TraceFieldRef{Field: TraceFieldSpanID}, []byte("span-def456")},
		{"parent_span_id", TraceFieldRef{Field: TraceFieldParentSpanID}, []byte("span-parent")},
		{"trace_state", TraceFieldRef{Field: TraceFieldTraceState}, []byte("vendor=value")},
		{"kind", TraceFieldRef{Field: TraceFieldKind}, []byte("server")},
		{"status", TraceFieldRef{Field: TraceFieldStatus}, []byte("ok")},
		{"event_name returns first event", TraceFieldRef{Field: TraceFieldEventName}, []byte("exception")},
		{"link_trace_id returns first link", TraceFieldRef{Field: TraceFieldLinkTraceID}, []byte("linked-trace-1")},
		{"unknown fixed field returns nil", TraceFieldRef{Field: TraceField(999)}, nil},
		{"span attribute", SpanAttr("http.method"), []byte("GET")},
		{"resource attribute", TraceResourceAttr("service.name"), []byte("user-service")},
		{"scope attribute", TraceScopeAttr("scope.name"), []byte("http")},
		{"event attribute (first event)", SpanEventAttr("exception.type"), []byte("NullPointerException")},
		{"link attribute (first link)", SpanLinkAttr("link.reason"), []byte("caused_by")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, SimpleSpanGetValue(record, tc.ref))
		})
	}
}

func TestSimpleSpanGetValueWithoutEventsOrLinks(t *testing.T) {
	record := &SimpleSpanRecord{Name: []byte("test span")}
	cases := []struct {
		name string
		ref  TraceFieldRef
	}{
		{"event name returns nil", TraceFieldRef{Field: TraceFieldEventName}},
		{"link trace id returns nil", TraceFieldRef{Field: TraceFieldLinkTraceID}},
		{"event attribute returns nil", SpanEventAttr("exception.type")},
		{"link attribute returns nil", SpanLinkAttr("link.reason")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Nil(t, SimpleSpanGetValue(record, tc.ref))
		})
	}
}

func TestTraversePath(t *testing.T) {
	nested := &SimpleLogRecord{
		LogAttributes: map[string]any{
			"http": map[string]any{
				"request": map[string]any{
					"headers": map[string]any{"content-type": "application/json"},
				},
			},
		},
	}
	byteAttr := &SimpleLogRecord{
		LogAttributes: map[string]any{"binary_data": []byte{0x01, 0x02, 0x03}},
	}
	flat := &SimpleLogRecord{LogAttributes: map[string]any{"key": "value"}}

	cases := []struct {
		name   string
		record *SimpleLogRecord
		ref    LogFieldRef
		want   []byte
	}{
		{"deeply nested path", nested, LogAttr("http", "request", "headers", "content-type"), []byte("application/json")},
		{"partial path (non-leaf) returns nil", nested, LogAttr("http", "request"), nil},
		{"missing nested path returns nil", nested, LogAttr("http", "response", "status"), nil},
		{"byte slice attribute returns the bytes", byteAttr, LogAttr("binary_data"), []byte{0x01, 0x02, 0x03}},
		{"empty path returns nil", flat, LogFieldRef{AttrScope: AttrScopeRecord, AttrPath: []string{}}, nil},
		{"nil scope map returns nil", &SimpleLogRecord{}, LogAttr("key"), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, SimpleLogGetValue(tc.record, tc.ref))
		})
	}
}

// ============================================================================
// ApplyLogTransform dispatch
// ============================================================================

func TestApplyLogTransformUnknownKind(t *testing.T) {
	record := &SimpleLogRecord{Body: []byte("x")}
	op := TransformOp{Kind: TransformKind(99)}
	assert.False(t, simpleLogTransform(record, op), "unknown kind must return false")
	assert.Equal(t, []byte("x"), record.Body, "record must not be mutated")
}

func TestApplyLogTransformDispatchesAllKinds(t *testing.T) {
	tests := []struct {
		name      string
		op        TransformOp
		setup     func(*SimpleLogRecord)
		wantHit   bool
		assertion func(*testing.T, *SimpleLogRecord)
	}{
		{
			name: "remove",
			setup: func(r *SimpleLogRecord) {
				r.LogAttributes = map[string]any{"k": "v"}
			},
			op:      TransformOp{Kind: TransformRemove, Ref: LogAttr("k")},
			wantHit: true,
			assertion: func(t *testing.T, r *SimpleLogRecord) {
				_, ok := r.LogAttributes["k"]
				assert.False(t, ok)
			},
		},
		{
			name: "redact",
			setup: func(r *SimpleLogRecord) {
				r.LogAttributes = map[string]any{"k": "v"}
			},
			op:      TransformOp{Kind: TransformRedact, Ref: LogAttr("k"), Value: "[X]"},
			wantHit: true,
			assertion: func(t *testing.T, r *SimpleLogRecord) {
				assert.Equal(t, "[X]", r.LogAttributes["k"])
			},
		},
		{
			name: "rename",
			setup: func(r *SimpleLogRecord) {
				r.LogAttributes = map[string]any{"old": "v"}
			},
			op:      TransformOp{Kind: TransformRename, Ref: LogAttr("old"), To: "new", Upsert: true},
			wantHit: true,
			assertion: func(t *testing.T, r *SimpleLogRecord) {
				_, oldOk := r.LogAttributes["old"]
				assert.False(t, oldOk)
				assert.Equal(t, "v", r.LogAttributes["new"])
			},
		},
		{
			name:    "add",
			setup:   func(r *SimpleLogRecord) {},
			op:      TransformOp{Kind: TransformAdd, Ref: LogAttr("k"), Value: "v", Upsert: true},
			wantHit: true,
			assertion: func(t *testing.T, r *SimpleLogRecord) {
				assert.Equal(t, "v", r.LogAttributes["k"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := &SimpleLogRecord{}
			tt.setup(record)
			got := simpleLogTransform(record, tt.op)
			assert.Equal(t, tt.wantHit, got)
			tt.assertion(t, record)
		})
	}
}

// ============================================================================
// simpleLogRemove
// ============================================================================

func TestSimpleLogRemoveFixedFields(t *testing.T) {
	fields := []struct {
		name string
		key  LogField
		read func(*SimpleLogRecord) []byte
		set  func(*SimpleLogRecord, []byte)
	}{
		{"body", LogFieldBody, func(r *SimpleLogRecord) []byte { return r.Body }, func(r *SimpleLogRecord, v []byte) { r.Body = v }},
		{"severity_text", LogFieldSeverityText, func(r *SimpleLogRecord) []byte { return r.SeverityText }, func(r *SimpleLogRecord, v []byte) { r.SeverityText = v }},
		{"trace_id", LogFieldTraceID, func(r *SimpleLogRecord) []byte { return r.TraceID }, func(r *SimpleLogRecord, v []byte) { r.TraceID = v }},
		{"span_id", LogFieldSpanID, func(r *SimpleLogRecord) []byte { return r.SpanID }, func(r *SimpleLogRecord, v []byte) { r.SpanID = v }},
		{"event_name", LogFieldEventName, func(r *SimpleLogRecord) []byte { return r.EventName }, func(r *SimpleLogRecord, v []byte) { r.EventName = v }},
	}

	for _, f := range fields {
		t.Run(f.name+"/present", func(t *testing.T) {
			r := &SimpleLogRecord{}
			f.set(r, []byte("x"))
			hit := simpleLogTransform(r, TransformOp{Kind: TransformRemove, Ref: LogFieldRef{Field: f.key}})
			assert.True(t, hit)
			assert.Nil(t, f.read(r))
		})
		t.Run(f.name+"/absent", func(t *testing.T) {
			r := &SimpleLogRecord{}
			hit := simpleLogTransform(r, TransformOp{Kind: TransformRemove, Ref: LogFieldRef{Field: f.key}})
			assert.False(t, hit, "removing an absent field must miss")
			assert.Nil(t, f.read(r))
		})
	}
}

func TestSimpleLogRemoveUnknownFixedField(t *testing.T) {
	r := &SimpleLogRecord{Body: []byte("x")}
	// LogFieldResourceSchemaURL has no fixed-field remove implementation.
	hit := simpleLogTransform(r, TransformOp{Kind: TransformRemove, Ref: LogFieldRef{Field: LogFieldResourceSchemaURL}})
	assert.False(t, hit)
	assert.Equal(t, []byte("x"), r.Body)
}

func TestSimpleLogRemoveAttributeScopes(t *testing.T) {
	cases := []struct {
		name string
		ref  LogFieldRef
		seed func() *SimpleLogRecord
		get  func(*SimpleLogRecord) map[string]any
	}{
		{
			name: "record",
			ref:  LogAttr("k"),
			seed: func() *SimpleLogRecord {
				return &SimpleLogRecord{LogAttributes: map[string]any{"k": "v"}}
			},
			get: func(r *SimpleLogRecord) map[string]any { return r.LogAttributes },
		},
		{
			name: "resource",
			ref:  LogResourceAttr("k"),
			seed: func() *SimpleLogRecord {
				return &SimpleLogRecord{ResourceAttributes: map[string]any{"k": "v"}}
			},
			get: func(r *SimpleLogRecord) map[string]any { return r.ResourceAttributes },
		},
		{
			name: "scope",
			ref:  LogScopeAttr("k"),
			seed: func() *SimpleLogRecord {
				return &SimpleLogRecord{ScopeAttributes: map[string]any{"k": "v"}}
			},
			get: func(r *SimpleLogRecord) map[string]any { return r.ScopeAttributes },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.seed()
			hit := simpleLogTransform(r, TransformOp{Kind: TransformRemove, Ref: tc.ref})
			assert.True(t, hit)
			_, ok := tc.get(r)["k"]
			assert.False(t, ok)
		})
	}
}

func TestSimpleLogRemoveAttributePathEdgeCases(t *testing.T) {
	cases := []struct {
		name    string
		seed    func() *SimpleLogRecord
		ref     LogFieldRef
		wantHit bool
		check   func(t *testing.T, r *SimpleLogRecord)
	}{
		{
			name: "missing attribute is a miss with siblings preserved",
			seed: func() *SimpleLogRecord {
				return &SimpleLogRecord{LogAttributes: map[string]any{"other": "v"}}
			},
			ref:     LogAttr("nope"),
			wantHit: false,
			check: func(t *testing.T, r *SimpleLogRecord) {
				assert.Equal(t, "v", r.LogAttributes["other"])
			},
		},
		{
			name:    "nil scope map is a miss",
			seed:    func() *SimpleLogRecord { return &SimpleLogRecord{} },
			ref:     LogResourceAttr("k"),
			wantHit: false,
			check: func(t *testing.T, r *SimpleLogRecord) {
				assert.Nil(t, r.ResourceAttributes)
			},
		},
		{
			name: "nested path removes leaf and preserves siblings",
			seed: func() *SimpleLogRecord {
				return &SimpleLogRecord{
					LogAttributes: map[string]any{
						"http": map[string]any{
							"request": map[string]any{
								"headers": map[string]any{
									"authorization": "Bearer abc",
									"content-type":  "json",
								},
							},
						},
					},
				}
			},
			ref:     LogAttr("http", "request", "headers", "authorization"),
			wantHit: true,
			check: func(t *testing.T, r *SimpleLogRecord) {
				headers := r.LogAttributes["http"].(map[string]any)["request"].(map[string]any)["headers"].(map[string]any)
				_, gone := headers["authorization"]
				assert.False(t, gone)
				assert.Equal(t, "json", headers["content-type"])
			},
		},
		{
			name: "non-map intermediate segment is a miss",
			seed: func() *SimpleLogRecord {
				return &SimpleLogRecord{LogAttributes: map[string]any{"http": "not a map"}}
			},
			ref:     LogAttr("http", "request"),
			wantHit: false,
			check: func(t *testing.T, r *SimpleLogRecord) {
				assert.Equal(t, "not a map", r.LogAttributes["http"])
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.seed()
			hit := simpleLogTransform(r, TransformOp{Kind: TransformRemove, Ref: tc.ref})
			assert.Equal(t, tc.wantHit, hit)
			tc.check(t, r)
		})
	}
}

// ============================================================================
// simpleLogRedact — whole value
// ============================================================================

func TestSimpleLogRedactFixedFields(t *testing.T) {
	fields := []struct {
		name string
		key  LogField
		read func(*SimpleLogRecord) []byte
		set  func(*SimpleLogRecord, []byte)
	}{
		{"body", LogFieldBody, func(r *SimpleLogRecord) []byte { return r.Body }, func(r *SimpleLogRecord, v []byte) { r.Body = v }},
		{"severity_text", LogFieldSeverityText, func(r *SimpleLogRecord) []byte { return r.SeverityText }, func(r *SimpleLogRecord, v []byte) { r.SeverityText = v }},
		{"trace_id", LogFieldTraceID, func(r *SimpleLogRecord) []byte { return r.TraceID }, func(r *SimpleLogRecord, v []byte) { r.TraceID = v }},
		{"span_id", LogFieldSpanID, func(r *SimpleLogRecord) []byte { return r.SpanID }, func(r *SimpleLogRecord, v []byte) { r.SpanID = v }},
		{"event_name", LogFieldEventName, func(r *SimpleLogRecord) []byte { return r.EventName }, func(r *SimpleLogRecord, v []byte) { r.EventName = v }},
	}

	for _, f := range fields {
		t.Run(f.name+"/present", func(t *testing.T) {
			r := &SimpleLogRecord{}
			f.set(r, []byte("secret"))
			hit := simpleLogTransform(r, TransformOp{
				Kind:  TransformRedact,
				Ref:   LogFieldRef{Field: f.key},
				Value: "[REDACTED]",
			})
			assert.True(t, hit)
			assert.Equal(t, []byte("[REDACTED]"), f.read(r))
		})
		t.Run(f.name+"/absent_is_noop", func(t *testing.T) {
			r := &SimpleLogRecord{}
			hit := simpleLogTransform(r, TransformOp{
				Kind:  TransformRedact,
				Ref:   LogFieldRef{Field: f.key},
				Value: "[REDACTED]",
			})
			assert.False(t, hit, "redacting an absent fixed field must miss per spec")
			assert.Nil(t, f.read(r), "value must remain nil (no-op)")
		})
	}
}

func TestSimpleLogRedactAttributeScopes(t *testing.T) {
	cases := []struct {
		name string
		ref  LogFieldRef
		seed func() *SimpleLogRecord
		get  func(*SimpleLogRecord) map[string]any
	}{
		{"record", LogAttr("k"), func() *SimpleLogRecord {
			return &SimpleLogRecord{LogAttributes: map[string]any{"k": "v"}}
		}, func(r *SimpleLogRecord) map[string]any { return r.LogAttributes }},
		{"resource", LogResourceAttr("k"), func() *SimpleLogRecord {
			return &SimpleLogRecord{ResourceAttributes: map[string]any{"k": "v"}}
		}, func(r *SimpleLogRecord) map[string]any { return r.ResourceAttributes }},
		{"scope", LogScopeAttr("k"), func() *SimpleLogRecord {
			return &SimpleLogRecord{ScopeAttributes: map[string]any{"k": "v"}}
		}, func(r *SimpleLogRecord) map[string]any { return r.ScopeAttributes }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.seed()
			hit := simpleLogTransform(r, TransformOp{
				Kind:  TransformRedact,
				Ref:   tc.ref,
				Value: "[REDACTED]",
			})
			assert.True(t, hit)
			assert.Equal(t, "[REDACTED]", tc.get(r)["k"])
		})
	}
}

func TestSimpleLogRedactEdgeCases(t *testing.T) {
	cases := []struct {
		name    string
		seed    func() *SimpleLogRecord
		ref     LogFieldRef
		wantHit bool
		check   func(t *testing.T, r *SimpleLogRecord)
	}{
		{
			name:    "unknown fixed field is a miss",
			seed:    func() *SimpleLogRecord { return &SimpleLogRecord{Body: []byte("x")} },
			ref:     LogFieldRef{Field: LogFieldResourceSchemaURL},
			wantHit: false,
			check: func(t *testing.T, r *SimpleLogRecord) {
				assert.Equal(t, []byte("x"), r.Body)
			},
		},
		{
			name: "missing attribute is a miss without creating it",
			seed: func() *SimpleLogRecord {
				return &SimpleLogRecord{LogAttributes: map[string]any{"other": "v"}}
			},
			ref:     LogAttr("nope"),
			wantHit: false,
			check: func(t *testing.T, r *SimpleLogRecord) {
				assert.Equal(t, "v", r.LogAttributes["other"])
				_, exists := r.LogAttributes["nope"]
				assert.False(t, exists)
			},
		},
		{
			name:    "nil scope map is a miss and not allocated",
			seed:    func() *SimpleLogRecord { return &SimpleLogRecord{} },
			ref:     LogResourceAttr("k"),
			wantHit: false,
			check: func(t *testing.T, r *SimpleLogRecord) {
				assert.Nil(t, r.ResourceAttributes)
			},
		},
		{
			name: "nested attribute redacted in place",
			seed: func() *SimpleLogRecord {
				return &SimpleLogRecord{
					LogAttributes: map[string]any{
						"http": map[string]any{
							"request": map[string]any{
								"headers": map[string]any{"authorization": "Bearer abc"},
							},
						},
					},
				}
			},
			ref:     LogAttr("http", "request", "headers", "authorization"),
			wantHit: true,
			check: func(t *testing.T, r *SimpleLogRecord) {
				headers := r.LogAttributes["http"].(map[string]any)["request"].(map[string]any)["headers"].(map[string]any)
				assert.Equal(t, "[REDACTED]", headers["authorization"])
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.seed()
			hit := simpleLogTransform(r, TransformOp{
				Kind:  TransformRedact,
				Ref:   tc.ref,
				Value: "[REDACTED]",
			})
			assert.Equal(t, tc.wantHit, hit)
			tc.check(t, r)
		})
	}
}

// ============================================================================
// simpleLogRedact — regex (targeted)
// ============================================================================

func mustCompile(t *testing.T, pattern string) *regexp.Regexp {
	t.Helper()
	re, err := regexp.Compile(pattern)
	require.NoError(t, err, "test regex must compile")
	return re
}

// TestSimpleLogRedactRegexAttribute exercises targeted regex redaction against
// a single record attribute. Each row seeds attribute "k" with `input` (unless
// `missing` is true), runs the redact, and asserts the hit flag plus the final
// attribute value.
func TestSimpleLogRedactRegexAttribute(t *testing.T) {
	cases := []struct {
		name        string
		input       any  // value seeded at attribute "k"; ignored when missing=true
		missing     bool // if true, do not seed any attribute
		regex       string
		replacement string
		wantHit     bool
		wantValue   any // expected final value at "k"; ignored when missing=true
	}{
		// --- hits: regex matches and replacement is applied ---
		{
			name:        "replaces all non-overlapping matches",
			input:       "from a@b.com to c@d.org via e@f.io",
			regex:       `\w+@\w+\.\w+`,
			replacement: "[email]",
			wantHit:     true,
			wantValue:   "from [email] to [email] via [email]",
		},
		{
			// Mirrors the policy-zig query-param example.
			name:        "numbered capture groups keep prefix and suffix",
			input:       "?user=alice&password=secret123&session=xyz",
			regex:       `([?&]password=)[^&\s]+(&session=)`,
			replacement: "$1[REDACTED]$2",
			wantHit:     true,
			wantValue:   "?user=alice&password=[REDACTED]&session=xyz",
		},
		{
			name:        "named capture group",
			input:       "Bearer abc123",
			regex:       `(?P<scheme>Bearer)\s+\S+`,
			replacement: "${scheme} [REDACTED]",
			wantHit:     true,
			wantValue:   "Bearer [REDACTED]",
		},
		{
			// $$ -> literal $, $0 -> full match.
			name:        "literal dollar via double-dollar escape",
			input:       "USD 100",
			regex:       `\d+`,
			replacement: "$$$0",
			wantHit:     true,
			wantValue:   "USD $100",
		},
		{
			// Spec: references to missing capture groups MUST expand to empty.
			name:        "missing capture group expands to empty",
			input:       "hello",
			regex:       `hello`,
			replacement: "X${nope}Y",
			wantHit:     true,
			wantValue:   "XY",
		},
		{
			// Spec note: "To replace an entire field value conditionally, use
			// an anchored regex that matches the full field value."
			name:        "anchored regex for conditional full-value replacement",
			input:       "4111-1111-1111-1111",
			regex:       `^\d{4}-\d{4}-\d{4}-\d{4}$`,
			replacement: "[CARD]",
			wantHit:     true,
			wantValue:   "[CARD]",
		},

		// --- misses: value must be untouched ---
		{
			name:        "no regex match is a miss",
			input:       "no secrets here",
			regex:       `password=\S+`,
			replacement: "X",
			wantHit:     false,
			wantValue:   "no secrets here",
		},
		{
			name:        "non-string int is a miss",
			input:       42,
			regex:       `.+`,
			replacement: "[X]",
			wantHit:     false,
			wantValue:   42,
		},
		{
			name:        "non-string bool is a miss",
			input:       true,
			regex:       `.+`,
			replacement: "[X]",
			wantHit:     false,
			wantValue:   true,
		},
		{
			name:        "non-string float is a miss",
			input:       3.14,
			regex:       `.+`,
			replacement: "[X]",
			wantHit:     false,
			wantValue:   3.14,
		},
		{
			// []byte attributes are treated as textual values like strings —
			// regex-redact applies to them.
			name:        "byte slice attribute is redacted in place",
			input:       []byte("4111-1111-1111-1111"),
			regex:       `\d{4}-\d{4}-\d{4}-\d{4}`,
			replacement: "[CARD]",
			wantHit:     true,
			wantValue:   "[CARD]",
		},
		{
			name:        "non-string nested map is a miss",
			input:       map[string]any{"x": "y"},
			regex:       `.+`,
			replacement: "[X]",
			wantHit:     false,
			wantValue:   map[string]any{"x": "y"},
		},
		{
			name:        "missing attribute is a miss without creating it",
			missing:     true,
			regex:       `\d+`,
			replacement: "X",
			wantHit:     false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &SimpleLogRecord{LogAttributes: map[string]any{}}
			if !tc.missing {
				r.LogAttributes["k"] = tc.input
			}

			hit := simpleLogTransform(r, TransformOp{
				Kind:  TransformRedact,
				Ref:   LogAttr("k"),
				Value: tc.replacement,
				Regex: mustCompile(t, tc.regex),
			})

			assert.Equal(t, tc.wantHit, hit)
			if tc.missing {
				_, exists := r.LogAttributes["k"]
				assert.False(t, exists, "missing attribute must NOT be created by a miss")
				return
			}
			assert.Equal(t, tc.wantValue, r.LogAttributes["k"])
		})
	}
}

// TestSimpleLogRedactRegexFixedField exercises targeted regex redaction against
// the Body fixed field. Each row seeds Body with `body` (nil = absent), runs
// the redact, and asserts the hit flag plus the final byte slice.
func TestSimpleLogRedactRegexFixedField(t *testing.T) {
	cases := []struct {
		name        string
		body        []byte // nil = Body is absent
		regex       string
		replacement string
		wantHit     bool
		wantBody    []byte
	}{
		{
			name:        "multi-match replaces every occurrence",
			body:        []byte("user=alice password=hunter2 host=x password=other"),
			regex:       `password=\S+`,
			replacement: "password=[REDACTED]",
			wantHit:     true,
			wantBody:    []byte("user=alice password=[REDACTED] host=x password=[REDACTED]"),
		},
		{
			name:        "nil body is a miss",
			body:        nil,
			regex:       `.+`,
			replacement: "[X]",
			wantHit:     false,
			wantBody:    nil,
		},
		{
			name:        "no match leaves body untouched",
			body:        []byte("nothing interesting"),
			regex:       `\d{16}`,
			replacement: "[X]",
			wantHit:     false,
			wantBody:    []byte("nothing interesting"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &SimpleLogRecord{Body: tc.body}
			hit := simpleLogTransform(r, TransformOp{
				Kind:  TransformRedact,
				Ref:   LogFieldRef{Field: LogFieldBody},
				Value: tc.replacement,
				Regex: mustCompile(t, tc.regex),
			})
			assert.Equal(t, tc.wantHit, hit)
			assert.Equal(t, tc.wantBody, r.Body)
		})
	}
}

// ============================================================================
// simpleLogRename
// ============================================================================

func TestSimpleLogRename(t *testing.T) {
	cases := []struct {
		name    string
		seed    func() *SimpleLogRecord
		ref     LogFieldRef
		to      string
		upsert  bool
		wantHit bool
		check   func(t *testing.T, r *SimpleLogRecord)
	}{
		{
			name: "renames existing attribute (upsert=true)",
			seed: func() *SimpleLogRecord {
				return &SimpleLogRecord{LogAttributes: map[string]any{"old_name": "value123"}}
			},
			ref: LogAttr("old_name"), to: "new_name", upsert: true, wantHit: true,
			check: func(t *testing.T, r *SimpleLogRecord) {
				_, oldOk := r.LogAttributes["old_name"]
				assert.False(t, oldOk, "source must be removed")
				assert.Equal(t, "value123", r.LogAttributes["new_name"])
			},
		},
		{
			name: "missing source is a miss; target not created",
			seed: func() *SimpleLogRecord {
				return &SimpleLogRecord{LogAttributes: map[string]any{}}
			},
			ref: LogAttr("nope"), to: "new_name", upsert: true, wantHit: false,
			check: func(t *testing.T, r *SimpleLogRecord) {
				_, exists := r.LogAttributes["new_name"]
				assert.False(t, exists)
			},
		},
		{
			// upsert=false + target exists: source remains, target unchanged,
			// but op is still a "hit" (source did exist).
			name: "upsert=false with existing target is a hit but source preserved",
			seed: func() *SimpleLogRecord {
				return &SimpleLogRecord{
					LogAttributes: map[string]any{"old": "src", "new": "preexisting"},
				}
			},
			ref: LogAttr("old"), to: "new", upsert: false, wantHit: true,
			check: func(t *testing.T, r *SimpleLogRecord) {
				assert.Equal(t, "src", r.LogAttributes["old"], "source preserved when target blocks rename")
				assert.Equal(t, "preexisting", r.LogAttributes["new"], "target unchanged")
			},
		},
		{
			name: "upsert=true overwrites existing target",
			seed: func() *SimpleLogRecord {
				return &SimpleLogRecord{
					LogAttributes: map[string]any{"old": "src", "new": "preexisting"},
				}
			},
			ref: LogAttr("old"), to: "new", upsert: true, wantHit: true,
			check: func(t *testing.T, r *SimpleLogRecord) {
				_, oldOk := r.LogAttributes["old"]
				assert.False(t, oldOk)
				assert.Equal(t, "src", r.LogAttributes["new"])
			},
		},
		{
			name: "renaming a fixed field is unsupported (miss)",
			seed: func() *SimpleLogRecord {
				return &SimpleLogRecord{Body: []byte("x")}
			},
			ref: LogFieldRef{Field: LogFieldBody}, to: "new", upsert: true, wantHit: false,
			check: func(t *testing.T, r *SimpleLogRecord) {
				assert.Equal(t, []byte("x"), r.Body)
			},
		},
		{
			name: "renames resource-scope attribute",
			seed: func() *SimpleLogRecord {
				return &SimpleLogRecord{ResourceAttributes: map[string]any{"old": "rv"}}
			},
			ref: LogResourceAttr("old"), to: "new", upsert: true, wantHit: true,
			check: func(t *testing.T, r *SimpleLogRecord) {
				_, oldOk := r.ResourceAttributes["old"]
				assert.False(t, oldOk)
				assert.Equal(t, "rv", r.ResourceAttributes["new"])
			},
		},
		{
			name: "renames scope-scope attribute",
			seed: func() *SimpleLogRecord {
				return &SimpleLogRecord{ScopeAttributes: map[string]any{"old": "sv"}}
			},
			ref: LogScopeAttr("old"), to: "new", upsert: true, wantHit: true,
			check: func(t *testing.T, r *SimpleLogRecord) {
				_, oldOk := r.ScopeAttributes["old"]
				assert.False(t, oldOk)
				assert.Equal(t, "sv", r.ScopeAttributes["new"])
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.seed()
			hit := simpleLogTransform(r, TransformOp{
				Kind:   TransformRename,
				Ref:    tc.ref,
				To:     tc.to,
				Upsert: tc.upsert,
			})
			assert.Equal(t, tc.wantHit, hit)
			tc.check(t, r)
		})
	}
}

// ============================================================================
// simpleLogAdd
// ============================================================================

func TestSimpleLogAddFixedFieldsNewValue(t *testing.T) {
	fields := []struct {
		name string
		key  LogField
		read func(*SimpleLogRecord) []byte
	}{
		{"body", LogFieldBody, func(r *SimpleLogRecord) []byte { return r.Body }},
		{"severity_text", LogFieldSeverityText, func(r *SimpleLogRecord) []byte { return r.SeverityText }},
		{"trace_id", LogFieldTraceID, func(r *SimpleLogRecord) []byte { return r.TraceID }},
		{"span_id", LogFieldSpanID, func(r *SimpleLogRecord) []byte { return r.SpanID }},
		{"event_name", LogFieldEventName, func(r *SimpleLogRecord) []byte { return r.EventName }},
	}
	for _, f := range fields {
		t.Run(f.name, func(t *testing.T) {
			r := &SimpleLogRecord{}
			hit := simpleLogTransform(r, TransformOp{
				Kind:   TransformAdd,
				Ref:    LogFieldRef{Field: f.key},
				Value:  "v",
				Upsert: false,
			})
			assert.True(t, hit)
			assert.Equal(t, []byte("v"), f.read(r))
		})
	}
}

func TestSimpleLogAddUpsertAndAutoCreate(t *testing.T) {
	cases := []struct {
		name    string
		seed    func() *SimpleLogRecord
		ref     LogFieldRef
		value   string
		upsert  bool
		wantHit bool
		check   func(t *testing.T, r *SimpleLogRecord)
	}{
		{
			name: "fixed field upsert=false on existing is hit without overwrite",
			seed: func() *SimpleLogRecord { return &SimpleLogRecord{Body: []byte("original")} },
			ref:  LogFieldRef{Field: LogFieldBody}, value: "should_not_overwrite", upsert: false, wantHit: true,
			check: func(t *testing.T, r *SimpleLogRecord) {
				assert.Equal(t, []byte("original"), r.Body, "value must not be overwritten")
			},
		},
		{
			name: "fixed field upsert=true overwrites existing",
			seed: func() *SimpleLogRecord { return &SimpleLogRecord{Body: []byte("original")} },
			ref:  LogFieldRef{Field: LogFieldBody}, value: "new", upsert: true, wantHit: true,
			check: func(t *testing.T, r *SimpleLogRecord) {
				assert.Equal(t, []byte("new"), r.Body)
			},
		},
		{
			name: "attribute on nil scope map auto-creates the map",
			seed: func() *SimpleLogRecord { return &SimpleLogRecord{} },
			ref:  LogAttr("k"), value: "v", upsert: false, wantHit: true,
			check: func(t *testing.T, r *SimpleLogRecord) {
				require.NotNil(t, r.LogAttributes, "ensureAttrs must allocate the scope map")
				assert.Equal(t, "v", r.LogAttributes["k"])
			},
		},
		{
			name: "attribute upsert=false on existing is hit without overwrite",
			seed: func() *SimpleLogRecord {
				return &SimpleLogRecord{LogAttributes: map[string]any{"k": "original"}}
			},
			ref: LogAttr("k"), value: "new", upsert: false, wantHit: true,
			check: func(t *testing.T, r *SimpleLogRecord) {
				assert.Equal(t, "original", r.LogAttributes["k"], "value must not be overwritten")
			},
		},
		{
			name: "attribute upsert=true overwrites existing",
			seed: func() *SimpleLogRecord {
				return &SimpleLogRecord{LogAttributes: map[string]any{"k": "original"}}
			},
			ref: LogAttr("k"), value: "new", upsert: true, wantHit: true,
			check: func(t *testing.T, r *SimpleLogRecord) {
				assert.Equal(t, "new", r.LogAttributes["k"])
			},
		},
		{
			name: "resource attribute auto-creates resource map",
			seed: func() *SimpleLogRecord { return &SimpleLogRecord{} },
			ref:  LogResourceAttr("k"), value: "rv", upsert: false, wantHit: true,
			check: func(t *testing.T, r *SimpleLogRecord) {
				require.NotNil(t, r.ResourceAttributes)
				assert.Equal(t, "rv", r.ResourceAttributes["k"])
			},
		},
		{
			name: "scope attribute auto-creates scope map",
			seed: func() *SimpleLogRecord { return &SimpleLogRecord{} },
			ref:  LogScopeAttr("k"), value: "sv", upsert: false, wantHit: true,
			check: func(t *testing.T, r *SimpleLogRecord) {
				require.NotNil(t, r.ScopeAttributes)
				assert.Equal(t, "sv", r.ScopeAttributes["k"])
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.seed()
			hit := simpleLogTransform(r, TransformOp{
				Kind:   TransformAdd,
				Ref:    tc.ref,
				Value:  tc.value,
				Upsert: tc.upsert,
			})
			assert.Equal(t, tc.wantHit, hit)
			tc.check(t, r)
		})
	}
}

// ============================================================================
// Map helpers — setPath / getPath / deletePath
// ============================================================================

func TestSetPath(t *testing.T) {
	cases := []struct {
		name  string
		m     map[string]any
		path  []string
		value string
		check func(t *testing.T, m map[string]any)
	}{
		{
			name:  "empty path is a no-op",
			m:     map[string]any{"k": "v"},
			path:  nil,
			value: "x",
			check: func(t *testing.T, m map[string]any) {
				assert.Equal(t, "v", m["k"])
				assert.Len(t, m, 1)
			},
		},
		{
			name:  "nil map does not panic",
			m:     nil,
			path:  []string{"k"},
			value: "x",
			check: func(t *testing.T, m map[string]any) {
				assert.Nil(t, m)
			},
		},
		{
			name:  "creates intermediate maps",
			m:     map[string]any{},
			path:  []string{"a", "b", "c"},
			value: "v",
			check: func(t *testing.T, m map[string]any) {
				a, ok := m["a"].(map[string]any)
				require.True(t, ok)
				b, ok := a["b"].(map[string]any)
				require.True(t, ok)
				assert.Equal(t, "v", b["c"])
			},
		},
		{
			// setPath replaces a non-map at an intermediate segment with a
			// fresh nested map rather than preserving the original.
			name:  "replaces non-map intermediate",
			m:     map[string]any{"a": "string-not-map"},
			path:  []string{"a", "b"},
			value: "v",
			check: func(t *testing.T, m map[string]any) {
				a, ok := m["a"].(map[string]any)
				require.True(t, ok)
				assert.Equal(t, "v", a["b"])
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setPath(tc.m, tc.path, tc.value)
			tc.check(t, tc.m)
		})
	}
}

func TestGetPath(t *testing.T) {
	cases := []struct {
		name    string
		m       map[string]any
		path    []string
		wantVal any
		wantOk  bool
	}{
		{
			name:    "basic nested lookup",
			m:       map[string]any{"a": map[string]any{"b": "v"}},
			path:    []string{"a", "b"},
			wantVal: "v", wantOk: true,
		},
		{
			name: "empty path returns not-ok",
			m:    map[string]any{"k": "v"},
			path: nil,
		},
		{
			name: "nil map returns not-ok",
			m:    nil, path: []string{"k"},
		},
		{
			name: "missing key returns not-ok",
			m:    map[string]any{"a": "v"}, path: []string{"b"},
		},
		{
			name: "non-map intermediate returns not-ok",
			m:    map[string]any{"a": "not a map"}, path: []string{"a", "b"},
		},
		{
			// getPath preserves the underlying type — unlike traversePath,
			// which coerces to []byte and drops non-string values.
			name:    "non-string value preserved (unlike traversePath)",
			m:       map[string]any{"k": 42},
			path:    []string{"k"},
			wantVal: 42, wantOk: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			val, ok := getPath(tc.m, tc.path)
			assert.Equal(t, tc.wantOk, ok)
			assert.Equal(t, tc.wantVal, val)
		})
	}
}

func TestDeletePath(t *testing.T) {
	cases := []struct {
		name  string
		m     map[string]any
		path  []string
		check func(t *testing.T, m map[string]any)
	}{
		{
			name: "nil map does not panic",
			m:    nil, path: []string{"k"},
			check: func(t *testing.T, m map[string]any) {
				assert.Nil(t, m)
			},
		},
		{
			name: "empty path leaves map untouched",
			m:    map[string]any{"k": "v"}, path: nil,
			check: func(t *testing.T, m map[string]any) {
				assert.Equal(t, "v", m["k"])
				assert.Len(t, m, 1)
			},
		},
		{
			name: "nested leaf deleted; sibling preserved",
			m: map[string]any{
				"a": map[string]any{
					"b": map[string]any{
						"c": "v",
						"d": "w",
					},
				},
			},
			path: []string{"a", "b", "c"},
			check: func(t *testing.T, m map[string]any) {
				b := m["a"].(map[string]any)["b"].(map[string]any)
				_, gone := b["c"]
				assert.False(t, gone)
				assert.Equal(t, "w", b["d"], "sibling preserved")
			},
		},
		{
			name: "non-map intermediate is a no-op",
			m:    map[string]any{"a": "not a map"}, path: []string{"a", "b"},
			check: func(t *testing.T, m map[string]any) {
				assert.Equal(t, "not a map", m["a"])
			},
		},
		{
			name: "missing key is a no-op",
			m:    map[string]any{"a": "v"}, path: []string{"b"},
			check: func(t *testing.T, m map[string]any) {
				assert.Equal(t, "v", m["a"])
				assert.Len(t, m, 1)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deletePath(tc.m, tc.path)
			tc.check(t, tc.m)
		})
	}
}
