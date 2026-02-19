package policy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
)

func TestContentType_String(t *testing.T) {
	tests := []struct {
		name        string
		contentType ContentType
		want        string
	}{
		{
			name:        "protobuf",
			contentType: ContentTypeProtobuf,
			want:        "application/x-protobuf",
		},
		{
			name:        "json",
			contentType: ContentTypeJSON,
			want:        "application/json",
		},
		{
			name:        "default (unknown) returns protobuf",
			contentType: ContentType(99),
			want:        "application/x-protobuf",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.contentType.String())
		})
	}
}

func TestNewHttpProvider(t *testing.T) {
	tests := []struct {
		name             string
		url              string
		opts             []HttpProviderOption
		wantURL          string
		wantPollInterval time.Duration
		wantContentType  ContentType
		wantHeaders      map[string]string
	}{
		{
			name:             "default configuration",
			url:              "http://example.com/sync",
			opts:             nil,
			wantURL:          "http://example.com/sync",
			wantPollInterval: 60 * time.Second,
			wantContentType:  ContentTypeProtobuf,
			wantHeaders:      nil,
		},
		{
			name: "with custom poll interval",
			url:  "http://example.com/sync",
			opts: []HttpProviderOption{
				WithHTTPPollInterval(30 * time.Second),
			},
			wantURL:          "http://example.com/sync",
			wantPollInterval: 30 * time.Second,
			wantContentType:  ContentTypeProtobuf,
		},
		{
			name: "with JSON content type",
			url:  "http://example.com/sync",
			opts: []HttpProviderOption{
				WithContentType(ContentTypeJSON),
			},
			wantURL:          "http://example.com/sync",
			wantPollInterval: 60 * time.Second,
			wantContentType:  ContentTypeJSON,
		},
		{
			name: "with headers",
			url:  "http://example.com/sync",
			opts: []HttpProviderOption{
				WithHeaders(map[string]string{
					"Authorization": "Bearer token",
					"X-Custom":      "value",
				}),
			},
			wantURL:          "http://example.com/sync",
			wantPollInterval: 60 * time.Second,
			wantContentType:  ContentTypeProtobuf,
			wantHeaders: map[string]string{
				"Authorization": "Bearer token",
				"X-Custom":      "value",
			},
		},
		{
			name: "with multiple options",
			url:  "http://example.com/sync",
			opts: []HttpProviderOption{
				WithHTTPPollInterval(10 * time.Second),
				WithContentType(ContentTypeJSON),
				WithHeaders(map[string]string{"X-Test": "test"}),
			},
			wantURL:          "http://example.com/sync",
			wantPollInterval: 10 * time.Second,
			wantContentType:  ContentTypeJSON,
			wantHeaders:      map[string]string{"X-Test": "test"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewHttpProvider(tt.url, tt.opts...)

			assert.Equal(t, tt.wantURL, p.config.URL)
			assert.Equal(t, tt.wantPollInterval, p.config.PollInterval)
			assert.Equal(t, tt.wantContentType, p.config.ContentType)
			if tt.wantHeaders != nil {
				for k, v := range tt.wantHeaders {
					assert.Equal(t, v, p.config.Headers[k], "Header %s mismatch", k)
				}
			}
			assert.NotNil(t, p.client)
		})
	}
}

func TestNewHttpProvider_WithCustomClient(t *testing.T) {
	customClient := &http.Client{Timeout: 5 * time.Second}
	p := NewHttpProvider("http://example.com", WithHTTPClient(customClient))

	assert.Equal(t, customClient, p.client)
}

func TestNewHttpProvider_WithServiceMetadata(t *testing.T) {
	metadata := &ServiceMetadata{
		ServiceName:       "test-service",
		ServiceNamespace:  "test-namespace",
		ServiceInstanceID: "instance-1",
		ServiceVersion:    "1.0.0",
		SupportedStages:   []policyv1.PolicyStage{policyv1.PolicyStage_POLICY_STAGE_LOG_FILTER},
		Labels:            map[string]string{"env": "test"},
	}

	p := NewHttpProvider("http://example.com", WithServiceMetadata(metadata))

	assert.Equal(t, metadata, p.config.ServiceMetadata)
}

func TestNewHttpProvider_WithCallbacks(t *testing.T) {
	var errorCalled, syncCalled bool

	p := NewHttpProvider("http://example.com",
		WithHTTPOnError(func(err error) { errorCalled = true }),
		WithHTTPOnSync(func() { syncCalled = true }),
	)

	require.NotNil(t, p.config.OnError)
	require.NotNil(t, p.config.OnSync)

	// Verify callbacks are callable
	p.config.OnError(nil)
	p.config.OnSync()

	assert.True(t, errorCalled, "OnError callback was not invoked")
	assert.True(t, syncCalled, "OnSync callback was not invoked")
}

func TestHttpProvider_SetStatsCollector(t *testing.T) {
	p := NewHttpProvider("http://example.com")

	assert.Nil(t, p.statsCollector, "statsCollector should be nil initially")

	collector := func() []PolicyStatsSnapshot {
		return []PolicyStatsSnapshot{
			{PolicyID: "policy-1", MatchHits: 10, MatchMisses: 5},
		}
	}

	p.SetStatsCollector(collector)

	require.NotNil(t, p.statsCollector)

	// Verify the collector returns expected data
	snapshots := p.statsCollector()
	require.Len(t, snapshots, 1)
	assert.Equal(t, "policy-1", snapshots[0].PolicyID)
}

func TestHttpProvider_Load_Protobuf(t *testing.T) {
	expectedPolicies := []*policyv1.Policy{
		{Id: "policy-1", Name: "Test Policy 1", Enabled: true},
		{Id: "policy-2", Name: "Test Policy 2", Enabled: false},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/x-protobuf", r.Header.Get("Content-Type"))
		assert.Equal(t, "application/x-protobuf", r.Header.Get("Accept"))

		// Parse request
		body, _ := io.ReadAll(r.Body)
		var req policyv1.SyncRequest
		require.NoError(t, proto.Unmarshal(body, &req))
		assert.True(t, req.FullSync)

		// Send response
		resp := &policyv1.SyncResponse{
			Policies:              expectedPolicies,
			Hash:                  "hash123",
			SyncTimestampUnixNano: 1234567890,
		}
		respBytes, _ := proto.Marshal(resp)
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.Write(respBytes)
	}))
	defer server.Close()

	p := NewHttpProvider(server.URL)
	policies, err := p.Load()

	require.NoError(t, err)
	require.Len(t, policies, 2)
	assert.Equal(t, "policy-1", policies[0].Id)

	// Verify state was updated
	assert.Equal(t, "hash123", p.lastHash)
	assert.Equal(t, uint64(1234567890), p.lastSyncTimestamp)
}

func TestHttpProvider_Load_JSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		// Parse JSON request using protojson
		body, _ := io.ReadAll(r.Body)
		var req policyv1.SyncRequest
		require.NoError(t, protojson.Unmarshal(body, &req))
		assert.True(t, req.GetFullSync())

		// Send JSON response using protojson (spec-compliant proto3 JSON)
		resp := &policyv1.SyncResponse{
			Policies: []*policyv1.Policy{
				{Id: "json-policy", Name: "JSON Policy"},
			},
			Hash: "json-hash",
		}
		respBytes, err := protojson.Marshal(resp)
		require.NoError(t, err)
		w.Header().Set("Content-Type", "application/json")
		w.Write(respBytes)
	}))
	defer server.Close()

	p := NewHttpProvider(server.URL, WithContentType(ContentTypeJSON))
	policies, err := p.Load()

	require.NoError(t, err)
	require.Len(t, policies, 1)
	assert.Equal(t, "json-policy", policies[0].GetId())
}

func TestHttpProvider_Load_JSON_StringUint64(t *testing.T) {
	// Proto3 JSON spec requires uint64/int64 to be encoded as strings.
	// A spec-compliant server (using protojson.Marshal) emits string values.
	// encoding/json would reject these; protojson handles them correctly.
	ts := uint64(1771277811889719000)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := &policyv1.SyncResponse{
			Policies: []*policyv1.Policy{
				{
					Id:                 "p1",
					Name:               "test",
					CreatedAtUnixNano:  ts,
					ModifiedAtUnixNano: ts,
				},
			},
			Hash:                  "hash-1",
			SyncTimestampUnixNano: ts,
		}
		respBytes, err := protojson.Marshal(resp)
		require.NoError(t, err)

		// Verify the server output actually contains string-encoded uint64s
		assert.Contains(t, string(respBytes), fmt.Sprintf("%q", fmt.Sprint(ts)))

		w.Header().Set("Content-Type", "application/json")
		w.Write(respBytes)
	}))
	defer server.Close()

	p := NewHttpProvider(server.URL, WithContentType(ContentTypeJSON))
	policies, err := p.Load()

	require.NoError(t, err)
	require.Len(t, policies, 1)
	assert.Equal(t, ts, policies[0].GetCreatedAtUnixNano())
	assert.Equal(t, ts, policies[0].GetModifiedAtUnixNano())
	assert.Equal(t, ts, p.lastSyncTimestamp)
}

func TestHttpProvider_Load_JSON_RawStringUint64(t *testing.T) {
	// Test with hand-crafted JSON where uint64 fields are JSON strings,
	// exactly as a spec-compliant proto3 server would emit.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := `{
			"policies": [{"id": "p1", "name": "test"}],
			"hash": "abc",
			"syncTimestampUnixNano": "1771277811889719000"
		}`
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(raw))
	}))
	defer server.Close()

	p := NewHttpProvider(server.URL, WithContentType(ContentTypeJSON))
	policies, err := p.Load()

	require.NoError(t, err)
	require.Len(t, policies, 1)
	assert.Equal(t, uint64(1771277811889719000), p.lastSyncTimestamp)
}

func TestHttpProvider_Load_JSON_OneofLogTarget(t *testing.T) {
	// Oneof fields require protojson to decode correctly.
	// encoding/json cannot populate proto oneof interfaces.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := &policyv1.SyncResponse{
			Policies: []*policyv1.Policy{
				{
					Id:      "log-policy",
					Name:    "Log Filter",
					Enabled: true,
					Target: &policyv1.Policy_Log{
						Log: &policyv1.LogTarget{
							Keep: "all",
							Match: []*policyv1.LogMatcher{
								{
									Field: &policyv1.LogMatcher_LogField{
										LogField: policyv1.LogField_LOG_FIELD_SEVERITY_TEXT,
									},
									Match: &policyv1.LogMatcher_Exact{
										Exact: "ERROR",
									},
								},
							},
						},
					},
				},
			},
			Hash: "log-hash",
		}
		respBytes, err := protojson.Marshal(resp)
		require.NoError(t, err)
		w.Header().Set("Content-Type", "application/json")
		w.Write(respBytes)
	}))
	defer server.Close()

	p := NewHttpProvider(server.URL, WithContentType(ContentTypeJSON))
	policies, err := p.Load()

	require.NoError(t, err)
	require.Len(t, policies, 1)

	policy := policies[0]
	assert.Equal(t, "log-policy", policy.GetId())
	assert.True(t, policy.GetEnabled())

	// Verify oneof target was decoded
	logTarget := policy.GetLog()
	require.NotNil(t, logTarget, "log oneof target should be populated")
	assert.Equal(t, "all", logTarget.GetKeep())
	require.Len(t, logTarget.GetMatch(), 1)

	matcher := logTarget.GetMatch()[0]
	assert.Equal(t, policyv1.LogField_LOG_FIELD_SEVERITY_TEXT, matcher.GetLogField())
	assert.Equal(t, "ERROR", matcher.GetExact())
}

func TestHttpProvider_Load_JSON_OneofTraceTarget(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := &policyv1.SyncResponse{
			Policies: []*policyv1.Policy{
				{
					Id:      "trace-policy",
					Name:    "Trace Sampler",
					Enabled: true,
					Target: &policyv1.Policy_Trace{
						Trace: &policyv1.TraceTarget{
							Keep: &policyv1.TraceSamplingConfig{
								Percentage: 50.0,
							},
							Match: []*policyv1.TraceMatcher{
								{
									Field: &policyv1.TraceMatcher_TraceField{
										TraceField: policyv1.TraceField_TRACE_FIELD_NAME,
									},
									Match: &policyv1.TraceMatcher_StartsWith{
										StartsWith: "GET /api",
									},
								},
							},
						},
					},
				},
			},
			Hash: "trace-hash",
		}
		respBytes, err := protojson.Marshal(resp)
		require.NoError(t, err)
		w.Header().Set("Content-Type", "application/json")
		w.Write(respBytes)
	}))
	defer server.Close()

	p := NewHttpProvider(server.URL, WithContentType(ContentTypeJSON))
	policies, err := p.Load()

	require.NoError(t, err)
	require.Len(t, policies, 1)

	policy := policies[0]
	traceTarget := policy.GetTrace()
	require.NotNil(t, traceTarget, "trace oneof target should be populated")
	assert.Equal(t, float32(50.0), traceTarget.GetKeep().GetPercentage())
	require.Len(t, traceTarget.GetMatch(), 1)
	assert.Equal(t, "GET /api", traceTarget.GetMatch()[0].GetStartsWith())
}

func TestHttpProvider_Load_JSON_OneofMetricTarget(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := &policyv1.SyncResponse{
			Policies: []*policyv1.Policy{
				{
					Id:      "metric-policy",
					Name:    "Metric Filter",
					Enabled: true,
					Target: &policyv1.Policy_Metric{
						Metric: &policyv1.MetricTarget{
							Keep: false,
							Match: []*policyv1.MetricMatcher{
								{
									Field: &policyv1.MetricMatcher_MetricField{
										MetricField: policyv1.MetricField_METRIC_FIELD_NAME,
									},
									Match: &policyv1.MetricMatcher_Regex{
										Regex: "system\\.cpu\\..*",
									},
								},
							},
						},
					},
				},
			},
			Hash: "metric-hash",
		}
		respBytes, err := protojson.Marshal(resp)
		require.NoError(t, err)
		w.Header().Set("Content-Type", "application/json")
		w.Write(respBytes)
	}))
	defer server.Close()

	p := NewHttpProvider(server.URL, WithContentType(ContentTypeJSON))
	policies, err := p.Load()

	require.NoError(t, err)
	require.Len(t, policies, 1)

	policy := policies[0]
	metricTarget := policy.GetMetric()
	require.NotNil(t, metricTarget, "metric oneof target should be populated")
	assert.False(t, metricTarget.GetKeep())
	require.Len(t, metricTarget.GetMatch(), 1)
	assert.Equal(t, "system\\.cpu\\..*", metricTarget.GetMatch()[0].GetRegex())
}

func TestHttpProvider_Load_JSON_MultiplePoliciesMixedTargets(t *testing.T) {
	// Test a realistic sync response with multiple policies using different
	// oneof targets and string-encoded uint64 timestamps.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts := uint64(1771277811889719000)
		resp := &policyv1.SyncResponse{
			Policies: []*policyv1.Policy{
				{
					Id:                 "log-1",
					Name:               "Log Keep All",
					Enabled:            true,
					CreatedAtUnixNano:  ts,
					ModifiedAtUnixNano: ts,
					Target: &policyv1.Policy_Log{
						Log: &policyv1.LogTarget{Keep: "all"},
					},
				},
				{
					Id:                 "trace-1",
					Name:               "Trace Sample",
					Enabled:            true,
					CreatedAtUnixNano:  ts,
					ModifiedAtUnixNano: ts,
					Target: &policyv1.Policy_Trace{
						Trace: &policyv1.TraceTarget{
							Keep: &policyv1.TraceSamplingConfig{Percentage: 25.0},
						},
					},
				},
				{
					Id:                 "metric-1",
					Name:               "Metric Drop",
					Enabled:            true,
					CreatedAtUnixNano:  ts,
					ModifiedAtUnixNano: ts,
					Target: &policyv1.Policy_Metric{
						Metric: &policyv1.MetricTarget{Keep: false},
					},
				},
			},
			Hash:                  "mixed-hash",
			SyncTimestampUnixNano: ts,
		}
		respBytes, err := protojson.Marshal(resp)
		require.NoError(t, err)
		w.Header().Set("Content-Type", "application/json")
		w.Write(respBytes)
	}))
	defer server.Close()

	p := NewHttpProvider(server.URL, WithContentType(ContentTypeJSON))
	policies, err := p.Load()

	require.NoError(t, err)
	require.Len(t, policies, 3)

	// Verify each policy decoded its oneof target correctly
	assert.NotNil(t, policies[0].GetLog())
	assert.Nil(t, policies[0].GetTrace())
	assert.Nil(t, policies[0].GetMetric())

	assert.Nil(t, policies[1].GetLog())
	assert.NotNil(t, policies[1].GetTrace())
	assert.Nil(t, policies[1].GetMetric())

	assert.Nil(t, policies[2].GetLog())
	assert.Nil(t, policies[2].GetTrace())
	assert.NotNil(t, policies[2].GetMetric())

	// Verify uint64 timestamps survived
	expectedTS := uint64(1771277811889719000)
	for _, pol := range policies {
		assert.Equal(t, expectedTS, pol.GetCreatedAtUnixNano())
		assert.Equal(t, expectedTS, pol.GetModifiedAtUnixNano())
	}
	assert.Equal(t, expectedTS, p.lastSyncTimestamp)
}

func TestHttpProvider_Load_JSON_AttributeMatchers(t *testing.T) {
	// Test nested oneof fields within matchers (attribute paths).
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := &policyv1.SyncResponse{
			Policies: []*policyv1.Policy{
				{
					Id:      "attr-policy",
					Name:    "Attribute Matcher",
					Enabled: true,
					Target: &policyv1.Policy_Log{
						Log: &policyv1.LogTarget{
							Keep: "none",
							Match: []*policyv1.LogMatcher{
								{
									Field: &policyv1.LogMatcher_LogAttribute{
										LogAttribute: &policyv1.AttributePath{Path: []string{"http.status_code"}},
									},
									Match: &policyv1.LogMatcher_Exact{
										Exact: "500",
									},
								},
								{
									Field: &policyv1.LogMatcher_ResourceAttribute{
										ResourceAttribute: &policyv1.AttributePath{Path: []string{"service.name"}},
									},
									Match: &policyv1.LogMatcher_Contains{
										Contains: "payment",
									},
								},
							},
						},
					},
				},
			},
			Hash: "attr-hash",
		}
		respBytes, err := protojson.Marshal(resp)
		require.NoError(t, err)
		w.Header().Set("Content-Type", "application/json")
		w.Write(respBytes)
	}))
	defer server.Close()

	p := NewHttpProvider(server.URL, WithContentType(ContentTypeJSON))
	policies, err := p.Load()

	require.NoError(t, err)
	require.Len(t, policies, 1)

	logTarget := policies[0].GetLog()
	require.NotNil(t, logTarget)
	require.Len(t, logTarget.GetMatch(), 2)

	// First matcher: log attribute exact match
	m0 := logTarget.GetMatch()[0]
	assert.Equal(t, []string{"http.status_code"}, m0.GetLogAttribute().GetPath())
	assert.Equal(t, "500", m0.GetExact())

	// Second matcher: resource attribute contains
	m1 := logTarget.GetMatch()[1]
	assert.Equal(t, []string{"service.name"}, m1.GetResourceAttribute().GetPath())
	assert.Equal(t, "payment", m1.GetContains())
}

func TestHttpProvider_Load_JSON_NumericUint64AlsoWorks(t *testing.T) {
	// protojson.Unmarshal also accepts numeric uint64 values (both formats
	// are valid per the proto3 JSON spec). Verify backwards compatibility.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := `{
			"policies": [{"id": "p1", "name": "test"}],
			"hash": "abc",
			"syncTimestampUnixNano": 1234567890
		}`
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(raw))
	}))
	defer server.Close()

	p := NewHttpProvider(server.URL, WithContentType(ContentTypeJSON))
	policies, err := p.Load()

	require.NoError(t, err)
	require.Len(t, policies, 1)
	assert.Equal(t, uint64(1234567890), p.lastSyncTimestamp)
}

func TestHttpProvider_Load_WithHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify custom headers
		assert.Equal(t, "Bearer secret-token", r.Header.Get("Authorization"))
		assert.Equal(t, "custom-value", r.Header.Get("X-Custom-Header"))

		resp := &policyv1.SyncResponse{Hash: "test"}
		respBytes, _ := proto.Marshal(resp)
		w.Write(respBytes)
	}))
	defer server.Close()

	p := NewHttpProvider(server.URL, WithHeaders(map[string]string{
		"Authorization":   "Bearer secret-token",
		"X-Custom-Header": "custom-value",
	}))

	_, err := p.Load()
	require.NoError(t, err)
}

func TestHttpProvider_Load_WithServiceMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req policyv1.SyncRequest
		proto.Unmarshal(body, &req)

		// Verify client metadata
		cm := req.GetClientMetadata()
		require.NotNil(t, cm)

		// Check resource attributes
		attrs := cm.GetResourceAttributes()
		attrMap := make(map[string]string)
		for _, attr := range attrs {
			if sv := attr.GetValue().GetStringValue(); sv != "" {
				attrMap[attr.GetKey()] = sv
			}
		}

		assert.Equal(t, "my-service", attrMap["service.name"])
		assert.Equal(t, "my-namespace", attrMap["service.namespace"])

		resp := &policyv1.SyncResponse{Hash: "test"}
		respBytes, _ := proto.Marshal(resp)
		w.Write(respBytes)
	}))
	defer server.Close()

	p := NewHttpProvider(server.URL, WithServiceMetadata(&ServiceMetadata{
		ServiceName:       "my-service",
		ServiceNamespace:  "my-namespace",
		ServiceInstanceID: "instance-1",
		ServiceVersion:    "1.0.0",
	}))

	_, err := p.Load()
	require.NoError(t, err)
}

func TestHttpProvider_Load_WithStatsCollector(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req policyv1.SyncRequest
		proto.Unmarshal(body, &req)

		// Verify policy statuses
		statuses := req.GetPolicyStatuses()
		require.Len(t, statuses, 2)

		statusMap := make(map[string]*policyv1.PolicySyncStatus)
		for _, s := range statuses {
			statusMap[s.GetId()] = s
		}

		assert.Equal(t, int64(100), statusMap["policy-1"].GetMatchHits())
		assert.Equal(t, int64(50), statusMap["policy-2"].GetMatchHits())

		resp := &policyv1.SyncResponse{Hash: "test"}
		respBytes, _ := proto.Marshal(resp)
		w.Write(respBytes)
	}))
	defer server.Close()

	p := NewHttpProvider(server.URL)
	p.SetStatsCollector(func() []PolicyStatsSnapshot {
		return []PolicyStatsSnapshot{
			{PolicyID: "policy-1", MatchHits: 100},
			{PolicyID: "policy-2", MatchHits: 50},
		}
	})

	_, err := p.Load()
	require.NoError(t, err)
}

func TestHttpProvider_Load_HTTPError(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
	}{
		{"bad request", http.StatusBadRequest, "invalid request"},
		{"unauthorized", http.StatusUnauthorized, "not authorized"},
		{"internal error", http.StatusInternalServerError, "server error"},
		{"not found", http.StatusNotFound, "endpoint not found"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.body))
			}))
			defer server.Close()

			p := NewHttpProvider(server.URL)
			_, err := p.Load()

			require.Error(t, err)
			assert.True(t, IsProvider(err))
		})
	}
}

func TestHttpProvider_Load_SyncError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := &policyv1.SyncResponse{
			ErrorMessage: "policy validation failed",
		}
		respBytes, _ := proto.Marshal(resp)
		w.Write(respBytes)
	}))
	defer server.Close()

	p := NewHttpProvider(server.URL)
	_, err := p.Load()

	require.Error(t, err)
	assert.True(t, IsProvider(err))
}

func TestHttpProvider_Load_InvalidResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not valid protobuf"))
	}))
	defer server.Close()

	p := NewHttpProvider(server.URL)
	_, err := p.Load()

	require.Error(t, err)
	assert.True(t, IsProvider(err))
}

func TestHttpProvider_Subscribe(t *testing.T) {
	var mu sync.Mutex
	var callCount int
	var receivedPolicies []*policyv1.Policy

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := &policyv1.SyncResponse{
			Policies: []*policyv1.Policy{
				{Id: "sub-policy", Name: "Subscription Policy"},
			},
			Hash: "initial-hash",
		}
		respBytes, _ := proto.Marshal(resp)
		w.Write(respBytes)
	}))
	defer server.Close()

	// Disable polling for this test
	p := NewHttpProvider(server.URL, WithHTTPPollInterval(0))

	err := p.Subscribe(func(policies []*policyv1.Policy) {
		mu.Lock()
		callCount++
		receivedPolicies = policies
		mu.Unlock()
	})

	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()

	assert.Equal(t, 1, callCount, "callback should be called once")
	require.Len(t, receivedPolicies, 1)
	assert.Equal(t, "sub-policy", receivedPolicies[0].Id)
}

func TestHttpProvider_Subscribe_WithPolling(t *testing.T) {
	var requestCount atomic.Int32
	var mu sync.Mutex
	var callbackCount int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := requestCount.Add(1)

		// Return different hash on second request to trigger callback
		hash := "hash-1"
		if count > 1 {
			hash = "hash-2"
		}

		resp := &policyv1.SyncResponse{
			Policies: []*policyv1.Policy{
				{Id: "policy-1"},
			},
			Hash: hash,
		}
		respBytes, _ := proto.Marshal(resp)
		w.Write(respBytes)
	}))
	defer server.Close()

	p := NewHttpProvider(server.URL, WithHTTPPollInterval(50*time.Millisecond))

	err := p.Subscribe(func(policies []*policyv1.Policy) {
		mu.Lock()
		callbackCount++
		mu.Unlock()
	})
	require.NoError(t, err)

	// Wait for at least one poll cycle
	time.Sleep(150 * time.Millisecond)
	p.Stop()

	mu.Lock()
	finalCount := callbackCount
	mu.Unlock()

	// Should have initial call + at least one poll that detected change
	assert.GreaterOrEqual(t, finalCount, 2, "callback should be called at least twice")
}

func TestHttpProvider_Subscribe_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	p := NewHttpProvider(server.URL, WithHTTPPollInterval(0))

	err := p.Subscribe(func(policies []*policyv1.Policy) {
		t.Error("callback should not be called on error")
	})

	require.Error(t, err)
}

func TestHttpProvider_Stop(t *testing.T) {
	var requestCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		resp := &policyv1.SyncResponse{Hash: "test"}
		respBytes, _ := proto.Marshal(resp)
		w.Write(respBytes)
	}))
	defer server.Close()

	p := NewHttpProvider(server.URL, WithHTTPPollInterval(50*time.Millisecond))

	err := p.Subscribe(func(policies []*policyv1.Policy) {})
	require.NoError(t, err)

	// Wait for at least one poll to happen
	assert.Eventually(t, func() bool {
		return requestCount.Load() >= 1
	}, time.Second, 10*time.Millisecond, "should have at least one request")

	// Stop and wait for goroutine to exit
	p.Stop()

	// Record count after stop completes (wg.Wait ensures goroutine exited)
	countAtStop := requestCount.Load()

	// Verify no more requests happen after stop
	assert.Never(t, func() bool {
		return requestCount.Load() > countAtStop
	}, 200*time.Millisecond, 20*time.Millisecond, "requests should not continue after Stop()")
}

func TestHttpProvider_Stop_Idempotent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := &policyv1.SyncResponse{Hash: "test"}
		respBytes, _ := proto.Marshal(resp)
		w.Write(respBytes)
	}))
	defer server.Close()

	p := NewHttpProvider(server.URL, WithHTTPPollInterval(100*time.Millisecond))

	err := p.Subscribe(func(policies []*policyv1.Policy) {})
	require.NoError(t, err)

	// Multiple stops should not panic
	p.Stop()
	p.Stop()
	p.Stop()
}

func TestHttpProvider_Stop_WithoutSubscribe(t *testing.T) {
	p := NewHttpProvider("http://example.com")

	// Should not panic when Stop is called without Subscribe
	p.Stop()
}

func TestHttpProvider_OnErrorCallback(t *testing.T) {
	var errorReceived atomic.Value

	// First request succeeds (for Subscribe), subsequent fail
	var requestCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := requestCount.Add(1)
		if count == 1 {
			// First request succeeds for Subscribe
			resp := &policyv1.SyncResponse{Hash: "test"}
			respBytes, _ := proto.Marshal(resp)
			w.Write(respBytes)
		} else {
			// Subsequent requests fail
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	p := NewHttpProvider(server.URL,
		WithHTTPPollInterval(20*time.Millisecond),
		WithHTTPOnError(func(err error) {
			errorReceived.Store(err)
		}),
	)

	err := p.Subscribe(func(policies []*policyv1.Policy) {})
	require.NoError(t, err)

	// Wait for a poll to fail
	time.Sleep(100 * time.Millisecond)
	p.Stop()

	assert.NotNil(t, errorReceived.Load(), "OnError callback should have been called")
}

func TestHttpProvider_OnSyncCallback(t *testing.T) {
	var syncCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := &policyv1.SyncResponse{Hash: "test"}
		respBytes, _ := proto.Marshal(resp)
		w.Write(respBytes)
	}))
	defer server.Close()

	p := NewHttpProvider(server.URL,
		WithHTTPPollInterval(20*time.Millisecond),
		WithHTTPOnSync(func() {
			syncCount.Add(1)
		}),
	)

	err := p.Subscribe(func(policies []*policyv1.Policy) {})
	require.NoError(t, err)

	// Wait for some polls
	time.Sleep(100 * time.Millisecond)
	p.Stop()

	// OnSync should have been called multiple times (during polling, not initial load)
	assert.Greater(t, syncCount.Load(), int32(0), "OnSync callback should have been called")
}

func TestHttpProvider_HashChangeDetection(t *testing.T) {
	var requestCount atomic.Int32
	var callbackCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := requestCount.Add(1)

		// Keep same hash for requests 2 and 3, change on 4
		var hash string
		switch count {
		case 1:
			hash = "hash-1"
		case 2, 3:
			hash = "hash-1" // Same as initial - should NOT trigger callback
		default:
			hash = "hash-2" // Different - should trigger callback
		}

		resp := &policyv1.SyncResponse{
			Policies: []*policyv1.Policy{{Id: "p1"}},
			Hash:     hash,
		}
		respBytes, _ := proto.Marshal(resp)
		w.Write(respBytes)
	}))
	defer server.Close()

	p := NewHttpProvider(server.URL, WithHTTPPollInterval(20*time.Millisecond))

	err := p.Subscribe(func(policies []*policyv1.Policy) {
		callbackCount.Add(1)
	})
	require.NoError(t, err)

	// Wait for several poll cycles
	time.Sleep(150 * time.Millisecond)
	p.Stop()

	// Should have: 1 initial + 1 when hash changed to hash-2
	count := callbackCount.Load()
	assert.GreaterOrEqual(t, count, int32(2), "callback should be called at least twice")
}

func TestHttpProvider_IncrementalSync(t *testing.T) {
	var isFirstRequest atomic.Bool
	isFirstRequest.Store(true)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req policyv1.SyncRequest
		proto.Unmarshal(body, &req)

		if isFirstRequest.Load() {
			isFirstRequest.Store(false)
			assert.True(t, req.GetFullSync(), "first request should have full_sync=true")
			assert.Empty(t, req.GetLastSuccessfulHash(), "first request should have empty last_successful_hash")
		} else {
			assert.False(t, req.GetFullSync(), "subsequent requests should have full_sync=false")
			assert.Equal(t, "hash-1", req.GetLastSuccessfulHash())
		}

		resp := &policyv1.SyncResponse{
			Hash:                  "hash-1",
			SyncTimestampUnixNano: 123456789,
		}
		respBytes, _ := proto.Marshal(resp)
		w.Write(respBytes)
	}))
	defer server.Close()

	p := NewHttpProvider(server.URL, WithHTTPPollInterval(30*time.Millisecond))

	err := p.Subscribe(func(policies []*policyv1.Policy) {})
	require.NoError(t, err)

	// Wait for at least one poll after initial load
	time.Sleep(100 * time.Millisecond)
	p.Stop()
}

func TestCollectPolicyStatuses(t *testing.T) {
	tests := []struct {
		name      string
		collector StatsCollector
		wantNil   bool
		wantLen   int
	}{
		{
			name:      "nil collector",
			collector: nil,
			wantNil:   true,
		},
		{
			name: "empty snapshots",
			collector: func() []PolicyStatsSnapshot {
				return []PolicyStatsSnapshot{}
			},
			wantLen: 0,
		},
		{
			name: "multiple snapshots",
			collector: func() []PolicyStatsSnapshot {
				return []PolicyStatsSnapshot{
					{PolicyID: "p1", MatchHits: 10, MatchMisses: 5},
					{PolicyID: "p2", MatchHits: 20},
				}
			},
			wantLen: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := collectPolicyStatuses(tt.collector)

			if tt.wantNil {
				assert.Nil(t, result)
				return
			}

			assert.Len(t, result, tt.wantLen)
		})
	}
}

func TestCollectPolicyStatuses_Values(t *testing.T) {
	collector := func() []PolicyStatsSnapshot {
		return []PolicyStatsSnapshot{
			{PolicyID: "p1", MatchHits: 82, MatchMisses: 18},
		}
	}

	result := collectPolicyStatuses(collector)

	require.Len(t, result, 1)

	status := result[0]
	assert.Equal(t, "p1", status.GetId())
	assert.Equal(t, int64(82), status.GetMatchHits())
	assert.Equal(t, int64(18), status.GetMatchMisses())
}

func TestHttpProvider_ConcurrentAccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := &policyv1.SyncResponse{
			Policies: []*policyv1.Policy{{Id: "p1"}},
			Hash:     "hash",
		}
		respBytes, _ := proto.Marshal(resp)
		w.Write(respBytes)
	}))
	defer server.Close()

	p := NewHttpProvider(server.URL, WithHTTPPollInterval(10*time.Millisecond))

	err := p.Subscribe(func(policies []*policyv1.Policy) {})
	require.NoError(t, err)

	// Concurrent operations
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.SetStatsCollector(func() []PolicyStatsSnapshot {
				return nil
			})
		}()
	}

	wg.Wait()
	p.Stop()
}
