package policy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	policyv1 "github.com/usetero/policy-go/internal/proto/tero/policy/v1"
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
			{PolicyID: "policy-1", Hits: 10, Drops: 5},
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

		// Parse JSON request
		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		require.NoError(t, json.Unmarshal(body, &req))
		assert.Equal(t, true, req["full_sync"])

		// Send JSON response (using protobuf JSON format)
		resp := &policyv1.SyncResponse{
			Policies: []*policyv1.Policy{
				{Id: "json-policy", Name: "JSON Policy"},
			},
			Hash: "json-hash",
		}
		respBytes, _ := json.Marshal(resp)
		w.Header().Set("Content-Type", "application/json")
		w.Write(respBytes)
	}))
	defer server.Close()

	p := NewHttpProvider(server.URL, WithContentType(ContentTypeJSON))
	policies, err := p.Load()

	require.NoError(t, err)
	require.Len(t, policies, 1)
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
			{PolicyID: "policy-1", Hits: 100, Drops: 10},
			{PolicyID: "policy-2", Hits: 50, Drops: 5, Samples: 3, RateLimited: 2},
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

	// Let a few polls happen
	time.Sleep(150 * time.Millisecond)

	// Stop and wait for goroutine to exit
	p.Stop()

	// Record count after stop completes (wg.Wait ensures goroutine exited)
	countAtStop := requestCount.Load()

	// Wait and verify no more requests
	time.Sleep(150 * time.Millisecond)
	countAfterStop := requestCount.Load()

	assert.Equal(t, countAtStop, countAfterStop, "requests should not continue after Stop()")
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
					{PolicyID: "p1", Hits: 10, Drops: 5, Samples: 2, RateLimited: 1},
					{PolicyID: "p2", Hits: 20, Drops: 0, Samples: 0, RateLimited: 0},
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
			{PolicyID: "p1", Hits: 100, Drops: 10, Samples: 5, RateLimited: 3},
		}
	}

	result := collectPolicyStatuses(collector)

	require.Len(t, result, 1)

	status := result[0]
	assert.Equal(t, "p1", status.GetId())
	assert.Equal(t, int64(100), status.GetMatchHits())
	// MatchMisses = Drops + Samples + RateLimited = 10 + 5 + 3 = 18
	assert.Equal(t, int64(18), status.GetMatchMisses())
}

func TestSyncRequestToMap(t *testing.T) {
	tests := []struct {
		name string
		req  *policyv1.SyncRequest
		want map[string]any
	}{
		{
			name: "minimal request",
			req: &policyv1.SyncRequest{
				FullSync: true,
			},
			want: map[string]any{
				"full_sync":                     true,
				"last_sync_timestamp_unix_nano": uint64(0),
				"last_successful_hash":          "",
			},
		},
		{
			name: "with hash and timestamp",
			req: &policyv1.SyncRequest{
				FullSync:                  false,
				LastSuccessfulHash:        "abc123",
				LastSyncTimestampUnixNano: 1234567890,
			},
			want: map[string]any{
				"full_sync":                     false,
				"last_sync_timestamp_unix_nano": uint64(1234567890),
				"last_successful_hash":          "abc123",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := syncRequestToMap(tt.req)

			assert.Equal(t, tt.want["full_sync"], got["full_sync"])
			assert.Equal(t, tt.want["last_successful_hash"], got["last_successful_hash"])
		})
	}
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
