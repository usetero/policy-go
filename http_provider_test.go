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
			if got := tt.contentType.String(); got != tt.want {
				t.Errorf("ContentType.String() = %v, want %v", got, tt.want)
			}
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

			if p.config.URL != tt.wantURL {
				t.Errorf("URL = %v, want %v", p.config.URL, tt.wantURL)
			}
			if p.config.PollInterval != tt.wantPollInterval {
				t.Errorf("PollInterval = %v, want %v", p.config.PollInterval, tt.wantPollInterval)
			}
			if p.config.ContentType != tt.wantContentType {
				t.Errorf("ContentType = %v, want %v", p.config.ContentType, tt.wantContentType)
			}
			if tt.wantHeaders != nil {
				for k, v := range tt.wantHeaders {
					if p.config.Headers[k] != v {
						t.Errorf("Header[%s] = %v, want %v", k, p.config.Headers[k], v)
					}
				}
			}
			if p.client == nil {
				t.Error("client should not be nil")
			}
		})
	}
}

func TestNewHttpProvider_WithCustomClient(t *testing.T) {
	customClient := &http.Client{Timeout: 5 * time.Second}
	p := NewHttpProvider("http://example.com", WithHTTPClient(customClient))

	if p.client != customClient {
		t.Error("custom HTTP client was not set")
	}
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

	if p.config.ServiceMetadata != metadata {
		t.Error("ServiceMetadata was not set")
	}
}

func TestNewHttpProvider_WithCallbacks(t *testing.T) {
	var errorCalled, syncCalled bool

	p := NewHttpProvider("http://example.com",
		WithHTTPOnError(func(err error) { errorCalled = true }),
		WithHTTPOnSync(func() { syncCalled = true }),
	)

	if p.config.OnError == nil {
		t.Error("OnError callback was not set")
	}
	if p.config.OnSync == nil {
		t.Error("OnSync callback was not set")
	}

	// Verify callbacks are callable
	p.config.OnError(nil)
	p.config.OnSync()

	if !errorCalled {
		t.Error("OnError callback was not invoked")
	}
	if !syncCalled {
		t.Error("OnSync callback was not invoked")
	}
}

func TestHttpProvider_SetStatsCollector(t *testing.T) {
	p := NewHttpProvider("http://example.com")

	if p.statsCollector != nil {
		t.Error("statsCollector should be nil initially")
	}

	collector := func() []PolicyStatsSnapshot {
		return []PolicyStatsSnapshot{
			{PolicyID: "policy-1", Hits: 10, Drops: 5},
		}
	}

	p.SetStatsCollector(collector)

	if p.statsCollector == nil {
		t.Error("statsCollector should be set")
	}

	// Verify the collector returns expected data
	snapshots := p.statsCollector()
	if len(snapshots) != 1 {
		t.Errorf("expected 1 snapshot, got %d", len(snapshots))
	}
	if snapshots[0].PolicyID != "policy-1" {
		t.Errorf("expected policy-1, got %s", snapshots[0].PolicyID)
	}
}

func TestHttpProvider_Load_Protobuf(t *testing.T) {
	expectedPolicies := []*policyv1.Policy{
		{Id: "policy-1", Name: "Test Policy 1", Enabled: true},
		{Id: "policy-2", Name: "Test Policy 2", Enabled: false},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/x-protobuf" {
			t.Errorf("expected application/x-protobuf, got %s", ct)
		}
		if accept := r.Header.Get("Accept"); accept != "application/x-protobuf" {
			t.Errorf("expected application/x-protobuf Accept, got %s", accept)
		}

		// Parse request
		body, _ := io.ReadAll(r.Body)
		var req policyv1.SyncRequest
		if err := proto.Unmarshal(body, &req); err != nil {
			t.Errorf("failed to unmarshal request: %v", err)
		}
		if !req.FullSync {
			t.Error("expected full_sync to be true")
		}

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

	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(policies) != 2 {
		t.Errorf("expected 2 policies, got %d", len(policies))
	}
	if policies[0].Id != "policy-1" {
		t.Errorf("expected policy-1, got %s", policies[0].Id)
	}

	// Verify state was updated
	if p.lastHash != "hash123" {
		t.Errorf("lastHash = %s, want hash123", p.lastHash)
	}
	if p.lastSyncTimestamp != 1234567890 {
		t.Errorf("lastSyncTimestamp = %d, want 1234567890", p.lastSyncTimestamp)
	}
}

func TestHttpProvider_Load_JSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected application/json, got %s", ct)
		}

		// Parse JSON request
		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("failed to unmarshal JSON request: %v", err)
		}
		if fullSync, ok := req["full_sync"].(bool); !ok || !fullSync {
			t.Error("expected full_sync to be true")
		}

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

	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(policies) != 1 {
		t.Errorf("expected 1 policy, got %d", len(policies))
	}
}

func TestHttpProvider_Load_WithHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify custom headers
		if auth := r.Header.Get("Authorization"); auth != "Bearer secret-token" {
			t.Errorf("expected Authorization header, got %s", auth)
		}
		if custom := r.Header.Get("X-Custom-Header"); custom != "custom-value" {
			t.Errorf("expected X-Custom-Header, got %s", custom)
		}

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
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
}

func TestHttpProvider_Load_WithServiceMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req policyv1.SyncRequest
		proto.Unmarshal(body, &req)

		// Verify client metadata
		cm := req.GetClientMetadata()
		if cm == nil {
			t.Fatal("expected client_metadata to be set")
		}

		// Check resource attributes
		attrs := cm.GetResourceAttributes()
		attrMap := make(map[string]string)
		for _, attr := range attrs {
			if sv := attr.GetValue().GetStringValue(); sv != "" {
				attrMap[attr.GetKey()] = sv
			}
		}

		if attrMap["service.name"] != "my-service" {
			t.Errorf("service.name = %s, want my-service", attrMap["service.name"])
		}
		if attrMap["service.namespace"] != "my-namespace" {
			t.Errorf("service.namespace = %s, want my-namespace", attrMap["service.namespace"])
		}

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
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
}

func TestHttpProvider_Load_WithStatsCollector(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req policyv1.SyncRequest
		proto.Unmarshal(body, &req)

		// Verify policy statuses
		statuses := req.GetPolicyStatuses()
		if len(statuses) != 2 {
			t.Errorf("expected 2 policy statuses, got %d", len(statuses))
		}

		statusMap := make(map[string]*policyv1.PolicySyncStatus)
		for _, s := range statuses {
			statusMap[s.GetId()] = s
		}

		if s := statusMap["policy-1"]; s == nil || s.GetMatchHits() != 100 {
			t.Errorf("policy-1 match_hits = %v, want 100", s)
		}
		if s := statusMap["policy-2"]; s == nil || s.GetMatchHits() != 50 {
			t.Errorf("policy-2 match_hits = %v, want 50", s)
		}

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
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
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

			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !IsProvider(err) {
				t.Errorf("expected provider error, got %T", err)
			}
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

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !IsProvider(err) {
		t.Errorf("expected provider error, got %T", err)
	}
}

func TestHttpProvider_Load_InvalidResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not valid protobuf"))
	}))
	defer server.Close()

	p := NewHttpProvider(server.URL)
	_, err := p.Load()

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !IsProvider(err) {
		t.Errorf("expected provider error, got %T", err)
	}
}

func TestHttpProvider_Subscribe(t *testing.T) {
	callCount := 0
	var receivedPolicies []*policyv1.Policy
	var mu sync.Mutex

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

	if err != nil {
		t.Fatalf("Subscribe() error = %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	if callCount != 1 {
		t.Errorf("callback called %d times, want 1", callCount)
	}
	if len(receivedPolicies) != 1 {
		t.Errorf("received %d policies, want 1", len(receivedPolicies))
	}
	if receivedPolicies[0].Id != "sub-policy" {
		t.Errorf("policy ID = %s, want sub-policy", receivedPolicies[0].Id)
	}
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
	if err != nil {
		t.Fatalf("Subscribe() error = %v", err)
	}

	// Wait for at least one poll cycle
	time.Sleep(150 * time.Millisecond)
	p.Stop()

	mu.Lock()
	finalCount := callbackCount
	mu.Unlock()

	// Should have initial call + at least one poll that detected change
	if finalCount < 2 {
		t.Errorf("callback called %d times, want at least 2", finalCount)
	}
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

	if err == nil {
		t.Fatal("expected error, got nil")
	}
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
	if err != nil {
		t.Fatalf("Subscribe() error = %v", err)
	}

	// Let a few polls happen
	time.Sleep(150 * time.Millisecond)

	// Stop and wait for goroutine to exit
	p.Stop()

	// Record count after stop completes (wg.Wait ensures goroutine exited)
	countAtStop := requestCount.Load()

	// Wait and verify no more requests
	time.Sleep(150 * time.Millisecond)
	countAfterStop := requestCount.Load()

	if countAfterStop != countAtStop {
		t.Errorf("requests continued after Stop(): before=%d, after=%d", countAtStop, countAfterStop)
	}
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
	if err != nil {
		t.Fatalf("Subscribe() error = %v", err)
	}

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
	if err != nil {
		t.Fatalf("Subscribe() error = %v", err)
	}

	// Wait for a poll to fail
	time.Sleep(100 * time.Millisecond)
	p.Stop()

	if errorReceived.Load() == nil {
		t.Error("OnError callback was never called")
	}
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
	if err != nil {
		t.Fatalf("Subscribe() error = %v", err)
	}

	// Wait for some polls
	time.Sleep(100 * time.Millisecond)
	p.Stop()

	// OnSync should have been called multiple times (during polling, not initial load)
	if syncCount.Load() == 0 {
		t.Error("OnSync callback was never called")
	}
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
	if err != nil {
		t.Fatalf("Subscribe() error = %v", err)
	}

	// Wait for several poll cycles
	time.Sleep(150 * time.Millisecond)
	p.Stop()

	// Should have: 1 initial + 1 when hash changed to hash-2
	// NOT called when hash stayed the same
	count := callbackCount.Load()
	if count < 2 {
		t.Errorf("callback called %d times, want at least 2", count)
	}
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
			if !req.GetFullSync() {
				t.Error("first request should have full_sync=true")
			}
			if req.GetLastSuccessfulHash() != "" {
				t.Error("first request should have empty last_successful_hash")
			}
		} else {
			if req.GetFullSync() {
				t.Error("subsequent requests should have full_sync=false")
			}
			if req.GetLastSuccessfulHash() != "hash-1" {
				t.Errorf("expected last_successful_hash=hash-1, got %s", req.GetLastSuccessfulHash())
			}
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
	if err != nil {
		t.Fatalf("Subscribe() error = %v", err)
	}

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
				if result != nil {
					t.Errorf("expected nil, got %v", result)
				}
				return
			}

			if len(result) != tt.wantLen {
				t.Errorf("len = %d, want %d", len(result), tt.wantLen)
			}
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

	if len(result) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result))
	}

	status := result[0]
	if status.GetId() != "p1" {
		t.Errorf("Id = %s, want p1", status.GetId())
	}
	if status.GetMatchHits() != 100 {
		t.Errorf("MatchHits = %d, want 100", status.GetMatchHits())
	}
	// MatchMisses = Drops + Samples + RateLimited = 10 + 5 + 3 = 18
	if status.GetMatchMisses() != 18 {
		t.Errorf("MatchMisses = %d, want 18", status.GetMatchMisses())
	}
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

			if got["full_sync"] != tt.want["full_sync"] {
				t.Errorf("full_sync = %v, want %v", got["full_sync"], tt.want["full_sync"])
			}
			if got["last_successful_hash"] != tt.want["last_successful_hash"] {
				t.Errorf("last_successful_hash = %v, want %v", got["last_successful_hash"], tt.want["last_successful_hash"])
			}
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
	if err != nil {
		t.Fatalf("Subscribe() error = %v", err)
	}

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
