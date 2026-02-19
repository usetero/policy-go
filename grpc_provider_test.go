package policy

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
)

// mockPolicyServer implements PolicyServiceServer for testing.
type mockPolicyServer struct {
	policyv1.UnimplementedPolicyServiceServer
	mu           sync.Mutex
	syncHandler  func(context.Context, *policyv1.SyncRequest) (*policyv1.SyncResponse, error)
	requestCount atomic.Int32
	lastRequest  *policyv1.SyncRequest
	lastMetadata metadata.MD
}

func (s *mockPolicyServer) Sync(ctx context.Context, req *policyv1.SyncRequest) (*policyv1.SyncResponse, error) {
	s.requestCount.Add(1)
	s.mu.Lock()
	s.lastRequest = req
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		s.lastMetadata = md
	}
	handler := s.syncHandler
	s.mu.Unlock()

	if handler != nil {
		return handler(ctx, req)
	}

	return &policyv1.SyncResponse{
		Hash: "default-hash",
	}, nil
}

func (s *mockPolicyServer) getLastRequest() *policyv1.SyncRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastRequest
}

func (s *mockPolicyServer) getLastMetadata() metadata.MD {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastMetadata
}

func (s *mockPolicyServer) setHandler(h func(context.Context, *policyv1.SyncRequest) (*policyv1.SyncResponse, error)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.syncHandler = h
}

// startTestServer starts a gRPC test server and returns the address and cleanup function.
func startTestServer(t *testing.T, server *mockPolicyServer) (string, func()) {
	t.Helper()

	lis, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)

	grpcServer := grpc.NewServer()
	policyv1.RegisterPolicyServiceServer(grpcServer, server)

	go func() {
		if err := grpcServer.Serve(lis); err != nil && err != grpc.ErrServerStopped {
			t.Logf("server error: %v", err)
		}
	}()

	cleanup := func() {
		grpcServer.GracefulStop()
	}

	return lis.Addr().String(), cleanup
}

func TestNewGrpcProvider(t *testing.T) {
	tests := []struct {
		name             string
		target           string
		opts             []GrpcProviderOption
		wantTarget       string
		wantPollInterval time.Duration
		wantUseTLS       bool
		wantHeaders      map[string]string
	}{
		{
			name:             "default configuration",
			target:           "localhost:50051",
			opts:             nil,
			wantTarget:       "localhost:50051",
			wantPollInterval: 60 * time.Second,
			wantUseTLS:       true,
		},
		{
			name:   "with custom poll interval",
			target: "localhost:50051",
			opts: []GrpcProviderOption{
				WithGrpcPollInterval(30 * time.Second),
			},
			wantTarget:       "localhost:50051",
			wantPollInterval: 30 * time.Second,
			wantUseTLS:       true,
		},
		{
			name:   "with insecure",
			target: "localhost:50051",
			opts: []GrpcProviderOption{
				WithGrpcInsecure(),
			},
			wantTarget:       "localhost:50051",
			wantPollInterval: 60 * time.Second,
			wantUseTLS:       false,
		},
		{
			name:   "with headers",
			target: "localhost:50051",
			opts: []GrpcProviderOption{
				WithGrpcHeaders(map[string]string{
					"authorization": "Bearer token",
					"x-custom":      "value",
				}),
			},
			wantTarget:       "localhost:50051",
			wantPollInterval: 60 * time.Second,
			wantUseTLS:       true,
			wantHeaders: map[string]string{
				"authorization": "Bearer token",
				"x-custom":      "value",
			},
		},
		{
			name:   "with multiple options",
			target: "localhost:50051",
			opts: []GrpcProviderOption{
				WithGrpcPollInterval(10 * time.Second),
				WithGrpcInsecure(),
				WithGrpcHeaders(map[string]string{"x-test": "test"}),
			},
			wantTarget:       "localhost:50051",
			wantPollInterval: 10 * time.Second,
			wantUseTLS:       false,
			wantHeaders:      map[string]string{"x-test": "test"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewGrpcProvider(tt.target, tt.opts...)

			assert.Equal(t, tt.wantTarget, p.config.Target)
			assert.Equal(t, tt.wantPollInterval, p.config.PollInterval)
			assert.Equal(t, tt.wantUseTLS, p.config.UseTLS)
			if tt.wantHeaders != nil {
				for k, v := range tt.wantHeaders {
					assert.Equal(t, v, p.config.Headers[k], "Header %s mismatch", k)
				}
			}
		})
	}
}

func TestNewGrpcProvider_WithServiceMetadata(t *testing.T) {
	metadata := &ServiceMetadata{
		ServiceName:       "test-service",
		ServiceNamespace:  "test-namespace",
		ServiceInstanceID: "instance-1",
		ServiceVersion:    "1.0.0",
		SupportedStages:   []policyv1.PolicyStage{policyv1.PolicyStage_POLICY_STAGE_LOG_FILTER},
		Labels:            map[string]string{"env": "test"},
	}

	p := NewGrpcProvider("localhost:50051", WithGrpcServiceMetadata(metadata))

	assert.Equal(t, metadata, p.config.ServiceMetadata)
}

func TestNewGrpcProvider_WithCallbacks(t *testing.T) {
	var errorCalled, syncCalled bool

	p := NewGrpcProvider("localhost:50051",
		WithGrpcOnError(func(err error) { errorCalled = true }),
		WithGrpcOnSync(func() { syncCalled = true }),
	)

	require.NotNil(t, p.config.OnError)
	require.NotNil(t, p.config.OnSync)

	// Verify callbacks are callable
	p.config.OnError(nil)
	p.config.OnSync()

	assert.True(t, errorCalled, "OnError callback was not invoked")
	assert.True(t, syncCalled, "OnSync callback was not invoked")
}

func TestNewGrpcProvider_WithDialOptions(t *testing.T) {
	customOpt := grpc.WithUserAgent("test-agent")
	p := NewGrpcProvider("localhost:50051", WithGrpcDialOptions(customOpt))

	assert.Len(t, p.config.DialOptions, 1)
}

func TestGrpcProvider_SetStatsCollector(t *testing.T) {
	p := NewGrpcProvider("localhost:50051")

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

func TestGrpcProvider_Load(t *testing.T) {
	server := &mockPolicyServer{}
	server.setHandler(func(ctx context.Context, req *policyv1.SyncRequest) (*policyv1.SyncResponse, error) {
		return &policyv1.SyncResponse{
			Policies: []*policyv1.Policy{
				{Id: "policy-1", Name: "Test Policy 1", Enabled: true},
				{Id: "policy-2", Name: "Test Policy 2", Enabled: false},
			},
			Hash:                  "hash123",
			SyncTimestampUnixNano: 1234567890,
		}, nil
	})

	addr, cleanup := startTestServer(t, server)
	defer cleanup()

	p := NewGrpcProvider(addr, WithGrpcInsecure(), WithGrpcPollInterval(0))
	policies, err := p.Load()

	require.NoError(t, err)
	require.Len(t, policies, 2)
	assert.Equal(t, "policy-1", policies[0].Id)

	// Verify state was updated
	assert.Equal(t, "hash123", p.lastHash)
	assert.Equal(t, uint64(1234567890), p.lastSyncTimestamp)

	// Verify request was a full sync
	lastReq := server.getLastRequest()
	require.NotNil(t, lastReq)
	assert.True(t, lastReq.GetFullSync())

	p.Stop()
}

func TestGrpcProvider_Load_WithHeaders(t *testing.T) {
	server := &mockPolicyServer{}
	server.setHandler(func(ctx context.Context, req *policyv1.SyncRequest) (*policyv1.SyncResponse, error) {
		return &policyv1.SyncResponse{Hash: "test"}, nil
	})

	addr, cleanup := startTestServer(t, server)
	defer cleanup()

	p := NewGrpcProvider(addr,
		WithGrpcInsecure(),
		WithGrpcPollInterval(0),
		WithGrpcHeaders(map[string]string{
			"authorization": "Bearer secret-token",
			"x-custom":      "custom-value",
		}),
	)

	_, err := p.Load()
	require.NoError(t, err)

	// Verify headers were sent as metadata
	md := server.getLastMetadata()
	assert.Contains(t, md.Get("authorization"), "Bearer secret-token")
	assert.Contains(t, md.Get("x-custom"), "custom-value")

	p.Stop()
}

func TestGrpcProvider_Load_WithServiceMetadata(t *testing.T) {
	server := &mockPolicyServer{}
	server.setHandler(func(ctx context.Context, req *policyv1.SyncRequest) (*policyv1.SyncResponse, error) {
		return &policyv1.SyncResponse{Hash: "test"}, nil
	})

	addr, cleanup := startTestServer(t, server)
	defer cleanup()

	p := NewGrpcProvider(addr,
		WithGrpcInsecure(),
		WithGrpcPollInterval(0),
		WithGrpcServiceMetadata(&ServiceMetadata{
			ServiceName:       "my-service",
			ServiceNamespace:  "my-namespace",
			ServiceInstanceID: "instance-1",
			ServiceVersion:    "1.0.0",
		}),
	)

	_, err := p.Load()
	require.NoError(t, err)

	// Verify client metadata was included
	lastReq := server.getLastRequest()
	require.NotNil(t, lastReq)
	cm := lastReq.GetClientMetadata()
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

	p.Stop()
}

func TestGrpcProvider_Load_WithStatsCollector(t *testing.T) {
	server := &mockPolicyServer{}
	server.setHandler(func(ctx context.Context, req *policyv1.SyncRequest) (*policyv1.SyncResponse, error) {
		return &policyv1.SyncResponse{Hash: "test"}, nil
	})

	addr, cleanup := startTestServer(t, server)
	defer cleanup()

	p := NewGrpcProvider(addr, WithGrpcInsecure(), WithGrpcPollInterval(0))
	p.SetStatsCollector(func() []PolicyStatsSnapshot {
		return []PolicyStatsSnapshot{
			{PolicyID: "policy-1", MatchHits: 100},
			{PolicyID: "policy-2", MatchHits: 50},
		}
	})

	_, err := p.Load()
	require.NoError(t, err)

	// Verify policy statuses were included
	lastReq := server.getLastRequest()
	require.NotNil(t, lastReq)
	statuses := lastReq.GetPolicyStatuses()
	require.Len(t, statuses, 2)

	statusMap := make(map[string]*policyv1.PolicySyncStatus)
	for _, s := range statuses {
		statusMap[s.GetId()] = s
	}

	assert.Equal(t, int64(100), statusMap["policy-1"].GetMatchHits())
	assert.Equal(t, int64(50), statusMap["policy-2"].GetMatchHits())

	p.Stop()
}

func TestGrpcProvider_Load_GrpcError(t *testing.T) {
	tests := []struct {
		name     string
		grpcCode codes.Code
		grpcMsg  string
	}{
		{"unavailable", codes.Unavailable, "service unavailable"},
		{"internal", codes.Internal, "internal error"},
		{"permission denied", codes.PermissionDenied, "access denied"},
		{"unauthenticated", codes.Unauthenticated, "not authenticated"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := &mockPolicyServer{}
			server.setHandler(func(ctx context.Context, req *policyv1.SyncRequest) (*policyv1.SyncResponse, error) {
				return nil, status.Error(tt.grpcCode, tt.grpcMsg)
			})

			addr, cleanup := startTestServer(t, server)
			defer cleanup()

			p := NewGrpcProvider(addr, WithGrpcInsecure(), WithGrpcPollInterval(0))
			_, err := p.Load()

			require.Error(t, err)
			assert.True(t, IsProvider(err))

			p.Stop()
		})
	}
}

func TestGrpcProvider_Load_SyncError(t *testing.T) {
	server := &mockPolicyServer{}
	server.setHandler(func(ctx context.Context, req *policyv1.SyncRequest) (*policyv1.SyncResponse, error) {
		return &policyv1.SyncResponse{
			ErrorMessage: "policy validation failed",
		}, nil
	})

	addr, cleanup := startTestServer(t, server)
	defer cleanup()

	p := NewGrpcProvider(addr, WithGrpcInsecure(), WithGrpcPollInterval(0))
	_, err := p.Load()

	require.Error(t, err)
	assert.True(t, IsProvider(err))
	assert.Contains(t, err.Error(), "policy validation failed")

	p.Stop()
}

func TestGrpcProvider_Load_ConnectionError(t *testing.T) {
	// Try to connect to a non-existent server
	p := NewGrpcProvider("localhost:99999", WithGrpcInsecure(), WithGrpcPollInterval(0))

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, err := p.sync(ctx, true)

	require.Error(t, err)
	assert.True(t, IsProvider(err))

	p.Stop()
}

func TestGrpcProvider_Subscribe(t *testing.T) {
	server := &mockPolicyServer{}
	server.setHandler(func(ctx context.Context, req *policyv1.SyncRequest) (*policyv1.SyncResponse, error) {
		return &policyv1.SyncResponse{
			Policies: []*policyv1.Policy{
				{Id: "sub-policy", Name: "Subscription Policy"},
			},
			Hash: "initial-hash",
		}, nil
	})

	addr, cleanup := startTestServer(t, server)
	defer cleanup()

	var mu sync.Mutex
	var callCount int
	var receivedPolicies []*policyv1.Policy

	// Disable polling for this test
	p := NewGrpcProvider(addr, WithGrpcInsecure(), WithGrpcPollInterval(0))

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

	p.Stop()
}

func TestGrpcProvider_Subscribe_WithPolling(t *testing.T) {
	var requestCount atomic.Int32
	var mu sync.Mutex
	var callbackCount int

	server := &mockPolicyServer{}
	server.setHandler(func(ctx context.Context, req *policyv1.SyncRequest) (*policyv1.SyncResponse, error) {
		count := requestCount.Add(1)

		// Return different hash on second request to trigger callback
		hash := "hash-1"
		if count > 1 {
			hash = "hash-2"
		}

		return &policyv1.SyncResponse{
			Policies: []*policyv1.Policy{{Id: "policy-1"}},
			Hash:     hash,
		}, nil
	})

	addr, cleanup := startTestServer(t, server)
	defer cleanup()

	p := NewGrpcProvider(addr, WithGrpcInsecure(), WithGrpcPollInterval(50*time.Millisecond))

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

func TestGrpcProvider_Subscribe_Error(t *testing.T) {
	server := &mockPolicyServer{}
	server.setHandler(func(ctx context.Context, req *policyv1.SyncRequest) (*policyv1.SyncResponse, error) {
		return nil, status.Error(codes.Internal, "server error")
	})

	addr, cleanup := startTestServer(t, server)
	defer cleanup()

	p := NewGrpcProvider(addr, WithGrpcInsecure(), WithGrpcPollInterval(0))

	err := p.Subscribe(func(policies []*policyv1.Policy) {
		t.Error("callback should not be called on error")
	})

	require.Error(t, err)
}

func TestGrpcProvider_Stop(t *testing.T) {
	var requestCount atomic.Int32

	server := &mockPolicyServer{}
	server.setHandler(func(ctx context.Context, req *policyv1.SyncRequest) (*policyv1.SyncResponse, error) {
		requestCount.Add(1)
		return &policyv1.SyncResponse{Hash: "test"}, nil
	})

	addr, cleanup := startTestServer(t, server)
	defer cleanup()

	p := NewGrpcProvider(addr, WithGrpcInsecure(), WithGrpcPollInterval(100*time.Millisecond))

	err := p.Subscribe(func(policies []*policyv1.Policy) {})
	require.NoError(t, err)

	// Let a few polls happen
	time.Sleep(250 * time.Millisecond)

	// Stop and wait for goroutine to exit (wg.Wait ensures goroutine exited)
	p.Stop()

	// Record count after stop completes
	countAtStop := requestCount.Load()

	// Wait and verify no more requests
	time.Sleep(250 * time.Millisecond)
	countAfterStop := requestCount.Load()

	assert.Equal(t, countAtStop, countAfterStop, "requests should not continue after Stop()")
}

func TestGrpcProvider_Stop_Idempotent(t *testing.T) {
	server := &mockPolicyServer{}
	addr, cleanup := startTestServer(t, server)
	defer cleanup()

	p := NewGrpcProvider(addr, WithGrpcInsecure(), WithGrpcPollInterval(100*time.Millisecond))

	err := p.Subscribe(func(policies []*policyv1.Policy) {})
	require.NoError(t, err)

	// Multiple stops should not panic
	p.Stop()
	p.Stop()
	p.Stop()
}

func TestGrpcProvider_Stop_WithoutSubscribe(t *testing.T) {
	p := NewGrpcProvider("localhost:50051")

	// Should not panic when Stop is called without Subscribe
	p.Stop()
}

func TestGrpcProvider_OnErrorCallback(t *testing.T) {
	var errorReceived atomic.Value

	// First request succeeds (for Subscribe), subsequent fail
	var requestCount atomic.Int32
	server := &mockPolicyServer{}
	server.setHandler(func(ctx context.Context, req *policyv1.SyncRequest) (*policyv1.SyncResponse, error) {
		count := requestCount.Add(1)
		if count == 1 {
			// First request succeeds for Subscribe
			return &policyv1.SyncResponse{Hash: "test"}, nil
		}
		// Subsequent requests fail
		return nil, status.Error(codes.Internal, "server error")
	})

	addr, cleanup := startTestServer(t, server)
	defer cleanup()

	p := NewGrpcProvider(addr,
		WithGrpcInsecure(),
		WithGrpcPollInterval(20*time.Millisecond),
		WithGrpcOnError(func(err error) {
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

func TestGrpcProvider_OnSyncCallback(t *testing.T) {
	var syncCount atomic.Int32

	server := &mockPolicyServer{}
	server.setHandler(func(ctx context.Context, req *policyv1.SyncRequest) (*policyv1.SyncResponse, error) {
		return &policyv1.SyncResponse{Hash: "test"}, nil
	})

	addr, cleanup := startTestServer(t, server)
	defer cleanup()

	p := NewGrpcProvider(addr,
		WithGrpcInsecure(),
		WithGrpcPollInterval(20*time.Millisecond),
		WithGrpcOnSync(func() {
			syncCount.Add(1)
		}),
	)

	err := p.Subscribe(func(policies []*policyv1.Policy) {})
	require.NoError(t, err)

	// Wait for some polls
	time.Sleep(100 * time.Millisecond)
	p.Stop()

	// OnSync should have been called multiple times
	assert.Greater(t, syncCount.Load(), int32(0), "OnSync callback should have been called")
}

func TestGrpcProvider_HashChangeDetection(t *testing.T) {
	var requestCount atomic.Int32
	var callbackCount atomic.Int32

	server := &mockPolicyServer{}
	server.setHandler(func(ctx context.Context, req *policyv1.SyncRequest) (*policyv1.SyncResponse, error) {
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

		return &policyv1.SyncResponse{
			Policies: []*policyv1.Policy{{Id: "p1"}},
			Hash:     hash,
		}, nil
	})

	addr, cleanup := startTestServer(t, server)
	defer cleanup()

	p := NewGrpcProvider(addr, WithGrpcInsecure(), WithGrpcPollInterval(20*time.Millisecond))

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

func TestGrpcProvider_IncrementalSync(t *testing.T) {
	var isFirstRequest atomic.Bool
	isFirstRequest.Store(true)

	server := &mockPolicyServer{}
	server.setHandler(func(ctx context.Context, req *policyv1.SyncRequest) (*policyv1.SyncResponse, error) {
		if isFirstRequest.Load() {
			isFirstRequest.Store(false)
			assert.True(t, req.GetFullSync(), "first request should have full_sync=true")
			assert.Empty(t, req.GetLastSuccessfulHash(), "first request should have empty last_successful_hash")
		} else {
			assert.False(t, req.GetFullSync(), "subsequent requests should have full_sync=false")
			assert.Equal(t, "hash-1", req.GetLastSuccessfulHash(), "should send last_successful_hash")
		}

		return &policyv1.SyncResponse{
			Hash:                  "hash-1",
			SyncTimestampUnixNano: 123456789,
		}, nil
	})

	addr, cleanup := startTestServer(t, server)
	defer cleanup()

	p := NewGrpcProvider(addr, WithGrpcInsecure(), WithGrpcPollInterval(30*time.Millisecond))

	err := p.Subscribe(func(policies []*policyv1.Policy) {})
	require.NoError(t, err)

	// Wait for at least one poll after initial load
	time.Sleep(100 * time.Millisecond)
	p.Stop()
}

func TestGrpcProvider_ConcurrentAccess(t *testing.T) {
	server := &mockPolicyServer{}
	server.setHandler(func(ctx context.Context, req *policyv1.SyncRequest) (*policyv1.SyncResponse, error) {
		return &policyv1.SyncResponse{
			Policies: []*policyv1.Policy{{Id: "p1"}},
			Hash:     "hash",
		}, nil
	})

	addr, cleanup := startTestServer(t, server)
	defer cleanup()

	p := NewGrpcProvider(addr, WithGrpcInsecure(), WithGrpcPollInterval(10*time.Millisecond))

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

func TestGrpcProvider_ConnectionReuse(t *testing.T) {
	var requestCount atomic.Int32

	server := &mockPolicyServer{}
	server.setHandler(func(ctx context.Context, req *policyv1.SyncRequest) (*policyv1.SyncResponse, error) {
		requestCount.Add(1)
		return &policyv1.SyncResponse{Hash: "test"}, nil
	})

	addr, cleanup := startTestServer(t, server)
	defer cleanup()

	p := NewGrpcProvider(addr, WithGrpcInsecure(), WithGrpcPollInterval(0))

	// Multiple loads should reuse the connection
	_, err := p.Load()
	require.NoError(t, err)

	_, err = p.Load()
	require.NoError(t, err)

	_, err = p.Load()
	require.NoError(t, err)

	assert.Equal(t, int32(3), requestCount.Load())

	// Connection should be cached
	p.mu.RLock()
	conn := p.conn
	p.mu.RUnlock()
	assert.NotNil(t, conn)

	p.Stop()

	// After stop, connection should be closed
	p.mu.RLock()
	connAfterStop := p.conn
	p.mu.RUnlock()
	assert.Nil(t, connAfterStop)
}
