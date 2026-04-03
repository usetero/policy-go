package policy

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
)

// configTestPolicyServer implements PolicyServiceServer for config tests.
type configTestPolicyServer struct {
	policyv1.UnimplementedPolicyServiceServer
	mu          sync.Mutex
	syncHandler func(context.Context, *policyv1.SyncRequest) (*policyv1.SyncResponse, error)
}

func (s *configTestPolicyServer) Sync(ctx context.Context, req *policyv1.SyncRequest) (*policyv1.SyncResponse, error) {
	s.mu.Lock()
	handler := s.syncHandler
	s.mu.Unlock()

	if handler != nil {
		return handler(ctx, req)
	}

	return &policyv1.SyncResponse{Hash: "default-hash"}, nil
}

func (s *configTestPolicyServer) setHandler(h func(context.Context, *policyv1.SyncRequest) (*policyv1.SyncResponse, error)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.syncHandler = h
}

// startTestGrpcServer starts a gRPC test server and returns the address and cleanup function.
func startTestGrpcServer(t *testing.T, server *configTestPolicyServer) (string, func()) {
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

func TestParseConfigEmpty(t *testing.T) {
	config, err := ParseConfig([]byte(`{"policy_providers": []}`))
	require.NoError(t, err)
	assert.Empty(t, config.Providers)
}

func TestParseConfigFileProvider(t *testing.T) {
	json := `{
		"policy_providers": [
			{
				"type": "file",
				"id": "local-policies",
				"path": "/etc/policies.json"
			}
		]
	}`

	config, err := ParseConfig([]byte(json))
	require.NoError(t, err)
	require.Len(t, config.Providers, 1)

	p := config.Providers[0]
	assert.Equal(t, "file", p.Type)
	assert.Equal(t, "local-policies", p.ID)
	assert.Equal(t, "/etc/policies.json", p.Path)
}

func TestParseConfigFileProviderWithPollInterval(t *testing.T) {
	json := `{
		"policy_providers": [
			{
				"type": "file",
				"id": "local-policies",
				"path": "/etc/policies.json",
				"poll_interval_secs": 30
			}
		]
	}`

	config, err := ParseConfig([]byte(json))
	require.NoError(t, err)

	p := config.Providers[0]
	require.NotNil(t, p.PollIntervalSecs)
	assert.Equal(t, 30, *p.PollIntervalSecs)
	assert.Equal(t, 30*time.Second, p.PollInterval())
}

func TestParseConfigMultipleProviders(t *testing.T) {
	json := `{
		"policy_providers": [
			{
				"type": "file",
				"id": "local-policies",
				"path": "/etc/policies.json"
			},
			{
				"type": "file",
				"id": "override-policies",
				"path": "/etc/policies-override.json",
				"poll_interval_secs": 60
			}
		]
	}`

	config, err := ParseConfig([]byte(json))
	require.NoError(t, err)
	require.Len(t, config.Providers, 2)

	assert.Equal(t, "local-policies", config.Providers[0].ID)
	assert.Equal(t, "override-policies", config.Providers[1].ID)
}

func TestParseConfigHttpProvider(t *testing.T) {
	json := `{
		"policy_providers": [
			{
				"type": "http",
				"id": "remote-policies",
				"url": "https://api.example.com/policies",
				"headers": [
					{"name": "Authorization", "value": "Bearer token123"},
					{"name": "X-Custom", "value": "value"}
				],
				"poll_interval_secs": 120,
				"content_type": "json"
			}
		]
	}`

	config, err := ParseConfig([]byte(json))
	require.NoError(t, err)

	p := config.Providers[0]
	assert.Equal(t, "http", p.Type)
	assert.Equal(t, "https://api.example.com/policies", p.URL)
	require.Len(t, p.Headers, 2)
	assert.Equal(t, "Authorization", p.Headers[0].Name)
	assert.Equal(t, "Bearer token123", p.Headers[0].Value)
	assert.Equal(t, "json", p.ContentType)
}

func TestParseConfigGrpcProvider(t *testing.T) {
	json := `{
		"policy_providers": [
			{
				"type": "grpc",
				"id": "grpc-policies",
				"url": "grpc://api.example.com:443",
				"headers": [
					{"name": "authorization", "value": "Bearer token123"}
				],
				"poll_interval_secs": 60
			}
		]
	}`

	config, err := ParseConfig([]byte(json))
	require.NoError(t, err)

	p := config.Providers[0]
	assert.Equal(t, "grpc", p.Type)
	assert.Equal(t, "grpc://api.example.com:443", p.URL)
}

func TestParseConfigValidationMissingID(t *testing.T) {
	json := `{
		"policy_providers": [
			{
				"type": "file",
				"path": "/etc/policies.json"
			}
		]
	}`

	_, err := ParseConfig([]byte(json))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "id is required")
}

func TestParseConfigValidationMissingType(t *testing.T) {
	json := `{
		"policy_providers": [
			{
				"id": "test",
				"path": "/etc/policies.json"
			}
		]
	}`

	_, err := ParseConfig([]byte(json))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "type is required")
}

func TestParseConfigValidationMissingPath(t *testing.T) {
	json := `{
		"policy_providers": [
			{
				"type": "file",
				"id": "test"
			}
		]
	}`

	_, err := ParseConfig([]byte(json))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "path is required")
}

func TestParseConfigValidationMissingURL(t *testing.T) {
	tests := []struct {
		name     string
		provider string
	}{
		{"http", "http"},
		{"grpc", "grpc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			json := `{
				"policy_providers": [
					{
						"type": "` + tt.provider + `",
						"id": "test"
					}
				]
			}`

			_, err := ParseConfig([]byte(json))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "url is required")
		})
	}
}

func TestParseConfigValidationUnknownType(t *testing.T) {
	json := `{
		"policy_providers": [
			{
				"type": "unknown",
				"id": "test"
			}
		]
	}`

	_, err := ParseConfig([]byte(json))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown provider type")
}

func TestParseConfigInvalidJSON(t *testing.T) {
	_, err := ParseConfig([]byte(`{invalid json`))
	require.Error(t, err)
}

func TestParseConfigReader(t *testing.T) {
	json := `{
		"policy_providers": [
			{
				"type": "file",
				"id": "test",
				"path": "/etc/policies.json"
			}
		]
	}`

	config, err := ParseConfigReader(strings.NewReader(json))
	require.NoError(t, err)
	assert.Len(t, config.Providers, 1)
}

func TestLoadConfig(t *testing.T) {
	// Create temp config file
	tmpFile := filepath.Join(t.TempDir(), "config.json")
	content := `{
		"policy_providers": [
			{
				"type": "file",
				"id": "test",
				"path": "/etc/policies.json"
			}
		]
	}`
	err := os.WriteFile(tmpFile, []byte(content), 0644)
	require.NoError(t, err)

	config, err := LoadConfig(tmpFile)
	require.NoError(t, err)
	assert.Len(t, config.Providers, 1)
}

func TestLoadConfigFileNotFound(t *testing.T) {
	_, err := LoadConfig("/nonexistent/config.json")
	require.Error(t, err)
}

func TestProviderConfigPollIntervalNotSet(t *testing.T) {
	p := ProviderConfig{
		Type: "file",
		ID:   "test",
		Path: "/etc/policies.json",
	}

	assert.Equal(t, time.Duration(0), p.PollInterval())
}

func TestConfigLoaderLoad(t *testing.T) {
	// Create temp policies file
	policiesFile := filepath.Join(t.TempDir(), "policies.json")
	policiesContent := `{
		"policies": [
			{
				"id": "test-policy",
				"name": "Test Policy",
				"log": {
					"match": [{"log_field": "body", "regex": "error"}],
					"keep": "none"
				}
			}
		]
	}`
	err := os.WriteFile(policiesFile, []byte(policiesContent), 0644)
	require.NoError(t, err)

	config := &Config{
		Providers: []ProviderConfig{
			{
				Type: "file",
				ID:   "test-provider",
				Path: policiesFile,
			},
		},
	}

	registry := NewPolicyRegistry()
	loader := NewConfigLoader(registry)

	loaded, err := loader.Load(config)
	require.NoError(t, err)
	defer UnregisterAll(loaded)
	defer StopAll(loaded)

	require.Len(t, loaded, 1)
	assert.Equal(t, "test-provider", loaded[0].ID)

	// Verify policies were loaded
	snapshot := registry.Snapshot()
	require.NotNil(t, snapshot)

	_, ok := snapshot.GetPolicy("test-policy")
	assert.True(t, ok, "expected to find test-policy in snapshot")
}

func TestConfigLoaderLoadWithPollInterval(t *testing.T) {
	// Create temp policies file
	policiesFile := filepath.Join(t.TempDir(), "policies.json")
	policiesContent := `{"policies": []}`
	err := os.WriteFile(policiesFile, []byte(policiesContent), 0644)
	require.NoError(t, err)

	pollInterval := 30
	config := &Config{
		Providers: []ProviderConfig{
			{
				Type:             "file",
				ID:               "test-provider",
				Path:             policiesFile,
				PollIntervalSecs: &pollInterval,
			},
		},
	}

	registry := NewPolicyRegistry()
	loader := NewConfigLoader(registry)

	loaded, err := loader.Load(config)
	require.NoError(t, err)
	defer UnregisterAll(loaded)
	defer StopAll(loaded)

	// Verify the provider was created with polling enabled
	assert.Len(t, loaded, 1)
}

func TestConfigLoaderLoadWithOnError(t *testing.T) {
	// Create temp policies file
	policiesFile := filepath.Join(t.TempDir(), "policies.json")
	policiesContent := `{"policies": []}`
	err := os.WriteFile(policiesFile, []byte(policiesContent), 0644)
	require.NoError(t, err)

	pollInterval := 1
	config := &Config{
		Providers: []ProviderConfig{
			{
				Type:             "file",
				ID:               "test-provider",
				Path:             policiesFile,
				PollIntervalSecs: &pollInterval,
			},
		},
	}

	var errorCalled bool
	registry := NewPolicyRegistry()
	loader := NewConfigLoader(registry).WithOnError(func(err error) {
		errorCalled = true
	})

	loaded, err := loader.Load(config)
	require.NoError(t, err)
	defer UnregisterAll(loaded)
	defer StopAll(loaded)

	// Delete the file to trigger an error
	os.Remove(policiesFile)

	// Wait for error callback
	time.Sleep(1500 * time.Millisecond)

	assert.True(t, errorCalled, "expected onError callback to be called")
}

func TestConfigLoaderLoadMultipleProviders(t *testing.T) {
	// Create temp policies files
	tmpDir := t.TempDir()
	policiesFile1 := filepath.Join(tmpDir, "policies1.json")
	policiesFile2 := filepath.Join(tmpDir, "policies2.json")

	err := os.WriteFile(policiesFile1, []byte(`{
		"policies": [{
			"id": "policy-1",
			"name": "Policy 1",
			"log": {"match": [{"log_field": "body", "regex": "a"}], "keep": "none"}
		}]
	}`), 0644)
	require.NoError(t, err)

	err = os.WriteFile(policiesFile2, []byte(`{
		"policies": [{
			"id": "policy-2",
			"name": "Policy 2",
			"log": {"match": [{"log_field": "body", "regex": "b"}], "keep": "none"}
		}]
	}`), 0644)
	require.NoError(t, err)

	config := &Config{
		Providers: []ProviderConfig{
			{Type: "file", ID: "provider-1", Path: policiesFile1},
			{Type: "file", ID: "provider-2", Path: policiesFile2},
		},
	}

	registry := NewPolicyRegistry()
	loader := NewConfigLoader(registry)

	loaded, err := loader.Load(config)
	require.NoError(t, err)
	defer UnregisterAll(loaded)
	defer StopAll(loaded)

	assert.Len(t, loaded, 2)

	// Verify both policies were loaded
	snapshot := registry.Snapshot()
	require.NotNil(t, snapshot)

	_, ok := snapshot.GetPolicy("policy-1")
	assert.True(t, ok, "expected to find policy-1 in snapshot")

	_, ok = snapshot.GetPolicy("policy-2")
	assert.True(t, ok, "expected to find policy-2 in snapshot")
}

func TestConfigLoaderLoadFailure(t *testing.T) {
	config := &Config{
		Providers: []ProviderConfig{
			{
				Type: "file",
				ID:   "test-provider",
				Path: "/nonexistent/policies.json",
			},
		},
	}

	registry := NewPolicyRegistry()
	loader := NewConfigLoader(registry)

	_, err := loader.Load(config)
	require.Error(t, err)
}

func TestConfigLoaderLoadPartialFailure(t *testing.T) {
	// Create only the first file
	policiesFile := filepath.Join(t.TempDir(), "policies.json")
	err := os.WriteFile(policiesFile, []byte(`{
		"policies": [{
			"id": "policy-1",
			"name": "Policy 1",
			"log": {"match": [{"log_field": "body", "regex": "a"}], "keep": "none"}
		}]
	}`), 0644)
	require.NoError(t, err)

	config := &Config{
		Providers: []ProviderConfig{
			{Type: "file", ID: "provider-1", Path: policiesFile},
			{Type: "file", ID: "provider-2", Path: "/nonexistent/policies.json"},
		},
	}

	registry := NewPolicyRegistry()
	loader := NewConfigLoader(registry)

	loaded, err := loader.Load(config)
	require.Error(t, err)

	// loaded should be nil on error
	assert.Nil(t, loaded)

	// The first provider should have been unregistered (rolled back)
	// so the registry should have no policies
	snapshot := registry.Snapshot()
	if snapshot != nil {

		// Check that the policy from provider-1 was rolled back
		_, ok := snapshot.GetPolicy("policy-1")
		assert.False(t, ok, "expected policy-1 to be rolled back")
	}
}

func TestConfigLoaderLoadHttp(t *testing.T) {
	// Create a test server that returns policies with log target (required for compilation)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := &policyv1.SyncResponse{
			Policies: []*policyv1.Policy{
				{
					Id:      "http-policy-1",
					Name:    "HTTP Policy",
					Enabled: true,
					Target: &policyv1.Policy_Log{
						Log: &policyv1.LogTarget{
							Keep: "all",
						},
					},
				},
			},
			Hash: "test-hash",
		}
		respBytes, _ := proto.Marshal(resp)
		w.Write(respBytes)
	}))
	defer server.Close()

	pollInterval := 0 // Disable polling for test
	config := &Config{
		Providers: []ProviderConfig{
			{
				Type:             "http",
				ID:               "test-http-provider",
				URL:              server.URL,
				PollIntervalSecs: &pollInterval,
				Headers: []Header{
					{Name: "Authorization", Value: "Bearer test-token"},
				},
			},
		},
	}

	registry := NewPolicyRegistry()
	loader := NewConfigLoader(registry).WithServiceMetadata(testServiceMetadata())

	loaded, err := loader.Load(config)
	require.NoError(t, err)
	require.Len(t, loaded, 1)
	assert.Equal(t, "test-http-provider", loaded[0].ID)

	// Verify policies were loaded
	snapshot := registry.Snapshot()
	_, ok := snapshot.GetPolicy("http-policy-1")
	assert.True(t, ok, "expected http-policy-1 to be loaded")

	// Cleanup
	StopAll(loaded)
	UnregisterAll(loaded)
}

func TestConfigLoaderLoadHttpWithContentType(t *testing.T) {
	// Test JSON content type configuration
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify JSON content type was set
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		resp := &policyv1.SyncResponse{Hash: "test"}
		respBytes, _ := json.Marshal(resp)
		w.Header().Set("Content-Type", "application/json")
		w.Write(respBytes)
	}))
	defer server.Close()

	pollInterval := 0
	config := &Config{
		Providers: []ProviderConfig{
			{
				Type:             "http",
				ID:               "test-http-json",
				URL:              server.URL,
				PollIntervalSecs: &pollInterval,
				ContentType:      "json",
			},
		},
	}

	registry := NewPolicyRegistry()
	loader := NewConfigLoader(registry).WithServiceMetadata(testServiceMetadata())

	loaded, err := loader.Load(config)
	require.NoError(t, err)

	StopAll(loaded)
	UnregisterAll(loaded)
}

func TestConfigLoaderLoadGrpc(t *testing.T) {
	// Create a test gRPC server
	server := &configTestPolicyServer{}
	server.setHandler(func(ctx context.Context, req *policyv1.SyncRequest) (*policyv1.SyncResponse, error) {
		return &policyv1.SyncResponse{
			Policies: []*policyv1.Policy{
				{
					Id:      "grpc-policy-1",
					Name:    "gRPC Policy",
					Enabled: true,
					Target: &policyv1.Policy_Log{
						Log: &policyv1.LogTarget{
							Keep: "all",
						},
					},
				},
			},
			Hash: "test-hash",
		}, nil
	})

	addr, cleanup := startTestGrpcServer(t, server)
	defer cleanup()

	pollInterval := 0 // Disable polling for test
	config := &Config{
		Providers: []ProviderConfig{
			{
				Type:             "grpc",
				ID:               "test-grpc-provider",
				URL:              addr,
				PollIntervalSecs: &pollInterval,
				Headers: []Header{
					{Name: "authorization", Value: "Bearer test-token"},
				},
			},
		},
	}

	registry := NewPolicyRegistry()
	loader := NewConfigLoader(registry).WithServiceMetadata(testServiceMetadata())

	loaded, err := loader.Load(config)
	require.NoError(t, err)
	require.Len(t, loaded, 1)
	assert.Equal(t, "test-grpc-provider", loaded[0].ID)

	// Verify policies were loaded
	snapshot := registry.Snapshot()
	_, ok := snapshot.GetPolicy("grpc-policy-1")
	assert.True(t, ok, "expected grpc-policy-1 to be loaded")

	// Cleanup
	StopAll(loaded)
	UnregisterAll(loaded)
}

func TestStopAllAndUnregisterAll(t *testing.T) {
	policiesFile := filepath.Join(t.TempDir(), "policies.json")
	err := os.WriteFile(policiesFile, []byte(`{"policies": []}`), 0644)
	require.NoError(t, err)

	pollInterval := 10
	config := &Config{
		Providers: []ProviderConfig{
			{
				Type:             "file",
				ID:               "test-provider",
				Path:             policiesFile,
				PollIntervalSecs: &pollInterval,
			},
		},
	}

	registry := NewPolicyRegistry()
	loader := NewConfigLoader(registry)

	loaded, err := loader.Load(config)
	require.NoError(t, err)

	// Should not panic
	StopAll(loaded)
	UnregisterAll(loaded)
}

func testServiceMetadata() *ServiceMetadata {
	return &ServiceMetadata{
		ServiceName:       "test-service",
		ServiceNamespace:  "test-namespace",
		ServiceInstanceID: "test-instance-1",
		ServiceVersion:    "1.0.0",
	}
}

func TestConfigLoaderLoadHttpRequiresServiceMetadata(t *testing.T) {
	pollInterval := 0
	config := &Config{
		Providers: []ProviderConfig{
			{
				Type:             "http",
				ID:               "test-http",
				URL:              "http://example.com",
				PollIntervalSecs: &pollInterval,
			},
		},
	}

	registry := NewPolicyRegistry()
	loader := NewConfigLoader(registry)

	_, err := loader.Load(config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "service metadata is required for http providers")
}

func TestConfigLoaderLoadGrpcRequiresServiceMetadata(t *testing.T) {
	pollInterval := 0
	config := &Config{
		Providers: []ProviderConfig{
			{
				Type:             "grpc",
				ID:               "test-grpc",
				URL:              "localhost:50051",
				PollIntervalSecs: &pollInterval,
			},
		},
	}

	registry := NewPolicyRegistry()
	loader := NewConfigLoader(registry)

	_, err := loader.Load(config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "service metadata is required for grpc providers")
}

func TestConfigLoaderLoadValidatesServiceMetadataFields(t *testing.T) {
	pollInterval := 0
	config := &Config{
		Providers: []ProviderConfig{
			{
				Type:             "http",
				ID:               "test-http",
				URL:              "http://example.com",
				PollIntervalSecs: &pollInterval,
			},
		},
	}

	tests := []struct {
		name     string
		metadata *ServiceMetadata
		wantErr  string
	}{
		{
			name:     "missing service_name",
			metadata: &ServiceMetadata{ServiceNamespace: "ns", ServiceInstanceID: "id", ServiceVersion: "v"},
			wantErr:  "service_name is required",
		},
		{
			name:     "missing service_namespace",
			metadata: &ServiceMetadata{ServiceName: "svc", ServiceInstanceID: "id", ServiceVersion: "v"},
			wantErr:  "service_namespace is required",
		},
		{
			name:     "missing service_instance_id",
			metadata: &ServiceMetadata{ServiceName: "svc", ServiceNamespace: "ns", ServiceVersion: "v"},
			wantErr:  "service_instance_id is required",
		},
		{
			name:     "missing service_version",
			metadata: &ServiceMetadata{ServiceName: "svc", ServiceNamespace: "ns", ServiceInstanceID: "id"},
			wantErr:  "service_version is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := NewPolicyRegistry()
			loader := NewConfigLoader(registry).WithServiceMetadata(tt.metadata)

			_, err := loader.Load(config)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestConfigLoaderLoadFileDoesNotRequireServiceMetadata(t *testing.T) {
	policiesFile := filepath.Join(t.TempDir(), "policies.json")
	err := os.WriteFile(policiesFile, []byte(`{"policies": []}`), 0644)
	require.NoError(t, err)

	config := &Config{
		Providers: []ProviderConfig{
			{
				Type: "file",
				ID:   "test-file",
				Path: policiesFile,
			},
		},
	}

	registry := NewPolicyRegistry()
	loader := NewConfigLoader(registry)

	loaded, err := loader.Load(config)
	require.NoError(t, err)
	require.Len(t, loaded, 1)

	StopAll(loaded)
	UnregisterAll(loaded)
}

func TestConfigLoaderWithServiceMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse request and verify metadata is present
		body, _ := io.ReadAll(r.Body)
		var req policyv1.SyncRequest
		proto.Unmarshal(body, &req)

		require.NotNil(t, req.ClientMetadata)
		require.NotNil(t, req.ClientMetadata.ResourceAttributes)

		// Verify required resource attributes
		attrs := make(map[string]string)
		for _, kv := range req.ClientMetadata.ResourceAttributes {
			attrs[kv.Key] = kv.Value.GetStringValue()
		}
		assert.Equal(t, "my-service", attrs["service.name"])
		assert.Equal(t, "production", attrs["service.namespace"])
		assert.Equal(t, "instance-42", attrs["service.instance.id"])
		assert.Equal(t, "2.0.0", attrs["service.version"])
		assert.Equal(t, "extra-val", attrs["extra.attr"])

		// Verify labels
		labels := make(map[string]string)
		for _, kv := range req.ClientMetadata.Labels {
			labels[kv.Key] = kv.Value.GetStringValue()
		}
		assert.Equal(t, "us-east-1", labels["region"])

		resp := &policyv1.SyncResponse{Hash: "test"}
		respBytes, _ := proto.Marshal(resp)
		w.Write(respBytes)
	}))
	defer server.Close()

	pollInterval := 0
	config := &Config{
		Providers: []ProviderConfig{
			{
				Type:             "http",
				ID:               "test-http",
				URL:              server.URL,
				PollIntervalSecs: &pollInterval,
			},
		},
	}

	metadata := &ServiceMetadata{
		ServiceName:       "my-service",
		ServiceNamespace:  "production",
		ServiceInstanceID: "instance-42",
		ServiceVersion:    "2.0.0",
		ResourceAttributes: map[string]string{
			"extra.attr": "extra-val",
		},
		Labels: map[string]string{
			"region": "us-east-1",
		},
	}

	registry := NewPolicyRegistry()
	loader := NewConfigLoader(registry).WithServiceMetadata(metadata)

	loaded, err := loader.Load(config)
	require.NoError(t, err)

	StopAll(loaded)
	UnregisterAll(loaded)
}

func TestParseConfigWithServiceMetadata(t *testing.T) {
	jsonStr := `{
		"service_metadata": {
			"service_name": "my-service",
			"service_namespace": "production",
			"service_instance_id": "instance-001",
			"service_version": "1.0.0",
			"resource_attributes": {
				"cloud.region": "us-east-1"
			},
			"labels": {
				"team": "platform"
			}
		},
		"policy_providers": [
			{
				"type": "file",
				"id": "local",
				"path": "/etc/policies.json"
			}
		]
	}`

	config, err := ParseConfig([]byte(jsonStr))
	require.NoError(t, err)
	require.NotNil(t, config.ServiceMetadata)
	assert.Equal(t, "my-service", config.ServiceMetadata.ServiceName)
	assert.Equal(t, "production", config.ServiceMetadata.ServiceNamespace)
	assert.Equal(t, "instance-001", config.ServiceMetadata.ServiceInstanceID)
	assert.Equal(t, "1.0.0", config.ServiceMetadata.ServiceVersion)
	assert.Equal(t, "us-east-1", config.ServiceMetadata.ResourceAttributes["cloud.region"])
	assert.Equal(t, "platform", config.ServiceMetadata.Labels["team"])
}

func TestConfigLoaderLoadWithConfigServiceMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req policyv1.SyncRequest
		proto.Unmarshal(body, &req)

		require.NotNil(t, req.ClientMetadata)

		attrs := make(map[string]string)
		for _, kv := range req.ClientMetadata.ResourceAttributes {
			attrs[kv.Key] = kv.Value.GetStringValue()
		}
		assert.Equal(t, "config-service", attrs["service.name"])
		assert.Equal(t, "staging", attrs["service.namespace"])
		assert.Equal(t, "config-instance", attrs["service.instance.id"])
		assert.Equal(t, "3.0.0", attrs["service.version"])

		resp := &policyv1.SyncResponse{Hash: "test"}
		respBytes, _ := proto.Marshal(resp)
		w.Write(respBytes)
	}))
	defer server.Close()

	pollInterval := 0
	config := &Config{
		ServiceMetadata: &ServiceMetadataConfig{
			ServiceName:       "config-service",
			ServiceNamespace:  "staging",
			ServiceInstanceID: "config-instance",
			ServiceVersion:    "3.0.0",
		},
		Providers: []ProviderConfig{
			{
				Type:             "http",
				ID:               "test-http",
				URL:              server.URL,
				PollIntervalSecs: &pollInterval,
			},
		},
	}

	registry := NewPolicyRegistry()
	loader := NewConfigLoader(registry)

	loaded, err := loader.Load(config)
	require.NoError(t, err)

	StopAll(loaded)
	UnregisterAll(loaded)
}

func TestConfigLoaderConfigOverridesCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req policyv1.SyncRequest
		proto.Unmarshal(body, &req)

		attrs := make(map[string]string)
		for _, kv := range req.ClientMetadata.ResourceAttributes {
			attrs[kv.Key] = kv.Value.GetStringValue()
		}
		// Config metadata should win over code
		assert.Equal(t, "config-service", attrs["service.name"])
		assert.Equal(t, "staging", attrs["service.namespace"])
		assert.Equal(t, "config-instance", attrs["service.instance.id"])
		assert.Equal(t, "3.0.0", attrs["service.version"])

		resp := &policyv1.SyncResponse{Hash: "test"}
		respBytes, _ := proto.Marshal(resp)
		w.Write(respBytes)
	}))
	defer server.Close()

	pollInterval := 0
	config := &Config{
		ServiceMetadata: &ServiceMetadataConfig{
			ServiceName:       "config-service",
			ServiceNamespace:  "staging",
			ServiceInstanceID: "config-instance",
			ServiceVersion:    "3.0.0",
		},
		Providers: []ProviderConfig{
			{
				Type:             "http",
				ID:               "test-http",
				URL:              server.URL,
				PollIntervalSecs: &pollInterval,
			},
		},
	}

	registry := NewPolicyRegistry()
	loader := NewConfigLoader(registry).WithServiceMetadata(&ServiceMetadata{
		ServiceName:       "programmatic-service",
		ServiceNamespace:  "production",
		ServiceInstanceID: "prog-instance",
		ServiceVersion:    "4.0.0",
	})

	loaded, err := loader.Load(config)
	require.NoError(t, err)

	StopAll(loaded)
	UnregisterAll(loaded)
}

func TestConfigLoaderMergesCodeAndConfigMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req policyv1.SyncRequest
		proto.Unmarshal(body, &req)

		require.NotNil(t, req.ClientMetadata)

		// Verify required resource attributes overridden by config
		attrs := make(map[string]string)
		for _, kv := range req.ClientMetadata.ResourceAttributes {
			attrs[kv.Key] = kv.Value.GetStringValue()
		}
		assert.Equal(t, "config-service", attrs["service.name"])
		assert.Equal(t, "config-ns", attrs["service.namespace"])
		assert.Equal(t, "config-instance", attrs["service.instance.id"])
		assert.Equal(t, "9.9.9", attrs["service.version"])

		// Verify resource attributes are merged (config wins on conflict)
		assert.Equal(t, "us-east-1", attrs["cloud.region"])  // from config
		assert.Equal(t, "code-val", attrs["code.attr"])      // from code
		assert.Equal(t, "config-wins", attrs["shared.attr"]) // config wins on conflict

		// Verify labels are merged (config wins on conflict)
		labels := make(map[string]string)
		for _, kv := range req.ClientMetadata.Labels {
			labels[kv.Key] = kv.Value.GetStringValue()
		}
		assert.Equal(t, "platform", labels["team"])      // from config
		assert.Equal(t, "code-env", labels["env"])       // from code
		assert.Equal(t, "config-wins", labels["shared"]) // config wins on conflict

		resp := &policyv1.SyncResponse{Hash: "test"}
		respBytes, _ := proto.Marshal(resp)
		w.Write(respBytes)
	}))
	defer server.Close()

	pollInterval := 0
	config := &Config{
		ServiceMetadata: &ServiceMetadataConfig{
			ServiceName:       "config-service",
			ServiceNamespace:  "config-ns",
			ServiceInstanceID: "config-instance",
			ServiceVersion:    "9.9.9",
			ResourceAttributes: map[string]string{
				"cloud.region": "us-east-1",
				"shared.attr":  "config-wins",
			},
			Labels: map[string]string{
				"team":   "platform",
				"shared": "config-wins",
			},
		},
		Providers: []ProviderConfig{
			{
				Type:             "http",
				ID:               "test-http",
				URL:              server.URL,
				PollIntervalSecs: &pollInterval,
			},
		},
	}

	registry := NewPolicyRegistry()
	loader := NewConfigLoader(registry).WithServiceMetadata(&ServiceMetadata{
		ServiceName:       "my-service",
		ServiceNamespace:  "production",
		ServiceInstanceID: "instance-1",
		ServiceVersion:    "1.0.0",
		ResourceAttributes: map[string]string{
			"code.attr":   "code-val",
			"shared.attr": "code-loses",
		},
		Labels: map[string]string{
			"env":    "code-env",
			"shared": "code-loses",
		},
	})

	loaded, err := loader.Load(config)
	require.NoError(t, err)

	StopAll(loaded)
	UnregisterAll(loaded)
}

func TestConfigLoaderCodeRequiredFieldsConfigAttrsOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req policyv1.SyncRequest
		proto.Unmarshal(body, &req)

		require.NotNil(t, req.ClientMetadata)

		attrs := make(map[string]string)
		for _, kv := range req.ClientMetadata.ResourceAttributes {
			attrs[kv.Key] = kv.Value.GetStringValue()
		}
		// Required fields from code
		assert.Equal(t, "my-service", attrs["service.name"])
		assert.Equal(t, "production", attrs["service.namespace"])
		assert.Equal(t, "instance-1", attrs["service.instance.id"])
		assert.Equal(t, "1.0.0", attrs["service.version"])
		// Extra attrs from config only
		assert.Equal(t, "us-east-1", attrs["cloud.region"])

		labels := make(map[string]string)
		for _, kv := range req.ClientMetadata.Labels {
			labels[kv.Key] = kv.Value.GetStringValue()
		}
		assert.Equal(t, "platform", labels["team"])

		resp := &policyv1.SyncResponse{Hash: "test"}
		respBytes, _ := proto.Marshal(resp)
		w.Write(respBytes)
	}))
	defer server.Close()

	pollInterval := 0
	config := &Config{
		ServiceMetadata: &ServiceMetadataConfig{
			// Only set optional fields in config — no required fields
			ResourceAttributes: map[string]string{
				"cloud.region": "us-east-1",
			},
			Labels: map[string]string{
				"team": "platform",
			},
		},
		Providers: []ProviderConfig{
			{
				Type:             "http",
				ID:               "test-http",
				URL:              server.URL,
				PollIntervalSecs: &pollInterval,
			},
		},
	}

	registry := NewPolicyRegistry()
	loader := NewConfigLoader(registry).WithServiceMetadata(&ServiceMetadata{
		ServiceName:       "my-service",
		ServiceNamespace:  "production",
		ServiceInstanceID: "instance-1",
		ServiceVersion:    "1.0.0",
	})

	loaded, err := loader.Load(config)
	require.NoError(t, err)

	StopAll(loaded)
	UnregisterAll(loaded)
}
