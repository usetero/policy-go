package policy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	policyv1 "github.com/usetero/policy-go/internal/proto/tero/policy/v1"
	"google.golang.org/protobuf/proto"
)

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
	loader := NewConfigLoader(registry)

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
	loader := NewConfigLoader(registry)

	loaded, err := loader.Load(config)
	require.NoError(t, err)

	StopAll(loaded)
	UnregisterAll(loaded)
}

func TestConfigLoaderLoadGrpcNotImplemented(t *testing.T) {
	config := &Config{
		Providers: []ProviderConfig{
			{
				Type: "grpc",
				ID:   "test-provider",
				URL:  "grpc://example.com:443",
			},
		},
	}

	registry := NewPolicyRegistry()
	loader := NewConfigLoader(registry)

	_, err := loader.Load(config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not yet implemented")
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
