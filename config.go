package policy

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

// Config represents the root configuration for policy providers.
type Config struct {
	Providers []ProviderConfig `json:"policy_providers"`
}

// ProviderConfig represents a single provider configuration.
// The Type field determines which provider to instantiate.
type ProviderConfig struct {
	Type string `json:"type"`
	ID   string `json:"id"`

	// File provider options
	Path             string `json:"path,omitempty"`
	PollIntervalSecs *int   `json:"poll_interval_secs,omitempty"`

	// HTTP provider options (for future use)
	URL         string   `json:"url,omitempty"`
	Headers     []Header `json:"headers,omitempty"`
	ContentType string   `json:"content_type,omitempty"`
}

// Header represents an HTTP header for provider configuration.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// LoadConfig loads a configuration from a JSON file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	return ParseConfig(data)
}

// ParseConfig parses a configuration from JSON bytes.
func ParseConfig(data []byte) (*Config, error) {
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Validate
	for i, p := range config.Providers {
		if err := p.Validate(); err != nil {
			return nil, fmt.Errorf("provider %d: %w", i, err)
		}
	}

	return &config, nil
}

// ParseConfigReader parses a configuration from a reader.
func ParseConfigReader(r io.Reader) (*Config, error) {
	var config Config
	if err := json.NewDecoder(r).Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Validate
	for i, p := range config.Providers {
		if err := p.Validate(); err != nil {
			return nil, fmt.Errorf("provider %d: %w", i, err)
		}
	}

	return &config, nil
}

// Validate checks that the provider configuration is valid.
func (p *ProviderConfig) Validate() error {
	if p.ID == "" {
		return fmt.Errorf("id is required")
	}

	switch p.Type {
	case "file":
		if p.Path == "" {
			return fmt.Errorf("path is required for file provider")
		}
	case "http":
		if p.URL == "" {
			return fmt.Errorf("url is required for http provider")
		}
	case "grpc":
		if p.URL == "" {
			return fmt.Errorf("url is required for grpc provider")
		}
	case "":
		return fmt.Errorf("type is required")
	default:
		return fmt.Errorf("unknown provider type: %s", p.Type)
	}

	return nil
}

// PollInterval returns the poll interval as a time.Duration.
// Returns 0 if not configured.
func (p *ProviderConfig) PollInterval() time.Duration {
	if p.PollIntervalSecs == nil {
		return 0
	}
	return time.Duration(*p.PollIntervalSecs) * time.Second
}

// ConfigLoader creates providers from a configuration.
type ConfigLoader struct {
	registry *PolicyRegistry
	onError  func(error)
}

// NewConfigLoader creates a new ConfigLoader.
func NewConfigLoader(registry *PolicyRegistry) *ConfigLoader {
	return &ConfigLoader{
		registry: registry,
	}
}

// WithOnError sets a callback for provider errors.
// This callback is passed to providers that support it.
func (l *ConfigLoader) WithOnError(fn func(error)) *ConfigLoader {
	l.onError = fn
	return l
}

// LoadedProvider holds information about a loaded provider.
type LoadedProvider struct {
	ID       string
	Handle   ProviderHandle
	Provider PolicyProvider
}

// Load creates and registers providers from the configuration.
// Returns the loaded providers in the order they appear in the config.
func (l *ConfigLoader) Load(config *Config) ([]LoadedProvider, error) {
	loaded := make([]LoadedProvider, 0, len(config.Providers))

	for i, pc := range config.Providers {
		provider, err := l.createProvider(pc)
		if err != nil {
			// Unregister any providers we've already registered
			for _, lp := range loaded {
				lp.Handle.Unregister()
			}
			return nil, fmt.Errorf("provider %d (%s): %w", i, pc.ID, err)
		}

		handle, err := l.registry.Register(provider)
		if err != nil {
			// Stop the provider if it was started
			if stopper, ok := provider.(interface{ Stop() }); ok {
				stopper.Stop()
			}
			// Unregister any providers we've already registered
			for _, lp := range loaded {
				lp.Handle.Unregister()
			}
			return nil, fmt.Errorf("provider %d (%s): failed to register: %w", i, pc.ID, err)
		}

		loaded = append(loaded, LoadedProvider{
			ID:       pc.ID,
			Handle:   handle,
			Provider: provider,
		})
	}

	return loaded, nil
}

func (l *ConfigLoader) createProvider(pc ProviderConfig) (PolicyProvider, error) {
	switch pc.Type {
	case "file":
		return l.createFileProvider(pc), nil
	case "http":
		return l.createHTTPProvider(pc), nil
	case "grpc":
		return l.createGrpcProvider(pc), nil
	default:
		return nil, fmt.Errorf("unknown provider type: %s", pc.Type)
	}
}

func (l *ConfigLoader) createFileProvider(pc ProviderConfig) *FileProvider {
	opts := []FileProviderOption{}

	if pc.PollIntervalSecs != nil && *pc.PollIntervalSecs > 0 {
		opts = append(opts, WithPollInterval(time.Duration(*pc.PollIntervalSecs)*time.Second))
	}

	if l.onError != nil {
		opts = append(opts, WithOnError(l.onError))
	}

	return NewFileProvider(pc.Path, opts...)
}

func (l *ConfigLoader) createHTTPProvider(pc ProviderConfig) *HttpProvider {
	opts := []HttpProviderOption{}

	if pc.PollIntervalSecs != nil && *pc.PollIntervalSecs > 0 {
		opts = append(opts, WithHTTPPollInterval(time.Duration(*pc.PollIntervalSecs)*time.Second))
	}

	if len(pc.Headers) > 0 {
		headers := make(map[string]string, len(pc.Headers))
		for _, h := range pc.Headers {
			headers[h.Name] = h.Value
		}
		opts = append(opts, WithHeaders(headers))
	}

	if pc.ContentType != "" {
		switch pc.ContentType {
		case "json", "application/json":
			opts = append(opts, WithContentType(ContentTypeJSON))
		default:
			// Default to protobuf
			opts = append(opts, WithContentType(ContentTypeProtobuf))
		}
	}

	if l.onError != nil {
		opts = append(opts, WithHTTPOnError(l.onError))
	}

	return NewHttpProvider(pc.URL, opts...)
}

func (l *ConfigLoader) createGrpcProvider(pc ProviderConfig) *GrpcProvider {
	opts := []GrpcProviderOption{}

	if pc.PollIntervalSecs != nil && *pc.PollIntervalSecs > 0 {
		opts = append(opts, WithGrpcPollInterval(time.Duration(*pc.PollIntervalSecs)*time.Second))
	}

	if len(pc.Headers) > 0 {
		headers := make(map[string]string, len(pc.Headers))
		for _, h := range pc.Headers {
			headers[h.Name] = h.Value
		}
		opts = append(opts, WithGrpcHeaders(headers))
	}

	// Default to insecure for now (TLS configuration can be added later)
	opts = append(opts, WithGrpcInsecure())

	if l.onError != nil {
		opts = append(opts, WithGrpcOnError(l.onError))
	}

	return NewGrpcProvider(pc.URL, opts...)
}

// StopAll stops all providers that support stopping.
func StopAll(providers []LoadedProvider) {
	for _, lp := range providers {
		if stopper, ok := lp.Provider.(interface{ Stop() }); ok {
			stopper.Stop()
		}
	}
}

// UnregisterAll unregisters all providers.
func UnregisterAll(providers []LoadedProvider) {
	for _, lp := range providers {
		lp.Handle.Unregister()
	}
}
