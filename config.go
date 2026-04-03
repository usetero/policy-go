package policy

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"time"
)

// Config represents the root configuration for policy providers.
type Config struct {
	Providers       []ProviderConfig       `json:"policy_providers" mapstructure:"policy_providers"`
	ServiceMetadata *ServiceMetadataConfig `json:"service_metadata,omitempty" mapstructure:"service_metadata"`
}

// ServiceMetadataConfig is the JSON/mapstructure-friendly representation of ServiceMetadata.
type ServiceMetadataConfig struct {
	ServiceName        string            `json:"service_name" mapstructure:"service_name"`
	ServiceNamespace   string            `json:"service_namespace" mapstructure:"service_namespace"`
	ServiceInstanceID  string            `json:"service_instance_id" mapstructure:"service_instance_id"`
	ServiceVersion     string            `json:"service_version" mapstructure:"service_version"`
	ResourceAttributes map[string]string `json:"resource_attributes,omitempty" mapstructure:"resource_attributes"`
	Labels             map[string]string `json:"labels,omitempty" mapstructure:"labels"`
}

// ToServiceMetadata converts a ServiceMetadataConfig to a ServiceMetadata.
func (c *ServiceMetadataConfig) ToServiceMetadata() *ServiceMetadata {
	if c == nil {
		return nil
	}
	return &ServiceMetadata{
		ServiceName:        c.ServiceName,
		ServiceNamespace:   c.ServiceNamespace,
		ServiceInstanceID:  c.ServiceInstanceID,
		ServiceVersion:     c.ServiceVersion,
		ResourceAttributes: c.ResourceAttributes,
		Labels:             c.Labels,
	}
}

// ProviderConfig represents a single provider configuration.
// The Type field determines which provider to instantiate.
type ProviderConfig struct {
	Type string `json:"type" mapstructure:"type"`
	ID   string `json:"id" mapstructure:"id"`

	// File provider options
	Path             string `json:"path,omitempty" mapstructure:"path"`
	PollIntervalSecs *int   `json:"poll_interval_secs,omitempty" mapstructure:"poll_interval_secs"`

	// HTTP provider options (for future use)
	URL         string   `json:"url,omitempty" mapstructure:"url"`
	Headers     []Header `json:"headers,omitempty" mapstructure:"headers"`
	ContentType string   `json:"content_type,omitempty" mapstructure:"content_type"`
}

// Header represents an HTTP header for provider configuration.
type Header struct {
	Name  string `json:"name" mapstructure:"name"`
	Value string `json:"value" mapstructure:"value"`
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
	registry        *PolicyRegistry
	onError         func(error)
	serviceMetadata *ServiceMetadata
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

// WithServiceMetadata sets the service metadata for HTTP and gRPC providers.
// Service metadata is required when loading HTTP or gRPC providers.
func (l *ConfigLoader) WithServiceMetadata(metadata *ServiceMetadata) *ConfigLoader {
	l.serviceMetadata = metadata
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
// Service metadata is required when the config contains HTTP or gRPC providers.
// It can be set via WithServiceMetadata on the loader (code defaults) or via the
// service_metadata field in the Config. When both are provided, they are merged
// with config values taking precedence over code, allowing users to override defaults.
func (l *ConfigLoader) Load(config *Config) ([]LoadedProvider, error) {
	// Resolve service metadata: merge code and config, config values take precedence.
	metadata := mergeServiceMetadata(l.serviceMetadata, config.ServiceMetadata)

	// Validate that service metadata is set and complete if any HTTP or gRPC providers are configured.
	for _, pc := range config.Providers {
		if pc.Type == "http" || pc.Type == "grpc" {
			if metadata == nil {
				return nil, fmt.Errorf("service metadata is required for %s providers; set it in config or use WithServiceMetadata", pc.Type)
			}
			if err := metadata.Validate(); err != nil {
				return nil, fmt.Errorf("invalid service metadata: %w", err)
			}
			break
		}
	}

	// Use resolved metadata for provider creation.
	l.serviceMetadata = metadata

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

// mergeServiceMetadata merges programmatic and config-based service metadata.
// Config values take precedence over code, allowing users to override defaults.
// Maps (ResourceAttributes, Labels) are merged, with config values winning on key conflicts.
// If both are nil, returns nil.
func mergeServiceMetadata(code *ServiceMetadata, cfg *ServiceMetadataConfig) *ServiceMetadata {
	if code == nil && cfg == nil {
		return nil
	}
	if cfg == nil {
		return code
	}
	if code == nil {
		return cfg.ToServiceMetadata()
	}

	merged := *code

	// Merge resource attributes: code values first, then config values overwrite.
	if len(cfg.ResourceAttributes) > 0 || len(code.ResourceAttributes) > 0 {
		attrs := make(map[string]string)
		maps.Copy(attrs, code.ResourceAttributes)
		maps.Copy(attrs, cfg.ResourceAttributes)
		merged.ResourceAttributes = attrs
	}

	// Merge labels: code values first, then config values overwrite.
	if len(cfg.Labels) > 0 || len(code.Labels) > 0 {
		labels := make(map[string]string)
		maps.Copy(labels, code.Labels)
		maps.Copy(labels, cfg.Labels)
		merged.Labels = labels
	}

	// Config scalar fields override code when set.
	if cfg.ServiceName != "" {
		merged.ServiceName = cfg.ServiceName
	}
	if cfg.ServiceNamespace != "" {
		merged.ServiceNamespace = cfg.ServiceNamespace
	}
	if cfg.ServiceInstanceID != "" {
		merged.ServiceInstanceID = cfg.ServiceInstanceID
	}
	if cfg.ServiceVersion != "" {
		merged.ServiceVersion = cfg.ServiceVersion
	}

	return &merged
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

	if l.serviceMetadata != nil {
		opts = append(opts, WithServiceMetadata(l.serviceMetadata))
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

	if l.serviceMetadata != nil {
		opts = append(opts, WithGrpcServiceMetadata(l.serviceMetadata))
	}

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
