package policy

import (
	"context"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
)

// GrpcProviderConfig configures a gRPC policy provider.
type GrpcProviderConfig struct {
	// Target is the gRPC server address (required).
	// Format: "host:port" or "dns:///host:port"
	Target string
	// Headers are additional gRPC metadata headers to include in requests.
	Headers map[string]string
	// PollInterval is how often to check for policy updates.
	// Default is 60 seconds.
	PollInterval time.Duration
	// ServiceMetadata identifies this client to the policy server.
	ServiceMetadata *ServiceMetadata
	// DialOptions are additional gRPC dial options.
	DialOptions []grpc.DialOption
	// UseTLS enables TLS for the connection.
	// If false, insecure credentials are used.
	UseTLS bool
	// TLSCredentials are custom TLS credentials.
	// If nil and UseTLS is true, system credentials are used.
	TLSCredentials credentials.TransportCredentials
	// OnError is called when a sync error occurs.
	OnError func(error)
	// OnSync is called after a successful sync.
	OnSync func()
}

// GrpcProviderOption configures a GrpcProvider.
type GrpcProviderOption func(*GrpcProviderConfig)

// WithGrpcHeaders sets additional gRPC metadata headers.
func WithGrpcHeaders(headers map[string]string) GrpcProviderOption {
	return func(c *GrpcProviderConfig) {
		c.Headers = headers
	}
}

// WithGrpcPollInterval sets the polling interval.
func WithGrpcPollInterval(interval time.Duration) GrpcProviderOption {
	return func(c *GrpcProviderConfig) {
		c.PollInterval = interval
	}
}

// WithGrpcServiceMetadata sets the client metadata for sync requests.
func WithGrpcServiceMetadata(metadata *ServiceMetadata) GrpcProviderOption {
	return func(c *GrpcProviderConfig) {
		c.ServiceMetadata = metadata
	}
}

// WithGrpcDialOptions sets additional gRPC dial options.
func WithGrpcDialOptions(opts ...grpc.DialOption) GrpcProviderOption {
	return func(c *GrpcProviderConfig) {
		c.DialOptions = append(c.DialOptions, opts...)
	}
}

// WithGrpcTLS enables TLS for the connection.
func WithGrpcTLS(creds credentials.TransportCredentials) GrpcProviderOption {
	return func(c *GrpcProviderConfig) {
		c.UseTLS = true
		c.TLSCredentials = creds
	}
}

// WithGrpcInsecure disables TLS (for testing or internal networks).
func WithGrpcInsecure() GrpcProviderOption {
	return func(c *GrpcProviderConfig) {
		c.UseTLS = false
	}
}

// WithGrpcOnError sets an error callback.
func WithGrpcOnError(fn func(error)) GrpcProviderOption {
	return func(c *GrpcProviderConfig) {
		c.OnError = fn
	}
}

// WithGrpcOnSync sets a sync success callback.
func WithGrpcOnSync(fn func()) GrpcProviderOption {
	return func(c *GrpcProviderConfig) {
		c.OnSync = fn
	}
}

// GrpcProvider loads policies from a gRPC endpoint using the PolicyService.Sync RPC.
type GrpcProvider struct {
	config GrpcProviderConfig

	mu             sync.RWMutex
	callback       PolicyCallback
	statsCollector StatsCollector
	conn           *grpc.ClientConn

	// Sync state
	lastHash          string
	lastSyncTimestamp uint64

	// Runtime
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

var _ PolicyProvider = &GrpcProvider{}

// NewGrpcProvider creates a new gRPC policy provider.
func NewGrpcProvider(target string, opts ...GrpcProviderOption) *GrpcProvider {
	config := GrpcProviderConfig{
		Target:       target,
		PollInterval: 60 * time.Second,
		UseTLS:       true, // Default to TLS
	}

	for _, opt := range opts {
		opt(&config)
	}

	return &GrpcProvider{
		config: config,
	}
}

// Load performs an immediate sync and returns the current policies.
func (p *GrpcProvider) Load() ([]*policyv1.Policy, error) {
	return p.sync(context.Background(), true)
}

// Subscribe registers a callback for policy changes and starts polling.
func (p *GrpcProvider) Subscribe(callback PolicyCallback) error {
	p.mu.Lock()
	p.callback = callback
	p.mu.Unlock()

	// Initial load
	policies, err := p.Load()
	if err != nil {
		return err
	}

	callback(policies)

	// Start polling
	if p.config.PollInterval > 0 {
		p.startPolling()
	}

	return nil
}

// SetStatsCollector registers a stats collector for sync requests.
func (p *GrpcProvider) SetStatsCollector(collector StatsCollector) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.statsCollector = collector
}

// Stop stops the polling loop and closes the connection.
func (p *GrpcProvider) Stop() {
	p.mu.Lock()
	if p.cancel != nil {
		p.cancel()
	}
	p.mu.Unlock()

	p.wg.Wait()

	p.mu.Lock()
	if p.conn != nil {
		p.conn.Close()
		p.conn = nil
	}
	p.mu.Unlock()
}

func (p *GrpcProvider) startPolling() {
	ctx, cancel := context.WithCancel(context.Background())

	p.mu.Lock()
	p.cancel = cancel
	p.mu.Unlock()

	p.wg.Add(1)
	go p.pollLoop(ctx)
}

func (p *GrpcProvider) pollLoop(ctx context.Context) {
	defer p.wg.Done()

	ticker := time.NewTicker(p.config.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.doSync(ctx)
		}
	}
}

func (p *GrpcProvider) doSync(ctx context.Context) {
	p.mu.RLock()
	lastHash := p.lastHash
	callback := p.callback
	p.mu.RUnlock()

	policies, err := p.sync(ctx, false)
	if err != nil {
		if p.config.OnError != nil {
			p.config.OnError(err)
		}
		return
	}

	// Check if policies changed
	p.mu.RLock()
	newHash := p.lastHash
	p.mu.RUnlock()

	if newHash != lastHash && callback != nil {
		callback(policies)
	}

	if p.config.OnSync != nil {
		p.config.OnSync()
	}
}

func (p *GrpcProvider) getOrCreateConn() (*grpc.ClientConn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.conn != nil {
		return p.conn, nil
	}

	// Build dial options
	opts := make([]grpc.DialOption, 0, len(p.config.DialOptions)+1)

	if p.config.UseTLS {
		if p.config.TLSCredentials != nil {
			opts = append(opts, grpc.WithTransportCredentials(p.config.TLSCredentials))
		} else {
			// Use system TLS credentials
			opts = append(opts, grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(nil, "")))
		}
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	opts = append(opts, p.config.DialOptions...)

	conn, err := grpc.NewClient(p.config.Target, opts...)
	if err != nil {
		return nil, WrapError(ErrProvider, "failed to create gRPC client", err)
	}

	p.conn = conn
	return conn, nil
}

func (p *GrpcProvider) sync(ctx context.Context, fullSync bool) ([]*policyv1.Policy, error) {
	conn, err := p.getOrCreateConn()
	if err != nil {
		return nil, err
	}

	client := policyv1.NewPolicyServiceClient(conn)

	req := p.buildSyncRequest(fullSync)

	// Add metadata headers
	if len(p.config.Headers) > 0 {
		md := metadata.New(p.config.Headers)
		ctx = metadata.NewOutgoingContext(ctx, md)
	}

	resp, err := client.Sync(ctx, req)
	if err != nil {
		return nil, WrapError(ErrProvider, "gRPC sync failed", err)
	}

	// Check for errors
	if resp.GetErrorMessage() != "" {
		return nil, NewError(ErrProvider, "sync error: "+resp.GetErrorMessage())
	}

	// Update state
	p.mu.Lock()
	if resp.GetHash() != "" {
		p.lastHash = resp.GetHash()
	}
	if resp.GetSyncTimestampUnixNano() > 0 {
		p.lastSyncTimestamp = resp.GetSyncTimestampUnixNano()
	}
	p.mu.Unlock()

	return resp.GetPolicies(), nil
}

func (p *GrpcProvider) buildSyncRequest(fullSync bool) *policyv1.SyncRequest {
	p.mu.RLock()
	lastHash := p.lastHash
	lastTimestamp := p.lastSyncTimestamp
	statsCollector := p.statsCollector
	p.mu.RUnlock()

	req := &policyv1.SyncRequest{
		FullSync:                  fullSync,
		LastSuccessfulHash:        lastHash,
		LastSyncTimestampUnixNano: lastTimestamp,
	}

	if p.config.ServiceMetadata != nil {
		req.ClientMetadata = p.config.ServiceMetadata.ToProto()
	}

	if statsCollector != nil {
		req.PolicyStatuses = collectPolicyStatuses(statsCollector)
	}

	return req
}
