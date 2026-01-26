package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	"google.golang.org/protobuf/proto"

	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
)

// ContentType specifies the encoding format for HTTP requests.
type ContentType int

const (
	// ContentTypeProtobuf uses protobuf encoding (default, more efficient).
	ContentTypeProtobuf ContentType = iota
	// ContentTypeJSON uses JSON encoding (useful for debugging).
	ContentTypeJSON
)

// String returns the MIME type for the content type.
func (c ContentType) String() string {
	switch c {
	case ContentTypeJSON:
		return "application/json"
	default:
		return "application/x-protobuf"
	}
}

// HttpProviderConfig configures an HTTP policy provider.
type HttpProviderConfig struct {
	// URL is the endpoint to poll for policy updates (required).
	URL string
	// Headers are additional HTTP headers to include in requests.
	Headers map[string]string
	// PollInterval is how often to check for policy updates.
	// Default is 60 seconds.
	PollInterval time.Duration
	// ServiceMetadata identifies this client to the policy server.
	ServiceMetadata *ServiceMetadata
	// ContentType specifies the encoding format (protobuf or JSON).
	// Default is protobuf.
	ContentType ContentType
	// HTTPClient allows providing a custom HTTP client.
	// If nil, http.DefaultClient is used.
	HTTPClient *http.Client
	// OnError is called when a sync error occurs.
	OnError func(error)
	// OnSync is called after a successful sync.
	OnSync func()
}

// HttpProviderOption configures an HttpProvider.
type HttpProviderOption func(*HttpProviderConfig)

// WithHeaders sets additional HTTP headers.
func WithHeaders(headers map[string]string) HttpProviderOption {
	return func(c *HttpProviderConfig) {
		c.Headers = headers
	}
}

// WithHTTPPollInterval sets the polling interval.
func WithHTTPPollInterval(interval time.Duration) HttpProviderOption {
	return func(c *HttpProviderConfig) {
		c.PollInterval = interval
	}
}

// WithServiceMetadata sets the client metadata for sync requests.
func WithServiceMetadata(metadata *ServiceMetadata) HttpProviderOption {
	return func(c *HttpProviderConfig) {
		c.ServiceMetadata = metadata
	}
}

// WithContentType sets the content type for requests.
func WithContentType(ct ContentType) HttpProviderOption {
	return func(c *HttpProviderConfig) {
		c.ContentType = ct
	}
}

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(client *http.Client) HttpProviderOption {
	return func(c *HttpProviderConfig) {
		c.HTTPClient = client
	}
}

// WithHTTPOnError sets an error callback.
func WithHTTPOnError(fn func(error)) HttpProviderOption {
	return func(c *HttpProviderConfig) {
		c.OnError = fn
	}
}

// WithHTTPOnSync sets a sync success callback.
func WithHTTPOnSync(fn func()) HttpProviderOption {
	return func(c *HttpProviderConfig) {
		c.OnSync = fn
	}
}

var _ PolicyProvider = &HttpProvider{}

// HttpProvider loads policies from an HTTP endpoint using the sync protocol.
type HttpProvider struct {
	config HttpProviderConfig
	client *http.Client

	mu             sync.RWMutex
	callback       PolicyCallback
	statsCollector StatsCollector

	// Sync state
	lastHash          string
	lastSyncTimestamp uint64

	// Runtime
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewHttpProvider creates a new HTTP policy provider.
func NewHttpProvider(url string, opts ...HttpProviderOption) *HttpProvider {
	config := HttpProviderConfig{
		URL:          url,
		PollInterval: 60 * time.Second,
		ContentType:  ContentTypeProtobuf,
	}

	for _, opt := range opts {
		opt(&config)
	}

	client := config.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	return &HttpProvider{
		config: config,
		client: client,
	}
}

// Load performs an immediate sync and returns the current policies.
func (p *HttpProvider) Load() ([]*policyv1.Policy, error) {
	return p.sync(context.Background(), true)
}

// Subscribe registers a callback for policy changes and starts polling.
func (p *HttpProvider) Subscribe(callback PolicyCallback) error {
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
func (p *HttpProvider) SetStatsCollector(collector StatsCollector) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.statsCollector = collector
}

// Stop stops the polling loop.
func (p *HttpProvider) Stop() {
	p.mu.Lock()
	if p.cancel != nil {
		p.cancel()
	}
	p.mu.Unlock()

	p.wg.Wait()
}

func (p *HttpProvider) startPolling() {
	ctx, cancel := context.WithCancel(context.Background())

	p.mu.Lock()
	p.cancel = cancel
	p.mu.Unlock()

	p.wg.Add(1)
	go p.pollLoop(ctx)
}

func (p *HttpProvider) pollLoop(ctx context.Context) {
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

func (p *HttpProvider) doSync(ctx context.Context) {
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

func (p *HttpProvider) sync(ctx context.Context, fullSync bool) ([]*policyv1.Policy, error) {
	req := p.buildSyncRequest(fullSync)

	// Encode request
	var body []byte
	var err error
	contentType := p.config.ContentType.String()

	switch p.config.ContentType {
	case ContentTypeJSON:
		body, err = json.Marshal(syncRequestToMap(req))
		if err != nil {
			return nil, WrapError(ErrProvider, "failed to encode request", err)
		}
	default:
		body, err = proto.Marshal(req)
		if err != nil {
			return nil, WrapError(ErrProvider, "failed to encode request", err)
		}
	}

	// Build HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.config.URL, bytes.NewReader(body))
	if err != nil {
		return nil, WrapError(ErrProvider, "failed to create request", err)
	}

	httpReq.Header.Set("Content-Type", contentType)
	httpReq.Header.Set("Accept", contentType)

	for k, v := range p.config.Headers {
		httpReq.Header.Set(k, v)
	}

	// Send request
	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, WrapError(ErrProvider, "HTTP request failed", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, NewError(ErrProvider, fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(bodyBytes)))
	}

	// Read response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, WrapError(ErrProvider, "failed to read response", err)
	}

	// Decode response
	var syncResp policyv1.SyncResponse
	switch p.config.ContentType {
	case ContentTypeJSON:
		if err := json.Unmarshal(respBody, &syncResp); err != nil {
			return nil, WrapError(ErrProvider, "failed to decode JSON response", err)
		}
	default:
		if err := proto.Unmarshal(respBody, &syncResp); err != nil {
			return nil, WrapError(ErrProvider, "failed to decode protobuf response", err)
		}
	}

	// Check for errors
	if syncResp.GetErrorMessage() != "" {
		return nil, NewError(ErrProvider, fmt.Sprintf("sync error: %s", syncResp.GetErrorMessage()))
	}

	// Update state
	p.mu.Lock()
	if syncResp.GetHash() != "" {
		p.lastHash = syncResp.GetHash()
	}
	if syncResp.GetSyncTimestampUnixNano() > 0 {
		p.lastSyncTimestamp = syncResp.GetSyncTimestampUnixNano()
	}
	p.mu.Unlock()

	return syncResp.GetPolicies(), nil
}

func (p *HttpProvider) buildSyncRequest(fullSync bool) *policyv1.SyncRequest {
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

// collectPolicyStatuses converts stats snapshots to proto PolicySyncStatus.
func collectPolicyStatuses(collector StatsCollector) []*policyv1.PolicySyncStatus {
	if collector == nil {
		return nil
	}

	snapshots := collector()
	statuses := make([]*policyv1.PolicySyncStatus, 0, len(snapshots))

	for _, snap := range snapshots {
		statuses = append(statuses, &policyv1.PolicySyncStatus{
			Id:          snap.PolicyID,
			MatchHits:   int64(snap.Hits),
			MatchMisses: int64(snap.Drops + snap.Samples + snap.RateLimited),
		})
	}

	return statuses
}

// syncRequestToMap converts a SyncRequest to a map for JSON encoding.
// This is needed because protobuf JSON encoding uses different field names.
func syncRequestToMap(req *policyv1.SyncRequest) map[string]any {
	m := map[string]any{
		"full_sync":                     req.GetFullSync(),
		"last_sync_timestamp_unix_nano": req.GetLastSyncTimestampUnixNano(),
		"last_successful_hash":          req.GetLastSuccessfulHash(),
	}

	if req.GetClientMetadata() != nil {
		cm := req.GetClientMetadata()
		cmMap := map[string]any{}

		if len(cm.GetSupportedPolicyStages()) > 0 {
			stages := make([]int32, len(cm.GetSupportedPolicyStages()))
			for i, s := range cm.GetSupportedPolicyStages() {
				stages[i] = int32(s)
			}
			cmMap["supported_policy_stages"] = stages
		}

		if len(cm.GetLabels()) > 0 {
			cmMap["labels"] = keyValuesToMaps(cm.GetLabels())
		}

		if len(cm.GetResourceAttributes()) > 0 {
			cmMap["resource_attributes"] = keyValuesToMaps(cm.GetResourceAttributes())
		}

		m["client_metadata"] = cmMap
	}

	if len(req.GetPolicyStatuses()) > 0 {
		statuses := make([]map[string]any, len(req.GetPolicyStatuses()))
		for i, s := range req.GetPolicyStatuses() {
			statuses[i] = map[string]any{
				"id":           s.GetId(),
				"match_hits":   s.GetMatchHits(),
				"match_misses": s.GetMatchMisses(),
			}
		}
		m["policy_statuses"] = statuses
	}

	return m
}

func keyValuesToMaps(kvs []*commonv1.KeyValue) []map[string]any {
	result := make([]map[string]any, len(kvs))
	for i, kv := range kvs {
		m := map[string]any{"key": kv.GetKey()}
		if v := kv.GetValue(); v != nil {
			switch val := v.GetValue().(type) {
			case *commonv1.AnyValue_StringValue:
				m["value"] = map[string]any{"stringValue": val.StringValue}
			case *commonv1.AnyValue_IntValue:
				m["value"] = map[string]any{"intValue": val.IntValue}
			case *commonv1.AnyValue_BoolValue:
				m["value"] = map[string]any{"boolValue": val.BoolValue}
			case *commonv1.AnyValue_DoubleValue:
				m["value"] = map[string]any{"doubleValue": val.DoubleValue}
			}
		}
		result[i] = m
	}
	return result
}
