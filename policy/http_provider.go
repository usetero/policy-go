package policy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime"
	"net/http"
	"sync"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
)

// ContentType specifies the encoding format for HTTP requests.
// Requests are sent in the configured format; responses are decoded based
// on the server's Content-Type header, so a JSON request can accept a
// protobuf response (or vice versa) without reconfiguring the provider.
type ContentType int

const (
	// ContentTypeProtobuf uses protobuf encoding (more compact on the wire).
	ContentTypeProtobuf ContentType = iota
	// ContentTypeJSON uses JSON encoding (default for new providers;
	// spec-compliant proto3 JSON, easier to debug).
	ContentTypeJSON
)

const (
	mimeJSON     = "application/json"
	mimeProtobuf = "application/x-protobuf"
	// mimeProtobufAlt is the alternate spelling some servers use.
	mimeProtobufAlt = "application/protobuf"
)

// String returns the MIME type for the content type.
func (c ContentType) String() string {
	switch c {
	case ContentTypeJSON:
		return mimeJSON
	default:
		return mimeProtobuf
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
	// ContentType specifies the encoding format for outgoing requests.
	// Default is JSON. The provider always decodes responses based on the
	// server's Content-Type header regardless of this setting.
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

// NewHttpProvider creates a new HTTP policy provider. Requests default to
// JSON; the server's response Content-Type is honored, so a JSON-sending
// client will still decode a protobuf response correctly.
func NewHttpProvider(url string, opts ...HttpProviderOption) *HttpProvider {
	config := HttpProviderConfig{
		URL:          url,
		PollInterval: 60 * time.Second,
		ContentType:  ContentTypeJSON,
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

	// Encode request body using the configured content type.
	var body []byte
	var err error
	reqContentType := p.config.ContentType.String()

	switch p.config.ContentType {
	case ContentTypeJSON:
		body, err = protojson.Marshal(req)
	default:
		body, err = proto.Marshal(req)
	}
	if err != nil {
		return nil, WrapError(ErrProvider, "failed to encode request", err)
	}

	// Build HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.config.URL, bytes.NewReader(body))
	if err != nil {
		return nil, WrapError(ErrProvider, "failed to create request", err)
	}

	httpReq.Header.Set("Content-Type", reqContentType)
	// Advertise both formats so the server can pick either. The configured
	// format is listed first as a soft preference.
	if p.config.ContentType == ContentTypeJSON {
		httpReq.Header.Set("Accept", mimeJSON+", "+mimeProtobuf)
	} else {
		httpReq.Header.Set("Accept", mimeProtobuf+", "+mimeJSON)
	}

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

	// Decode response based on the server's Content-Type header, not on what
	// we sent — a JSON request can be answered with a protobuf response.
	syncResp, err := decodeSyncResponse(respBody, resp.Header.Get("Content-Type"), p.config.ContentType)
	if err != nil {
		return nil, err
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

// decodeSyncResponse decodes a sync response body according to the server's
// Content-Type header. Recognized types: application/json,
// application/x-protobuf, application/protobuf. If the header is missing or
// unparseable, falls back to fallback (the format the client sent), since a
// symmetric server is the most likely answer. An unrecognized non-empty type
// is an error rather than silent guessing.
func decodeSyncResponse(body []byte, contentType string, fallback ContentType) (*policyv1.SyncResponse, error) {
	var mediaType string
	if contentType != "" {
		if mt, _, err := mime.ParseMediaType(contentType); err == nil {
			mediaType = mt
		}
	}

	var syncResp policyv1.SyncResponse
	switch mediaType {
	case mimeProtobuf, mimeProtobufAlt:
		if err := proto.Unmarshal(body, &syncResp); err != nil {
			return nil, WrapError(ErrProvider, "failed to decode protobuf response", err)
		}
	case mimeJSON:
		if err := protojson.Unmarshal(body, &syncResp); err != nil {
			return nil, WrapError(ErrProvider, "failed to decode JSON response", err)
		}
	case "":
		// Server didn't tell us what it sent — assume it mirrored our request.
		if fallback == ContentTypeJSON {
			if err := protojson.Unmarshal(body, &syncResp); err != nil {
				return nil, WrapError(ErrProvider, "failed to decode response (no Content-Type, fell back to JSON)", err)
			}
		} else {
			if err := proto.Unmarshal(body, &syncResp); err != nil {
				return nil, WrapError(ErrProvider, "failed to decode response (no Content-Type, fell back to protobuf)", err)
			}
		}
	default:
		return nil, NewError(ErrProvider, fmt.Sprintf("unsupported response Content-Type %q", contentType))
	}
	return &syncResp, nil
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
		status := &policyv1.PolicySyncStatus{
			Id:          snap.PolicyID,
			MatchHits:   int64(snap.MatchHits),
			MatchMisses: int64(snap.MatchMisses),
			Errors:      snap.Errors,
		}
		if snap.RemoveHits > 0 || snap.RemoveMisses > 0 {
			status.Remove = &policyv1.TransformStageStatus{Hits: int64(snap.RemoveHits), Misses: int64(snap.RemoveMisses)}
		}
		if snap.RedactHits > 0 || snap.RedactMisses > 0 {
			status.Redact = &policyv1.TransformStageStatus{Hits: int64(snap.RedactHits), Misses: int64(snap.RedactMisses)}
		}
		if snap.RenameHits > 0 || snap.RenameMisses > 0 {
			status.Rename = &policyv1.TransformStageStatus{Hits: int64(snap.RenameHits), Misses: int64(snap.RenameMisses)}
		}
		if snap.AddHits > 0 || snap.AddMisses > 0 {
			status.Add = &policyv1.TransformStageStatus{Hits: int64(snap.AddHits), Misses: int64(snap.AddMisses)}
		}
		statuses = append(statuses, status)
	}

	return statuses
}
