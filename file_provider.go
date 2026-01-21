package policy

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/usetero/policy-go/internal/jsonpolicy"
)

// FileProviderOption configures a FileProvider.
type FileProviderOption func(*FileProvider)

// WithPollInterval sets the polling interval for file changes.
// When set, the provider will periodically check if the file has been modified
// and reload policies if changes are detected.
// Default is 0, which disables polling.
func WithPollInterval(interval time.Duration) FileProviderOption {
	return func(f *FileProvider) {
		f.pollInterval = interval
	}
}

// WithOnError sets a callback that is invoked when an error occurs during polling.
// This is useful for logging or monitoring reload failures.
func WithOnError(fn func(error)) FileProviderOption {
	return func(f *FileProvider) {
		f.onError = fn
	}
}

// WithOnReload sets a callback that is invoked after a successful reload.
// This is useful for logging or monitoring successful reloads.
func WithOnReload(fn func()) FileProviderOption {
	return func(f *FileProvider) {
		f.onReload = fn
	}
}

// FileProvider loads policies from a JSON file.
// It implements the PolicyProvider interface.
type FileProvider struct {
	path           string
	parser         *jsonpolicy.Parser
	mu             sync.RWMutex
	statsCollector StatsCollector

	// Polling configuration
	pollInterval time.Duration
	onError      func(error)
	onReload     func()

	// Runtime state
	callback    PolicyCallback
	lastModTime time.Time
	cancel      context.CancelFunc
	wg          sync.WaitGroup
}

// NewFileProvider creates a new FileProvider that reads from the given path.
func NewFileProvider(path string, opts ...FileProviderOption) *FileProvider {
	f := &FileProvider{
		path:   path,
		parser: jsonpolicy.NewParser(),
	}

	for _, opt := range opts {
		opt(f)
	}

	return f
}

// Load reads and parses policies from the file.
func (f *FileProvider) Load() ([]*Policy, error) {
	data, err := os.ReadFile(f.path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", f.path, err)
	}

	return f.parser.ParseBytes(data)
}

// Subscribe registers a callback for policy changes.
// If a poll interval is configured, the provider will start watching for file changes.
func (f *FileProvider) Subscribe(callback PolicyCallback) error {
	f.mu.Lock()
	f.callback = callback
	f.mu.Unlock()

	// Load initial policies
	policies, err := f.Load()
	if err != nil {
		return err
	}

	// Record initial mod time
	if info, err := os.Stat(f.path); err == nil {
		f.mu.Lock()
		f.lastModTime = info.ModTime()
		f.mu.Unlock()
	}

	// Invoke callback with initial policies
	callback(policies)

	// Start polling if configured
	if f.pollInterval > 0 {
		f.startPolling()
	}

	return nil
}

// Stop stops the file watcher if it is running.
func (f *FileProvider) Stop() {
	f.mu.Lock()
	if f.cancel != nil {
		f.cancel()
	}
	f.mu.Unlock()

	f.wg.Wait()
}

// SetStatsCollector registers a stats collector function.
func (f *FileProvider) SetStatsCollector(collector StatsCollector) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statsCollector = collector
}

// GetStatsCollector returns the registered stats collector.
func (f *FileProvider) GetStatsCollector() StatsCollector {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.statsCollector
}

func (f *FileProvider) startPolling() {
	ctx, cancel := context.WithCancel(context.Background())

	f.mu.Lock()
	f.cancel = cancel
	f.mu.Unlock()

	f.wg.Add(1)
	go f.pollLoop(ctx)
}

func (f *FileProvider) pollLoop(ctx context.Context) {
	defer f.wg.Done()

	ticker := time.NewTicker(f.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			f.checkAndReload()
		}
	}
}

func (f *FileProvider) checkAndReload() {
	info, err := os.Stat(f.path)
	if err != nil {
		if f.onError != nil {
			f.onError(fmt.Errorf("failed to stat file %s: %w", f.path, err))
		}
		return
	}

	f.mu.RLock()
	lastModTime := f.lastModTime
	callback := f.callback
	f.mu.RUnlock()

	// Check if file has been modified
	if !info.ModTime().After(lastModTime) {
		return
	}

	// Reload policies
	policies, err := f.Load()
	if err != nil {
		if f.onError != nil {
			f.onError(fmt.Errorf("failed to reload policies: %w", err))
		}
		return
	}

	// Update last mod time
	f.mu.Lock()
	f.lastModTime = info.ModTime()
	f.mu.Unlock()

	// Invoke callback
	if callback != nil {
		callback(policies)
	}

	// Invoke reload callback
	if f.onReload != nil {
		f.onReload()
	}
}
