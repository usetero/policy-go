package policy

import (
	"fmt"
	"os"
	"sync"

	"github.com/usetero/policy-go/internal/jsonpolicy"
)

// FileProvider loads policies from a JSON file.
// It implements the PolicyProvider interface.
type FileProvider struct {
	path           string
	parser         *jsonpolicy.Parser
	mu             sync.RWMutex
	statsCollector StatsCollector
}

// NewFileProvider creates a new FileProvider that reads from the given path.
func NewFileProvider(path string) *FileProvider {
	return &FileProvider{
		path:   path,
		parser: jsonpolicy.NewParser(),
	}
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
// Currently performs a one-shot load and callback.
// TODO: Add file watching support.
func (f *FileProvider) Subscribe(callback PolicyCallback) error {
	policies, err := f.Load()
	if err != nil {
		return err
	}
	callback(policies)
	return nil
}

// SetStatsCollector registers a stats collector function.
func (f *FileProvider) SetStatsCollector(collector StatsCollector) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statsCollector = collector
}

// StatsCollector returns the registered stats collector.
func (f *FileProvider) GetStatsCollector() StatsCollector {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.statsCollector
}
