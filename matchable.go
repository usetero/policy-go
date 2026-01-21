package policy

// Matchable is the interface for telemetry records that can be matched against policies.
// Implementations should return field values without allocating new memory where possible.
type Matchable interface {
	// GetField returns the value of the specified field.
	// Returns nil if the field doesn't exist or isn't applicable.
	// The returned slice should be a view into existing data when possible
	// to avoid allocations in the hot path.
	GetField(selector FieldSelector) []byte
}

// LogMatchable is the interface for log records that can be matched against log policies.
type LogMatchable interface {
	Matchable

	// Body returns the log body/message.
	Body() []byte

	// SeverityText returns the severity text (e.g., "DEBUG", "ERROR").
	SeverityText() []byte

	// SeverityNumber returns the severity number as a string.
	SeverityNumber() []byte

	// GetLogAttribute returns a log attribute value by key.
	GetLogAttribute(key string) []byte

	// GetResourceAttribute returns a resource attribute value by key.
	GetResourceAttribute(key string) []byte

	// GetScopeAttribute returns a scope attribute value by key.
	GetScopeAttribute(key string) []byte
}

// SimpleLogRecord is a simple implementation of LogMatchable for testing.
type SimpleLogRecord struct {
	BodyValue           []byte
	SeverityTextValue   []byte
	SeverityNumberValue []byte
	LogAttributes       map[string][]byte
	ResourceAttributes  map[string][]byte
	ScopeAttributes     map[string][]byte
}

// GetField implements Matchable.
func (r *SimpleLogRecord) GetField(selector FieldSelector) []byte {
	switch selector.Type {
	case FieldTypeLogField:
		switch selector.Field {
		case LogFieldBody:
			return r.BodyValue
		case LogFieldSeverityText:
			return r.SeverityTextValue
		case LogFieldSeverityNumber:
			return r.SeverityNumberValue
		default:
			return nil
		}
	case FieldTypeLogAttribute:
		if r.LogAttributes == nil {
			return nil
		}
		return r.LogAttributes[selector.Key]
	case FieldTypeResourceAttribute:
		if r.ResourceAttributes == nil {
			return nil
		}
		return r.ResourceAttributes[selector.Key]
	case FieldTypeScopeAttribute:
		if r.ScopeAttributes == nil {
			return nil
		}
		return r.ScopeAttributes[selector.Key]
	default:
		return nil
	}
}

// Body implements LogMatchable.
func (r *SimpleLogRecord) Body() []byte {
	return r.BodyValue
}

// SeverityText implements LogMatchable.
func (r *SimpleLogRecord) SeverityText() []byte {
	return r.SeverityTextValue
}

// SeverityNumber implements LogMatchable.
func (r *SimpleLogRecord) SeverityNumber() []byte {
	return r.SeverityNumberValue
}

// GetLogAttribute implements LogMatchable.
func (r *SimpleLogRecord) GetLogAttribute(key string) []byte {
	if r.LogAttributes == nil {
		return nil
	}
	return r.LogAttributes[key]
}

// GetResourceAttribute implements LogMatchable.
func (r *SimpleLogRecord) GetResourceAttribute(key string) []byte {
	if r.ResourceAttributes == nil {
		return nil
	}
	return r.ResourceAttributes[key]
}

// GetScopeAttribute implements LogMatchable.
func (r *SimpleLogRecord) GetScopeAttribute(key string) []byte {
	if r.ScopeAttributes == nil {
		return nil
	}
	return r.ScopeAttributes[key]
}
