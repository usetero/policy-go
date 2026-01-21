package jsonpolicy

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"

	"github.com/usetero/policy-go/internal/engine"
)

// Parser converts JSON policy files to Policy objects.
type Parser struct{}

// NewParser creates a new Parser.
func NewParser() *Parser {
	return &Parser{}
}

// Parse reads and parses policies from a reader.
func (p *Parser) Parse(r io.Reader) ([]*engine.Policy, error) {
	var file File
	if err := json.NewDecoder(r).Decode(&file); err != nil {
		return nil, fmt.Errorf("failed to decode JSON: %w", err)
	}

	policies := make([]*engine.Policy, 0, len(file.Policies))
	for i, jp := range file.Policies {
		pol, err := p.convertPolicy(jp)
		if err != nil {
			return nil, fmt.Errorf("policy %d (%s): %w", i, jp.ID, err)
		}
		policies = append(policies, pol)
	}

	return policies, nil
}

// ParseBytes parses policies from a byte slice.
func (p *Parser) ParseBytes(data []byte) ([]*engine.Policy, error) {
	var file File
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("failed to decode JSON: %w", err)
	}

	policies := make([]*engine.Policy, 0, len(file.Policies))
	for i, jp := range file.Policies {
		pol, err := p.convertPolicy(jp)
		if err != nil {
			return nil, fmt.Errorf("policy %d (%s): %w", i, jp.ID, err)
		}
		policies = append(policies, pol)
	}

	return policies, nil
}

func (p *Parser) convertPolicy(jp Policy) (*engine.Policy, error) {
	if jp.ID == "" {
		return nil, NewParseError("id", "required")
	}
	if jp.Name == "" {
		return nil, NewParseError("name", "required")
	}

	var logPolicy *engine.LogPolicy
	if jp.Log != nil {
		lp, err := p.convertLogPolicy(jp.Log)
		if err != nil {
			return nil, err
		}
		logPolicy = lp
	}

	return &engine.Policy{ID: jp.ID, Name: jp.Name, Log: logPolicy}, nil
}

func (p *Parser) convertLogPolicy(log *Log) (*engine.LogPolicy, error) {
	matchers := make([]engine.Matcher, 0, len(log.Match))
	for i, m := range log.Match {
		matcher, err := p.convertLogMatcher(m)
		if err != nil {
			return nil, fmt.Errorf("matcher %d: %w", i, err)
		}
		matchers = append(matchers, matcher)
	}

	keep, err := p.convertKeep(log.Keep)
	if err != nil {
		return nil, err
	}

	return &engine.LogPolicy{
		Matchers: matchers,
		Keep:     keep,
	}, nil
}

func (p *Parser) convertLogMatcher(m LogMatcher) (engine.Matcher, error) {
	selector, err := p.parseFieldSelector(m)
	if err != nil {
		return engine.Matcher{}, err
	}

	// Determine the pattern
	var pattern string
	var exists *bool

	if m.Exists != nil {
		exists = m.Exists
	} else if m.Exact != "" {
		// Convert exact match to anchored regex
		pattern = "^" + regexp.QuoteMeta(m.Exact) + "$"
	} else if m.Regex != "" {
		pattern = m.Regex
		// Validate regex
		if _, err := regexp.Compile(pattern); err != nil {
			return engine.Matcher{}, fmt.Errorf("invalid regex: %w", err)
		}
	} else {
		return engine.Matcher{}, NewParseError("matcher", "must have regex, exact, or exists")
	}

	return engine.Matcher{
		Field:   selector,
		Pattern: pattern,
		Negated: m.Negated,
		Exists:  exists,
	}, nil
}

func (p *Parser) parseFieldSelector(m LogMatcher) (engine.FieldSelector, error) {
	// Count how many field types are set
	count := 0
	if m.LogField != "" {
		count++
	}
	if m.LogAttribute != "" {
		count++
	}
	if m.ResourceAttribute != "" {
		count++
	}
	if m.ScopeAttribute != "" {
		count++
	}

	if count == 0 {
		return engine.FieldSelector{}, NewParseError("matcher", "must specify a field type")
	}
	if count > 1 {
		return engine.FieldSelector{}, NewParseError("matcher", "must specify only one field type")
	}

	if m.LogField != "" {
		field, ok := parseLogField(m.LogField)
		if !ok {
			return engine.FieldSelector{}, NewParseError("log_field",
				fmt.Sprintf("unknown field: %s", m.LogField))
		}
		return engine.FieldSelector{Type: engine.FieldTypeLogField, Field: field}, nil
	}

	if m.LogAttribute != "" {
		return engine.FieldSelector{Type: engine.FieldTypeLogAttribute, Key: m.LogAttribute}, nil
	}

	if m.ResourceAttribute != "" {
		return engine.FieldSelector{Type: engine.FieldTypeResourceAttribute, Key: m.ResourceAttribute}, nil
	}

	if m.ScopeAttribute != "" {
		return engine.FieldSelector{Type: engine.FieldTypeScopeAttribute, Key: m.ScopeAttribute}, nil
	}

	// Should not reach here
	return engine.FieldSelector{}, NewParseError("matcher", "no field selector")
}

func parseLogField(s string) (engine.LogField, bool) {
	switch s {
	case "body":
		return engine.LogFieldBody, true
	case "severity_text":
		return engine.LogFieldSeverityText, true
	case "severity_number":
		return engine.LogFieldSeverityNumber, true
	case "timestamp":
		return engine.LogFieldTimestamp, true
	case "trace_id":
		return engine.LogFieldTraceID, true
	case "span_id":
		return engine.LogFieldSpanID, true
	default:
		return 0, false
	}
}

func (p *Parser) convertKeep(k KeepValue) (engine.Keep, error) {
	if k.StringValue != nil {
		switch *k.StringValue {
		case "all", "":
			return engine.Keep{Action: engine.KeepAll}, nil
		case "none":
			return engine.Keep{Action: engine.KeepNone}, nil
		default:
			return engine.Keep{}, NewParseError("keep",
				fmt.Sprintf("unknown value: %s", *k.StringValue))
		}
	}

	if k.BoolValue != nil {
		if *k.BoolValue {
			return engine.Keep{Action: engine.KeepAll}, nil
		}
		return engine.Keep{Action: engine.KeepNone}, nil
	}

	if k.SampleValue != nil {
		percentage := k.SampleValue.Percentage
		if percentage < 0 || percentage > 100 {
			return engine.Keep{}, NewParseError("keep.percentage",
				"must be between 0 and 100")
		}
		// 0% is drop, 100% is keep all
		if percentage == 0 {
			return engine.Keep{Action: engine.KeepNone}, nil
		}
		if percentage == 100 {
			return engine.Keep{Action: engine.KeepAll}, nil
		}
		return engine.Keep{Action: engine.KeepSample, Value: percentage}, nil
	}

	// Default to keep all
	return engine.Keep{Action: engine.KeepAll}, nil
}
