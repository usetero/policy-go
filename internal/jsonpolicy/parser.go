package jsonpolicy

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"

	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
)

// Parser converts JSON policy files to proto Policy objects.
type Parser struct{}

// NewParser creates a new Parser.
func NewParser() *Parser {
	return &Parser{}
}

// Parse reads and parses policies from a reader.
func (p *Parser) Parse(r io.Reader) ([]*policyv1.Policy, error) {
	var file File
	if err := json.NewDecoder(r).Decode(&file); err != nil {
		return nil, fmt.Errorf("failed to decode JSON: %w", err)
	}

	policies := make([]*policyv1.Policy, 0, len(file.Policies))
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
func (p *Parser) ParseBytes(data []byte) ([]*policyv1.Policy, error) {
	var file File
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("failed to decode JSON: %w", err)
	}

	policies := make([]*policyv1.Policy, 0, len(file.Policies))
	for i, jp := range file.Policies {
		pol, err := p.convertPolicy(jp)
		if err != nil {
			return nil, fmt.Errorf("policy %d (%s): %w", i, jp.ID, err)
		}
		policies = append(policies, pol)
	}

	return policies, nil
}

func (p *Parser) convertPolicy(jp Policy) (*policyv1.Policy, error) {
	if jp.ID == "" {
		return nil, NewParseError("id", "required")
	}
	if jp.Name == "" {
		return nil, NewParseError("name", "required")
	}

	pol := &policyv1.Policy{
		Id:      jp.ID,
		Name:    jp.Name,
		Enabled: true,
	}

	if jp.Log != nil {
		logTarget, err := p.convertLogTarget(jp.Log)
		if err != nil {
			return nil, err
		}
		pol.Target = &policyv1.Policy_Log{Log: logTarget}
	}

	return pol, nil
}

func (p *Parser) convertLogTarget(log *Log) (*policyv1.LogTarget, error) {
	matchers := make([]*policyv1.LogMatcher, 0, len(log.Match))
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

	return &policyv1.LogTarget{
		Match: matchers,
		Keep:  keep,
	}, nil
}

func (p *Parser) convertLogMatcher(m LogMatcher) (*policyv1.LogMatcher, error) {
	matcher := &policyv1.LogMatcher{
		Negate: m.Negated,
	}

	// Set field selector
	if err := p.setFieldSelector(matcher, m); err != nil {
		return nil, err
	}

	// Set match type
	if m.Exists != nil {
		matcher.Match = &policyv1.LogMatcher_Exists{Exists: *m.Exists}
	} else if m.Exact != "" {
		matcher.Match = &policyv1.LogMatcher_Exact{Exact: m.Exact}
	} else if m.Regex != "" {
		// Validate regex
		if _, err := regexp.Compile(m.Regex); err != nil {
			return nil, fmt.Errorf("invalid regex: %w", err)
		}
		matcher.Match = &policyv1.LogMatcher_Regex{Regex: m.Regex}
	} else {
		return nil, NewParseError("matcher", "must have regex, exact, or exists")
	}

	return matcher, nil
}

func (p *Parser) setFieldSelector(matcher *policyv1.LogMatcher, m LogMatcher) error {
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
		return NewParseError("matcher", "must specify a field type")
	}
	if count > 1 {
		return NewParseError("matcher", "must specify only one field type")
	}

	if m.LogField != "" {
		field, ok := parseLogField(m.LogField)
		if !ok {
			return NewParseError("log_field", fmt.Sprintf("unknown field: %s", m.LogField))
		}
		matcher.Field = &policyv1.LogMatcher_LogField{LogField: field}
		return nil
	}

	if m.LogAttribute != "" {
		matcher.Field = &policyv1.LogMatcher_LogAttribute{LogAttribute: m.LogAttribute}
		return nil
	}

	if m.ResourceAttribute != "" {
		matcher.Field = &policyv1.LogMatcher_ResourceAttribute{ResourceAttribute: m.ResourceAttribute}
		return nil
	}

	if m.ScopeAttribute != "" {
		matcher.Field = &policyv1.LogMatcher_ScopeAttribute{ScopeAttribute: m.ScopeAttribute}
		return nil
	}

	return NewParseError("matcher", "no field selector")
}

func parseLogField(s string) (policyv1.LogField, bool) {
	switch s {
	case "body":
		return policyv1.LogField_LOG_FIELD_BODY, true
	case "severity_text":
		return policyv1.LogField_LOG_FIELD_SEVERITY_TEXT, true
	case "trace_id":
		return policyv1.LogField_LOG_FIELD_TRACE_ID, true
	case "span_id":
		return policyv1.LogField_LOG_FIELD_SPAN_ID, true
	case "event_name":
		return policyv1.LogField_LOG_FIELD_EVENT_NAME, true
	case "resource_schema_url":
		return policyv1.LogField_LOG_FIELD_RESOURCE_SCHEMA_URL, true
	case "scope_schema_url":
		return policyv1.LogField_LOG_FIELD_SCOPE_SCHEMA_URL, true
	default:
		return policyv1.LogField_LOG_FIELD_UNSPECIFIED, false
	}
}

func (p *Parser) convertKeep(k KeepValue) (string, error) {
	if k.StringValue != nil {
		switch *k.StringValue {
		case "all", "":
			return "all", nil
		case "none":
			return "none", nil
		default:
			return "", NewParseError("keep", fmt.Sprintf("unknown value: %s", *k.StringValue))
		}
	}

	if k.BoolValue != nil {
		if *k.BoolValue {
			return "all", nil
		}
		return "none", nil
	}

	if k.SampleValue != nil {
		percentage := k.SampleValue.Percentage
		if percentage < 0 || percentage > 100 {
			return "", NewParseError("keep.percentage", "must be between 0 and 100")
		}
		return fmt.Sprintf("%.0f%%", percentage), nil
	}

	// Default to keep all
	return "all", nil
}
