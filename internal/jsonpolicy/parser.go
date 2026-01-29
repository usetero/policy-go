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

	target := &policyv1.LogTarget{
		Match: matchers,
		Keep:  keep,
	}

	// Parse sample_key if present
	if log.SampleKey != nil {
		sk, err := p.convertSampleKey(log.SampleKey)
		if err != nil {
			return nil, err
		}
		target.SampleKey = sk
	}

	return target, nil
}

func (p *Parser) convertLogMatcher(m LogMatcher) (*policyv1.LogMatcher, error) {
	matcher := &policyv1.LogMatcher{
		Negate:          m.Negated,
		CaseInsensitive: m.CaseInsensitive,
	}

	// Set field selector
	if err := p.setFieldSelector(matcher, m); err != nil {
		return nil, err
	}

	// Set match type (exactly one must be set)
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
	} else if m.StartsWith != "" {
		matcher.Match = &policyv1.LogMatcher_StartsWith{StartsWith: m.StartsWith}
	} else if m.EndsWith != "" {
		matcher.Match = &policyv1.LogMatcher_EndsWith{EndsWith: m.EndsWith}
	} else if m.Contains != "" {
		matcher.Match = &policyv1.LogMatcher_Contains{Contains: m.Contains}
	} else {
		return nil, NewParseError("matcher", "must have a match type (regex, exact, exists, starts_with, ends_with, or contains)")
	}

	return matcher, nil
}

func (p *Parser) setFieldSelector(matcher *policyv1.LogMatcher, m LogMatcher) error {
	// Count how many field types are set
	count := 0
	if m.LogField != "" {
		count++
	}
	if m.LogAttribute != nil {
		count++
	}
	if m.ResourceAttribute != nil {
		count++
	}
	if m.ScopeAttribute != nil {
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

	if m.LogAttribute != nil {
		matcher.Field = &policyv1.LogMatcher_LogAttribute{
			LogAttribute: &policyv1.AttributePath{Path: m.LogAttribute.Path},
		}
		return nil
	}

	if m.ResourceAttribute != nil {
		matcher.Field = &policyv1.LogMatcher_ResourceAttribute{
			ResourceAttribute: &policyv1.AttributePath{Path: m.ResourceAttribute.Path},
		}
		return nil
	}

	if m.ScopeAttribute != nil {
		matcher.Field = &policyv1.LogMatcher_ScopeAttribute{
			ScopeAttribute: &policyv1.AttributePath{Path: m.ScopeAttribute.Path},
		}
		return nil
	}

	return NewParseError("matcher", "no field selector")
}

func (p *Parser) convertSampleKey(sk *SampleKey) (*policyv1.LogSampleKey, error) {
	result := &policyv1.LogSampleKey{}

	count := 0
	if sk.LogField != "" {
		count++
	}
	if sk.LogAttribute != nil {
		count++
	}
	if sk.ResourceAttribute != nil {
		count++
	}
	if sk.ScopeAttribute != nil {
		count++
	}

	if count == 0 {
		return nil, NewParseError("sample_key", "must specify a field type")
	}
	if count > 1 {
		return nil, NewParseError("sample_key", "must specify only one field type")
	}

	if sk.LogField != "" {
		field, ok := parseLogField(sk.LogField)
		if !ok {
			return nil, NewParseError("sample_key.log_field", fmt.Sprintf("unknown field: %s", sk.LogField))
		}
		result.Field = &policyv1.LogSampleKey_LogField{LogField: field}
		return result, nil
	}

	if sk.LogAttribute != nil {
		result.Field = &policyv1.LogSampleKey_LogAttribute{
			LogAttribute: &policyv1.AttributePath{Path: sk.LogAttribute.Path},
		}
		return result, nil
	}

	if sk.ResourceAttribute != nil {
		result.Field = &policyv1.LogSampleKey_ResourceAttribute{
			ResourceAttribute: &policyv1.AttributePath{Path: sk.ResourceAttribute.Path},
		}
		return result, nil
	}

	if sk.ScopeAttribute != nil {
		result.Field = &policyv1.LogSampleKey_ScopeAttribute{
			ScopeAttribute: &policyv1.AttributePath{Path: sk.ScopeAttribute.Path},
		}
		return result, nil
	}

	return nil, NewParseError("sample_key", "no field selector")
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
		s := *k.StringValue
		switch s {
		case "all", "":
			return "all", nil
		case "none":
			return "none", nil
		default:
			// Check if it's a percentage string like "50%"
			if len(s) > 0 && s[len(s)-1] == '%' {
				// Pass through percentage strings as-is for the engine to parse
				return s, nil
			}
			return "", NewParseError("keep", fmt.Sprintf("unknown value: %s", s))
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
