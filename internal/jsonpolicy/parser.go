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

	// Parse transform if present
	if log.Transform != nil {
		transform, err := p.convertLogTransform(log.Transform)
		if err != nil {
			return nil, err
		}
		target.Transform = transform
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

func (p *Parser) convertLogTransform(t *LogTransform) (*policyv1.LogTransform, error) {
	result := &policyv1.LogTransform{}

	for i, r := range t.Remove {
		pr, err := p.convertLogRemove(r)
		if err != nil {
			return nil, fmt.Errorf("remove[%d]: %w", i, err)
		}
		result.Remove = append(result.Remove, pr)
	}

	for i, r := range t.Redact {
		pr, err := p.convertLogRedact(r)
		if err != nil {
			return nil, fmt.Errorf("redact[%d]: %w", i, err)
		}
		result.Redact = append(result.Redact, pr)
	}

	for i, r := range t.Rename {
		pr, err := p.convertLogRename(r)
		if err != nil {
			return nil, fmt.Errorf("rename[%d]: %w", i, err)
		}
		result.Rename = append(result.Rename, pr)
	}

	for i, a := range t.Add {
		pa, err := p.convertLogAdd(a)
		if err != nil {
			return nil, fmt.Errorf("add[%d]: %w", i, err)
		}
		result.Add = append(result.Add, pa)
	}

	return result, nil
}

func (p *Parser) convertLogRemove(r LogRemove) (*policyv1.LogRemove, error) {
	result := &policyv1.LogRemove{}
	field, err := resolveFieldSelector("remove", r.LogField, r.LogAttribute, r.ResourceAttribute, r.ScopeAttribute)
	if err != nil {
		return nil, err
	}
	switch f := field.(type) {
	case logFieldSel:
		result.Field = &policyv1.LogRemove_LogField{LogField: policyv1.LogField(f)}
	case logAttrSel:
		result.Field = &policyv1.LogRemove_LogAttribute{LogAttribute: &policyv1.AttributePath{Path: f.path}}
	case resourceAttrSel:
		result.Field = &policyv1.LogRemove_ResourceAttribute{ResourceAttribute: &policyv1.AttributePath{Path: f.path}}
	case scopeAttrSel:
		result.Field = &policyv1.LogRemove_ScopeAttribute{ScopeAttribute: &policyv1.AttributePath{Path: f.path}}
	}
	return result, nil
}

func (p *Parser) convertLogRedact(r LogRedact) (*policyv1.LogRedact, error) {
	result := &policyv1.LogRedact{Replacement: r.Replacement}
	field, err := resolveFieldSelector("redact", r.LogField, r.LogAttribute, r.ResourceAttribute, r.ScopeAttribute)
	if err != nil {
		return nil, err
	}
	switch f := field.(type) {
	case logFieldSel:
		result.Field = &policyv1.LogRedact_LogField{LogField: policyv1.LogField(f)}
	case logAttrSel:
		result.Field = &policyv1.LogRedact_LogAttribute{LogAttribute: &policyv1.AttributePath{Path: f.path}}
	case resourceAttrSel:
		result.Field = &policyv1.LogRedact_ResourceAttribute{ResourceAttribute: &policyv1.AttributePath{Path: f.path}}
	case scopeAttrSel:
		result.Field = &policyv1.LogRedact_ScopeAttribute{ScopeAttribute: &policyv1.AttributePath{Path: f.path}}
	}
	return result, nil
}

func (p *Parser) convertLogRename(r LogRename) (*policyv1.LogRename, error) {
	if r.To == "" {
		return nil, NewParseError("rename.to", "required")
	}
	result := &policyv1.LogRename{To: r.To, Upsert: r.Upsert}
	field, err := resolveFieldSelector("rename", r.LogField, r.LogAttribute, r.ResourceAttribute, r.ScopeAttribute)
	if err != nil {
		return nil, err
	}
	switch f := field.(type) {
	case logFieldSel:
		result.From = &policyv1.LogRename_FromLogField{FromLogField: policyv1.LogField(f)}
	case logAttrSel:
		result.From = &policyv1.LogRename_FromLogAttribute{FromLogAttribute: &policyv1.AttributePath{Path: f.path}}
	case resourceAttrSel:
		result.From = &policyv1.LogRename_FromResourceAttribute{FromResourceAttribute: &policyv1.AttributePath{Path: f.path}}
	case scopeAttrSel:
		result.From = &policyv1.LogRename_FromScopeAttribute{FromScopeAttribute: &policyv1.AttributePath{Path: f.path}}
	}
	return result, nil
}

func (p *Parser) convertLogAdd(a LogAdd) (*policyv1.LogAdd, error) {
	result := &policyv1.LogAdd{Value: a.Value, Upsert: a.Upsert}
	field, err := resolveFieldSelector("add", a.LogField, a.LogAttribute, a.ResourceAttribute, a.ScopeAttribute)
	if err != nil {
		return nil, err
	}
	switch f := field.(type) {
	case logFieldSel:
		result.Field = &policyv1.LogAdd_LogField{LogField: policyv1.LogField(f)}
	case logAttrSel:
		result.Field = &policyv1.LogAdd_LogAttribute{LogAttribute: &policyv1.AttributePath{Path: f.path}}
	case resourceAttrSel:
		result.Field = &policyv1.LogAdd_ResourceAttribute{ResourceAttribute: &policyv1.AttributePath{Path: f.path}}
	case scopeAttrSel:
		result.Field = &policyv1.LogAdd_ScopeAttribute{ScopeAttribute: &policyv1.AttributePath{Path: f.path}}
	}
	return result, nil
}

// fieldSelection is a tagged union for resolved field selectors.
type fieldSelection interface{ fieldSelection() }

type logFieldSel policyv1.LogField
type logAttrSel struct{ path []string }
type resourceAttrSel struct{ path []string }
type scopeAttrSel struct{ path []string }

func (logFieldSel) fieldSelection()     {}
func (logAttrSel) fieldSelection()      {}
func (resourceAttrSel) fieldSelection() {}
func (scopeAttrSel) fieldSelection()    {}

// resolveFieldSelector validates and resolves the field selector from the four possible sources.
func resolveFieldSelector(context string, logField string, logAttr, resourceAttr, scopeAttr *AttributePath) (fieldSelection, error) {
	count := 0
	if logField != "" {
		count++
	}
	if logAttr != nil {
		count++
	}
	if resourceAttr != nil {
		count++
	}
	if scopeAttr != nil {
		count++
	}
	if count == 0 {
		return nil, NewParseError(context, "must specify a field type")
	}
	if count > 1 {
		return nil, NewParseError(context, "must specify only one field type")
	}

	if logField != "" {
		f, ok := parseLogField(logField)
		if !ok {
			return nil, NewParseError(context+".log_field", fmt.Sprintf("unknown field: %s", logField))
		}
		return logFieldSel(f), nil
	}
	if logAttr != nil {
		return logAttrSel{path: logAttr.Path}, nil
	}
	if resourceAttr != nil {
		return resourceAttrSel{path: resourceAttr.Path}, nil
	}
	return scopeAttrSel{path: scopeAttr.Path}, nil
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
