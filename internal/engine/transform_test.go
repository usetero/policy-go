package engine

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
)

func TestCompileLogTransformNil(t *testing.T) {
	ops := compileLogTransform(nil)
	assert.Nil(t, ops)
}

func TestCompileLogTransformEmpty(t *testing.T) {
	ops := compileLogTransform(&policyv1.LogTransform{})
	assert.Nil(t, ops)
}

func TestCompileLogTransformOrdering(t *testing.T) {
	transform := &policyv1.LogTransform{
		Remove: []*policyv1.LogRemove{
			{Field: &policyv1.LogRemove_LogField{LogField: policyv1.LogField_LOG_FIELD_TRACE_ID}},
			{Field: &policyv1.LogRemove_LogField{LogField: policyv1.LogField_LOG_FIELD_SPAN_ID}},
		},
		Redact: []*policyv1.LogRedact{
			{
				Field:       &policyv1.LogRedact_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY},
				Replacement: "***",
			},
		},
		Rename: []*policyv1.LogRename{
			{
				From:   &policyv1.LogRename_FromLogAttribute{FromLogAttribute: &policyv1.AttributePath{Path: []string{"old"}}},
				To:     "new",
				Upsert: true,
			},
		},
		Add: []*policyv1.LogAdd{
			{
				Field:  &policyv1.LogAdd_LogAttribute{LogAttribute: &policyv1.AttributePath{Path: []string{"tag"}}},
				Value:  "v1",
				Upsert: false,
			},
		},
	}

	ops := compileLogTransform(transform)
	require.Len(t, ops, 5)

	// Removes first (2), then redact (1), rename (1), add (1)
	assert.Equal(t, TransformRemove, ops[0].Kind)
	assert.Equal(t, LogFieldTraceID, ops[0].Ref.Field)

	assert.Equal(t, TransformRemove, ops[1].Kind)
	assert.Equal(t, LogFieldSpanID, ops[1].Ref.Field)

	assert.Equal(t, TransformRedact, ops[2].Kind)
	assert.Equal(t, LogFieldBody, ops[2].Ref.Field)
	assert.Equal(t, "***", ops[2].Value)

	assert.Equal(t, TransformRename, ops[3].Kind)
	assert.Equal(t, []string{"old"}, ops[3].Ref.AttrPath)
	assert.Equal(t, "new", ops[3].To)
	assert.True(t, ops[3].Upsert)

	assert.Equal(t, TransformAdd, ops[4].Kind)
	assert.Equal(t, []string{"tag"}, ops[4].Ref.AttrPath)
	assert.Equal(t, "v1", ops[4].Value)
	assert.False(t, ops[4].Upsert)
}

func TestFieldRefFromLogRemoveAllScopes(t *testing.T) {
	tests := []struct {
		name     string
		proto    *policyv1.LogRemove
		expected LogFieldRef
	}{
		{
			name:     "log field",
			proto:    &policyv1.LogRemove{Field: &policyv1.LogRemove_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY}},
			expected: LogFieldRef{Field: LogFieldBody},
		},
		{
			name: "log attribute",
			proto: &policyv1.LogRemove{Field: &policyv1.LogRemove_LogAttribute{
				LogAttribute: &policyv1.AttributePath{Path: []string{"http", "method"}},
			}},
			expected: LogFieldRef{AttrScope: AttrScopeRecord, AttrPath: []string{"http", "method"}},
		},
		{
			name: "resource attribute",
			proto: &policyv1.LogRemove{Field: &policyv1.LogRemove_ResourceAttribute{
				ResourceAttribute: &policyv1.AttributePath{Path: []string{"service.name"}},
			}},
			expected: LogFieldRef{AttrScope: AttrScopeResource, AttrPath: []string{"service.name"}},
		},
		{
			name: "scope attribute",
			proto: &policyv1.LogRemove{Field: &policyv1.LogRemove_ScopeAttribute{
				ScopeAttribute: &policyv1.AttributePath{Path: []string{"lib"}},
			}},
			expected: LogFieldRef{AttrScope: AttrScopeScope, AttrPath: []string{"lib"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref := fieldRefFromLogRemove(tt.proto)
			assert.Equal(t, tt.expected, ref)
		})
	}
}

func TestFieldRefFromLogRedactAllScopes(t *testing.T) {
	tests := []struct {
		name     string
		proto    *policyv1.LogRedact
		expected LogFieldRef
	}{
		{
			name: "log field",
			proto: &policyv1.LogRedact{
				Field:       &policyv1.LogRedact_LogField{LogField: policyv1.LogField_LOG_FIELD_SEVERITY_TEXT},
				Replacement: "x",
			},
			expected: LogFieldRef{Field: LogFieldSeverityText},
		},
		{
			name: "log attribute",
			proto: &policyv1.LogRedact{Field: &policyv1.LogRedact_LogAttribute{
				LogAttribute: &policyv1.AttributePath{Path: []string{"password"}},
			}},
			expected: LogFieldRef{AttrScope: AttrScopeRecord, AttrPath: []string{"password"}},
		},
		{
			name: "resource attribute",
			proto: &policyv1.LogRedact{Field: &policyv1.LogRedact_ResourceAttribute{
				ResourceAttribute: &policyv1.AttributePath{Path: []string{"host"}},
			}},
			expected: LogFieldRef{AttrScope: AttrScopeResource, AttrPath: []string{"host"}},
		},
		{
			name: "scope attribute",
			proto: &policyv1.LogRedact{Field: &policyv1.LogRedact_ScopeAttribute{
				ScopeAttribute: &policyv1.AttributePath{Path: []string{"version"}},
			}},
			expected: LogFieldRef{AttrScope: AttrScopeScope, AttrPath: []string{"version"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref := fieldRefFromLogRedact(tt.proto)
			assert.Equal(t, tt.expected, ref)
		})
	}
}

func TestFieldRefFromLogRenameAllScopes(t *testing.T) {
	tests := []struct {
		name     string
		proto    *policyv1.LogRename
		expected LogFieldRef
	}{
		{
			name:     "log field",
			proto:    &policyv1.LogRename{From: &policyv1.LogRename_FromLogField{FromLogField: policyv1.LogField_LOG_FIELD_EVENT_NAME}},
			expected: LogFieldRef{Field: LogFieldEventName},
		},
		{
			name: "log attribute",
			proto: &policyv1.LogRename{From: &policyv1.LogRename_FromLogAttribute{
				FromLogAttribute: &policyv1.AttributePath{Path: []string{"src"}},
			}},
			expected: LogFieldRef{AttrScope: AttrScopeRecord, AttrPath: []string{"src"}},
		},
		{
			name: "resource attribute",
			proto: &policyv1.LogRename{From: &policyv1.LogRename_FromResourceAttribute{
				FromResourceAttribute: &policyv1.AttributePath{Path: []string{"k8s.pod"}},
			}},
			expected: LogFieldRef{AttrScope: AttrScopeResource, AttrPath: []string{"k8s.pod"}},
		},
		{
			name: "scope attribute",
			proto: &policyv1.LogRename{From: &policyv1.LogRename_FromScopeAttribute{
				FromScopeAttribute: &policyv1.AttributePath{Path: []string{"scope_key"}},
			}},
			expected: LogFieldRef{AttrScope: AttrScopeScope, AttrPath: []string{"scope_key"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref := fieldRefFromLogRename(tt.proto)
			assert.Equal(t, tt.expected, ref)
		})
	}
}

func TestFieldRefFromLogAddAllScopes(t *testing.T) {
	tests := []struct {
		name     string
		proto    *policyv1.LogAdd
		expected LogFieldRef
	}{
		{
			name:     "log field",
			proto:    &policyv1.LogAdd{Field: &policyv1.LogAdd_LogField{LogField: policyv1.LogField_LOG_FIELD_BODY}},
			expected: LogFieldRef{Field: LogFieldBody},
		},
		{
			name: "log attribute",
			proto: &policyv1.LogAdd{Field: &policyv1.LogAdd_LogAttribute{
				LogAttribute: &policyv1.AttributePath{Path: []string{"added"}},
			}},
			expected: LogFieldRef{AttrScope: AttrScopeRecord, AttrPath: []string{"added"}},
		},
		{
			name: "resource attribute",
			proto: &policyv1.LogAdd{Field: &policyv1.LogAdd_ResourceAttribute{
				ResourceAttribute: &policyv1.AttributePath{Path: []string{"cluster"}},
			}},
			expected: LogFieldRef{AttrScope: AttrScopeResource, AttrPath: []string{"cluster"}},
		},
		{
			name: "scope attribute",
			proto: &policyv1.LogAdd{Field: &policyv1.LogAdd_ScopeAttribute{
				ScopeAttribute: &policyv1.AttributePath{Path: []string{"instrumentation"}},
			}},
			expected: LogFieldRef{AttrScope: AttrScopeScope, AttrPath: []string{"instrumentation"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref := fieldRefFromLogAdd(tt.proto)
			assert.Equal(t, tt.expected, ref)
		})
	}
}
