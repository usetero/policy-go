package policy

import (
	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"

	policyv1 "github.com/usetero/policy-go/internal/proto/tero/policy/v1"
)

// ServiceMetadata describes the client's identity for policy sync requests.
// This is used by HTTP and gRPC providers to identify themselves to the policy server.
type ServiceMetadata struct {
	// ServiceName is the name of the service (required).
	ServiceName string
	// ServiceNamespace is the namespace the service belongs to (required).
	ServiceNamespace string
	// ServiceInstanceID is a unique identifier for this service instance (required).
	ServiceInstanceID string
	// ServiceVersion is the version of the service (required).
	ServiceVersion string
	// SupportedStages lists which policy stages this client can handle.
	SupportedStages []policyv1.PolicyStage
	// Labels are additional metadata labels.
	Labels map[string]string
	// ResourceAttributes are additional resource attributes beyond the required ones.
	ResourceAttributes map[string]string
}

// ToProto converts ServiceMetadata to the proto ClientMetadata type.
func (m *ServiceMetadata) ToProto() *policyv1.ClientMetadata {
	if m == nil {
		return nil
	}

	// Build resource attributes with required fields
	resourceAttrs := []*commonv1.KeyValue{
		{Key: "service.name", Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: m.ServiceName}}},
		{Key: "service.namespace", Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: m.ServiceNamespace}}},
		{Key: "service.instance.id", Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: m.ServiceInstanceID}}},
		{Key: "service.version", Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: m.ServiceVersion}}},
	}

	// Add additional resource attributes
	for k, v := range m.ResourceAttributes {
		resourceAttrs = append(resourceAttrs, &commonv1.KeyValue{
			Key:   k,
			Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: v}},
		})
	}

	// Build labels
	var labels []*commonv1.KeyValue
	for k, v := range m.Labels {
		labels = append(labels, &commonv1.KeyValue{
			Key:   k,
			Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: v}},
		})
	}

	return &policyv1.ClientMetadata{
		SupportedPolicyStages: m.SupportedStages,
		Labels:                labels,
		ResourceAttributes:    resourceAttrs,
	}
}
