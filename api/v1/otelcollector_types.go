// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v1

import (
	corev1 "k8s.io/api/core/v1"
)

// OTelLogType represents the allowable log types for OTel export.
// +kubebuilder:validation:Enum=Audit;DNS;Flows
type OTelLogType string

const (
	OTelAuditLog OTelLogType = "Audit"
	OTelDNSLog   OTelLogType = "DNS"
	OTelFlowLog  OTelLogType = "Flows"
)

// OTelLogs configures log export.
type OTelLogs struct {
	// Types specifies which log types to export. Supported values: Audit, DNS, Flows.
	// +optional
	Types []OTelLogType `json:"types,omitempty"`
}

// OTelMetricsEnabled is the option to enable or disable metrics export.
// +kubebuilder:validation:Enum=Enabled;Disabled
type OTelMetricsEnabled string

const (
	OTelMetricsEnable  OTelMetricsEnabled = "Enabled"
	OTelMetricsDisable OTelMetricsEnabled = "Disabled"
)

// OTelMetrics configures metrics export.
type OTelMetrics struct {
	// Enabled specifies whether to scrape and export Calico component metrics via OTLP.
	// Default: Disabled
	// +optional
	Enabled *OTelMetricsEnabled `json:"enabled,omitempty"`
}

// OTelExporterProtocol specifies the OTLP transport protocol.
// +kubebuilder:validation:Enum=grpc;http
type OTelExporterProtocol string

const (
	OTelProtocolGRPC OTelExporterProtocol = "grpc"
	OTelProtocolHTTP OTelExporterProtocol = "http"
)

// OTelExporter defines an OTLP export endpoint.
type OTelExporter struct {
	// Name is a unique identifier for this exporter.
	Name string `json:"name"`

	// Endpoint is the OTLP endpoint URL.
	Endpoint string `json:"endpoint"`

	// Protocol specifies the OTLP transport protocol. Default: grpc.
	// +optional
	// +kubebuilder:default=grpc
	Protocol OTelExporterProtocol `json:"protocol,omitempty"`

	// TLSInsecure disables TLS verification for this exporter. Only use for trusted in-cluster targets.
	// Default: false
	// +optional
	TLSInsecure *bool `json:"tlsInsecure,omitempty"`
}

// OTelCollectorStatefulSet is the configuration for the OTel Collector StatefulSet.
type OTelCollectorStatefulSet struct {
	// Metadata is a subset of a Kubernetes object's metadata that is added to the StatefulSet.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`
	// Spec is the specification of the OTel Collector StatefulSet.
	// +optional
	Spec *OTelCollectorStatefulSetSpec `json:"spec,omitempty"`
}

// OTelCollectorStatefulSetSpec defines configuration for the OTel Collector StatefulSet.
type OTelCollectorStatefulSetSpec struct {
	// MinReadySeconds is the minimum number of seconds for which a newly created StatefulSet pod should
	// be ready without any of its container crashing, for it to be considered available.
	// If specified, this overrides any minReadySeconds value that may be set on the OTel Collector StatefulSet.
	// If omitted, the OTel Collector StatefulSet will use its default value for minReadySeconds.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=2147483647
	MinReadySeconds *int32 `json:"minReadySeconds,omitempty"`

	// Template describes the OTel Collector StatefulSet pod that will be created.
	// +optional
	Template *OTelCollectorStatefulSetPodTemplateSpec `json:"template,omitempty"`
}

// OTelCollectorStatefulSetPodTemplateSpec is the OTel Collector StatefulSet's PodTemplateSpec.
type OTelCollectorStatefulSetPodTemplateSpec struct {
	// Metadata is a subset of a Kubernetes object's metadata that is added to the pod's metadata.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`
	// Spec is the OTel Collector StatefulSet's PodSpec.
	// +optional
	Spec *OTelCollectorStatefulSetPodSpec `json:"spec,omitempty"`
}

// OTelCollectorStatefulSetPodSpec is the OTel Collector StatefulSet's PodSpec.
type OTelCollectorStatefulSetPodSpec struct {
	// Affinity is a group of affinity scheduling rules for the OTel Collector pods.
	// +optional
	Affinity *corev1.Affinity `json:"affinity"`
	// Containers is a list of OTel Collector containers.
	// If specified, this overrides the specified OTel Collector StatefulSet containers.
	// If omitted, the OTel Collector StatefulSet will use its default values for its containers.
	// +optional
	Containers []OTelCollectorStatefulSetContainer `json:"containers,omitempty"`
	// NodeSelector gives more control over the nodes where the OTel Collector pods will run on.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// TopologySpreadConstraints describes how a group of pods ought to spread across topology
	// domains. Scheduler will schedule pods in a way which abides by the constraints.
	// All topologySpreadConstraints are ANDed.
	// +optional
	TopologySpreadConstraints []corev1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
	// Tolerations is the OTel Collector pod's tolerations.
	// If specified, this overrides any tolerations that may be set on the OTel Collector StatefulSet.
	// If omitted, the OTel Collector StatefulSet will use its default value for tolerations.
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations"`
	// PriorityClassName allows to specify a PriorityClass resource to be used.
	// +optional
	PriorityClassName string `json:"priorityClassName,omitempty"`
}

// OTelCollectorStatefulSetContainer is an OTel Collector StatefulSet container.
type OTelCollectorStatefulSetContainer struct {
	// Name is an enum which identifies the OTel Collector StatefulSet container by name.
	// Supported values are: otel-collector
	// +kubebuilder:validation:Enum=otel-collector
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named OTel Collector StatefulSet container's resources.
	// If omitted, the OTel Collector StatefulSet will use its default value for this container's resources.
	// +optional
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`

	// ReadinessProbe allows customization of the readiness probe timing parameters.
	// The probe handler is set by the operator and cannot be overridden.
	// +optional
	ReadinessProbe *ProbeOverride `json:"readinessProbe,omitempty"`

	// LivenessProbe allows customization of the liveness probe timing parameters.
	// The probe handler is set by the operator and cannot be overridden.
	// +optional
	LivenessProbe *ProbeOverride `json:"livenessProbe,omitempty"`
}
