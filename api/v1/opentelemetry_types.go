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

// OpenTelemetryLogType represents the allowable log types for OpenTelemetry export.
// +kubebuilder:validation:Enum=Audit;DNS;Flows
type OpenTelemetryLogType string

const (
	OpenTelemetryAuditLog OpenTelemetryLogType = "Audit"
	OpenTelemetryDNSLog   OpenTelemetryLogType = "DNS"
	OpenTelemetryFlowLog  OpenTelemetryLogType = "Flows"
)

// OpenTelemetryLogs configures log export.
type OpenTelemetryLogs struct {
	// Types specifies which log types to export. Supported values: Audit, DNS, Flows.
	// +optional
	Types []OpenTelemetryLogType `json:"types,omitempty"`
}

// OpenTelemetryMetricsEnabled is the option to enable or disable metrics export.
// +kubebuilder:validation:Enum=Enabled;Disabled
type OpenTelemetryMetricsEnabled string

const (
	OpenTelemetryMetricsEnable  OpenTelemetryMetricsEnabled = "Enabled"
	OpenTelemetryMetricsDisable OpenTelemetryMetricsEnabled = "Disabled"
)

// OpenTelemetryMetrics configures metrics export.
type OpenTelemetryMetrics struct {
	// Enabled specifies whether to scrape and export Calico component metrics via OTLP.
	// Default: Disabled
	// +optional
	// +kubebuilder:default=Disabled
	Enabled *OpenTelemetryMetricsEnabled `json:"enabled,omitempty"`
}

// OpenTelemetryExporterProtocol specifies the OTLP transport protocol.
// +kubebuilder:validation:Enum=grpc;http
type OpenTelemetryExporterProtocol string

const (
	OpenTelemetryProtocolGRPC OpenTelemetryExporterProtocol = "grpc"
	OpenTelemetryProtocolHTTP OpenTelemetryExporterProtocol = "http"
)

// OpenTelemetryExporter defines an OTLP export endpoint.
type OpenTelemetryExporter struct {
	// Name is a unique identifier for this exporter. It keys the exporter in the
	// generated collector config, so it must be unique across the list.
	// +required
	Name string `json:"name"`

	// Endpoint is the OTLP endpoint URL.
	// +required
	Endpoint string `json:"endpoint"`

	// Protocol specifies the OTLP transport protocol. Default: grpc.
	// +optional
	// +kubebuilder:default=grpc
	Protocol OpenTelemetryExporterProtocol `json:"protocol,omitempty"`

	// MutualTLS enables client certificate authentication to this exporter's
	// endpoint. The collector presents the keypair from the
	// otel-collector-client-certs Secret in the tigera-operator namespace; that
	// Secret is required when any exporter enables this.
	// Default: false
	// +optional
	// +kubebuilder:default=false
	MutualTLS *bool `json:"mutualTLS,omitempty"`
}

// OpenTelemetryCollectorStatefulSet is the configuration for the OpenTelemetry Collector StatefulSet.
type OpenTelemetryCollectorStatefulSet struct {
	// Metadata is a subset of a Kubernetes object's metadata that is added to the StatefulSet.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`
	// Spec is the specification of the OpenTelemetry Collector StatefulSet.
	// +optional
	Spec *OpenTelemetryCollectorStatefulSetSpec `json:"spec,omitempty"`
}

// OpenTelemetryCollectorStatefulSetSpec defines configuration for the OpenTelemetry Collector StatefulSet.
type OpenTelemetryCollectorStatefulSetSpec struct {
	// MinReadySeconds is the minimum number of seconds for which a newly created StatefulSet pod should
	// be ready without any of its container crashing, for it to be considered available.
	// If specified, this overrides any minReadySeconds value that may be set on the OpenTelemetry Collector StatefulSet.
	// If omitted, the OpenTelemetry Collector StatefulSet will use its default value for minReadySeconds.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=2147483647
	MinReadySeconds *int32 `json:"minReadySeconds,omitempty"`

	// Template describes the OpenTelemetry Collector StatefulSet pod that will be created.
	// +optional
	Template *OpenTelemetryCollectorStatefulSetPodTemplateSpec `json:"template,omitempty"`
}

// OpenTelemetryCollectorStatefulSetPodTemplateSpec is the OpenTelemetry Collector StatefulSet's PodTemplateSpec.
type OpenTelemetryCollectorStatefulSetPodTemplateSpec struct {
	// Metadata is a subset of a Kubernetes object's metadata that is added to the pod's metadata.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`
	// Spec is the OpenTelemetry Collector StatefulSet's PodSpec.
	// +optional
	Spec *OpenTelemetryCollectorStatefulSetPodSpec `json:"spec,omitempty"`
}

// OpenTelemetryCollectorStatefulSetPodSpec is the OpenTelemetry Collector StatefulSet's PodSpec.
type OpenTelemetryCollectorStatefulSetPodSpec struct {
	// Affinity is a group of affinity scheduling rules for the OpenTelemetry Collector pods.
	// +optional
	Affinity *corev1.Affinity `json:"affinity"`
	// Containers is a list of OpenTelemetry Collector containers.
	// If specified, this overrides the specified OpenTelemetry Collector StatefulSet containers.
	// If omitted, the OpenTelemetry Collector StatefulSet will use its default values for its containers.
	// +optional
	Containers []OpenTelemetryCollectorStatefulSetContainer `json:"containers,omitempty"`
	// NodeSelector gives more control over the nodes where the OpenTelemetry Collector pods will run on.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// TopologySpreadConstraints describes how a group of pods ought to spread across topology
	// domains. Scheduler will schedule pods in a way which abides by the constraints.
	// All topologySpreadConstraints are ANDed.
	// +optional
	TopologySpreadConstraints []corev1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
	// Tolerations is the OpenTelemetry Collector pod's tolerations.
	// If specified, this overrides any tolerations that may be set on the OpenTelemetry Collector StatefulSet.
	// If omitted, the OpenTelemetry Collector StatefulSet will use its default value for tolerations.
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations"`
	// PriorityClassName allows to specify a PriorityClass resource to be used.
	// +optional
	PriorityClassName string `json:"priorityClassName,omitempty"`
}

// OpenTelemetryCollectorStatefulSetContainer is an OpenTelemetry Collector StatefulSet container.
type OpenTelemetryCollectorStatefulSetContainer struct {
	// Name is an enum which identifies the OpenTelemetry Collector StatefulSet container by name.
	// Supported values are: otel-collector
	// +kubebuilder:validation:Enum=otel-collector
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named OpenTelemetry Collector StatefulSet container's resources.
	// If omitted, the OpenTelemetry Collector StatefulSet will use its default value for this container's resources.
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
