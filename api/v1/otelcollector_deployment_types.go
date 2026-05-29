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
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

// OpenTelemetryCollectorDeployment is the configuration for the OTel Collector Deployment.
type OpenTelemetryCollectorDeployment struct {
	// Metadata is a subset of a Kubernetes object's metadata that is added to the Deployment.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`
	// Spec is the specification of the OTel Collector Deployment.
	// +optional
	Spec *OpenTelemetryCollectorDeploymentSpec `json:"spec,omitempty"`
}

// OpenTelemetryCollectorDeploymentSpec defines configuration for the OTel Collector Deployment.
type OpenTelemetryCollectorDeploymentSpec struct {
	// MinReadySeconds is the minimum number of seconds for which a newly created Deployment pod should
	// be ready without any of its container crashing, for it to be considered available.
	// If specified, this overrides any minReadySeconds value that may be set on the OTel Collector Deployment.
	// If omitted, the OTel Collector Deployment will use its default value for minReadySeconds.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=2147483647
	MinReadySeconds *int32 `json:"minReadySeconds,omitempty"`

	// Template describes the OTel Collector Deployment pod that will be created.
	// +optional
	Template *OpenTelemetryCollectorDeploymentPodTemplateSpec `json:"template,omitempty"`

	// The deployment strategy to use to replace existing pods with new ones.
	// +optional
	// +patchStrategy=retainKeys
	Strategy *OpenTelemetryCollectorDeploymentStrategy `json:"strategy,omitempty" patchStrategy:"retainKeys"`
}

// OpenTelemetryCollectorDeploymentPodTemplateSpec is the OTel Collector Deployment's PodTemplateSpec.
type OpenTelemetryCollectorDeploymentPodTemplateSpec struct {
	// Metadata is a subset of a Kubernetes object's metadata that is added to the pod's metadata.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`
	// Spec is the OTel Collector Deployment's PodSpec.
	// +optional
	Spec *OpenTelemetryCollectorDeploymentPodSpec `json:"spec,omitempty"`
}

// OpenTelemetryCollectorDeploymentPodSpec is the OTel Collector Deployment's PodSpec.
type OpenTelemetryCollectorDeploymentPodSpec struct {
	// Affinity is a group of affinity scheduling rules for the OTel Collector pods.
	// +optional
	Affinity *corev1.Affinity `json:"affinity"`
	// Containers is a list of OTel Collector containers.
	// If specified, this overrides the specified OTel Collector Deployment containers.
	// If omitted, the OTel Collector Deployment will use its default values for its containers.
	// +optional
	Containers []OpenTelemetryCollectorDeploymentContainer `json:"containers,omitempty"`
	// NodeSelector gives more control over the nodes where the OTel Collector pods will run on.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// TopologySpreadConstraints describes how a group of pods ought to spread across topology
	// domains. Scheduler will schedule pods in a way which abides by the constraints.
	// All topologySpreadConstraints are ANDed.
	// +optional
	TopologySpreadConstraints []corev1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
	// Tolerations is the OTel Collector pod's tolerations.
	// If specified, this overrides any tolerations that may be set on the OTel Collector Deployment.
	// If omitted, the OTel Collector Deployment will use its default value for tolerations.
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations"`
	// PriorityClassName allows to specify a PriorityClass resource to be used.
	// +optional
	PriorityClassName string `json:"priorityClassName,omitempty"`
}

// OpenTelemetryCollectorDeploymentContainer is an OTel Collector Deployment container.
type OpenTelemetryCollectorDeploymentContainer struct {
	// Name is an enum which identifies the OTel Collector Deployment container by name.
	// Supported values are: otel-collector
	// +kubebuilder:validation:Enum=otel-collector
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named OTel Collector Deployment container's resources.
	// If omitted, the OTel Collector Deployment will use its default value for this container's resources.
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

// OpenTelemetryCollectorDeploymentStrategy defines the strategy for the OTel Collector Deployment.
type OpenTelemetryCollectorDeploymentStrategy struct {
	// Rolling update config params. Present only if DeploymentStrategyType = RollingUpdate.
	// +optional
	RollingUpdate *appsv1.RollingUpdateDeployment `json:"rollingUpdate,omitempty"`
}
