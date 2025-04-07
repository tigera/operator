// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

// {{ .StructPrefix }}Deployment is the configuration for the {{ .Name }} Deployment.
type {{ .StructPrefix }}Deployment struct {
{{- if deploymentMetaDataOverrideEnabled }}
	// Metadata is a subset of a Kubernetes object's metadata that is added to the Deployment.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`
{{- end }}
	// Spec is the specification of the {{ .Name }} Deployment.
	// +optional
	Spec *{{ .StructPrefix }}DeploymentSpec `json:"spec,omitempty"`
}

// {{ .StructPrefix }}DeploymentSpec defines configuration for the {{ .Name }} Deployment.
type {{ .StructPrefix }}DeploymentSpec struct {
	// MinReadySeconds is the minimum number of seconds for which a newly created Deployment pod should
	// be ready without any of its container crashing, for it to be considered available.
	// If specified, this overrides any minReadySeconds value that may be set on the {{ .Name }} Deployment.
	// If omitted, the {{ .Name }} Deployment will use its default value for minReadySeconds.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=2147483647
	MinReadySeconds *int32 `json:"minReadySeconds,omitempty"`

	// Template describes the {{ .Name }} Deployment pod that will be created.
	// +optional
	Template *{{ .StructPrefix }}DeploymentPodTemplateSpec `json:"template,omitempty"`
{{- if strategyOverrideEnabled }}
	// The deployment strategy to use to replace existing pods with new ones.
	// +optional
	// +patchStrategy=retainKeys
	Strategy *{{ .StructPrefix }}DeploymentStrategy `json:"strategy,omitempty" patchStrategy:"retainKeys" protobuf:"bytes,4,opt,name=strategy"`
{{- end }}
}

// {{ .StructPrefix }}DeploymentPodTemplateSpec is the {{ .Name }} Deployment's PodTemplateSpec
type {{ .StructPrefix }}DeploymentPodTemplateSpec struct {
{{- if podMetaDataOverrideEnabled }}
    // Metadata is a subset of a Kubernetes object's metadata that is added to the pod's metadata.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`
{{- end }}
    // Spec is the {{ .Name }} Deployment's PodSpec.
	// +optional
	Spec *{{ .StructPrefix }}DeploymentPodSpec `json:"spec,omitempty"`
}

// {{- .StructPrefix }}DeploymentPodSpec is the {{ .Name }} Deployment's PodSpec.
type {{ .StructPrefix }}DeploymentPodSpec struct {
{{- if affinityOverrideEnabled }}
    // Affinity is a group of affinity scheduling rules for the {{ .Name }} pods.
	// +optional
	Affinity *corev1.Affinity `json:"affinity"`
{{- end }}
{{- if resourcesOverrideEnabled }}
    // Containers is a list of {{ .Name }} containers.
	// If specified, this overrides the specified EGW Deployment containers.
	// If omitted, the {{ .Name }} Deployment will use its default values for its containers.
	// +optional
	Containers []{{ .StructPrefix }}DeploymentContainer `json:"containers,omitempty"`
{{- end }}
{{- if nodeSelectorOverrideEnabled }}
    // NodeSelector gives more control over the nodes where the {{ .Name }} pods will run on.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
{{- end }}
{{- if terminationGracePeriodSecondsOverrideEnabled }}
    // TerminationGracePeriodSeconds defines the termination grace period of the {{ .Name }} pods in seconds.
	// +optional
	// +kubebuilder:validation:Minimum=0
	TerminationGracePeriodSeconds *int64 `json:"terminationGracePeriodSeconds,omitempty"`
{{- end }}
{{- if topologySpreadConstraintsOverrideEnabled }}
	// TopologySpreadConstraints describes how a group of pods ought to spread across topology
	// domains. Scheduler will schedule pods in a way which abides by the constraints.
	// All topologySpreadConstraints are ANDed.
	// +optional
	TopologySpreadConstraints []corev1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
{{- end }}
{{- if tolerationsOverrideEnabled }}
    // Tolerations is the {{ .Name }} pod's tolerations.
	// If specified, this overrides any tolerations that may be set on the {{ .Name }} Deployment.
	// If omitted, the {{ .Name }} Deployment will use its default value for tolerations.
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations"`
{{- end }}
{{- if priorityClassOverrideEnabled }}
    // PriorityClassName allows to specify a PriorityClass resource to be used.
	// +optional
	PriorityClassName string `json:"priorityClassName,omitempty"`
{{- end }}
}
{{- if resourcesOverrideEnabled }}
type {{ .StructPrefix }}DeploymentContainer struct {
	// +kubebuilder:validation:Enum={{ join .ContainerNames ";" }}
	Name string `json:"name"`

	// +optional
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`
}
{{- end }}
{{- if strategyOverrideEnabled }}
type {{ .StructPrefix }}DeploymentStrategy struct {
	// Rolling update config params. Present only if DeploymentStrategyType =
	// RollingUpdate.
	// to be.
	// +optional
	RollingUpdate *appsv1.RollingUpdateDeployment `json:"rollingUpdate,omitempty" protobuf:"bytes,2,opt,name=rollingUpdate"`
}
{{- end }}