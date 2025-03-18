package v1

import (
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

// {{ .StructPrefix }}Deployment is the configuration for the whisker Deployment.
type {{ .StructPrefix }}Deployment struct {
{{ if deploymentMetaDataOverrideEnabled }}
	// Metadata is a subset of a Kubernetes object's metadata that is added to the Deployment.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`
{{ end }}
	// Spec is the specification of the typha Deployment.
	// +optional
	Spec *{{ .StructPrefix }}DeploymentSpec `json:"spec,omitempty"`
}

type {{ .StructPrefix }}DeploymentSpec struct {
	// MinReadySeconds is the minimum number of seconds for which a newly created Deployment pod should
	// be ready without any of its container crashing, for it to be considered available.
	// If specified, this overrides any minReadySeconds value that may be set on the typha Deployment.
	// If omitted, the typha Deployment will use its default value for minReadySeconds.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=2147483647
	MinReadySeconds *int32 `json:"minReadySeconds,omitempty"`

	// Template describes the typha Deployment pod that will be created.
	// +optional
	Template *{{ .StructPrefix }}DeploymentPodTemplateSpec `json:"template,omitempty"`
{{ if strategyOverrideEnabled }}
	// The deployment strategy to use to replace existing pods with new ones.
	// +optional
	// +patchStrategy=retainKeys
	Strategy *{{ .StructPrefix }}DeploymentStrategy `json:"strategy,omitempty" patchStrategy:"retainKeys" protobuf:"bytes,4,opt,name=strategy"`
{{ end }}
}

type {{ .StructPrefix }}DeploymentPodTemplateSpec struct {
{{ if podMetaDataOverrideEnabled }}
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`
{{ end }}
	// +optional
	Spec *{{ .StructPrefix }}DeploymentPodSpec `json:"spec,omitempty"`
}

// {{ .StructPrefix }}DeploymentPodSpec is the {{ .Name }} Deployment's PodSpec.
type {{ .StructPrefix }}DeploymentPodSpec struct {
{{ if affinityOverrideEnabled }}
	// +optional
	Affinity *corev1.Affinity `json:"affinity"`
{{ end }}
{{ if resourcesOverrideEnabled }}
	// +optional
	Containers []{{ .StructPrefix }}DeploymentContainer `json:"containers,omitempty"`
{{ end }}
{{ if nodeSelectorOverrideEnabled }}
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
{{ end }}
{{ if topologySpreadConstraintsOverrideEnabled }}
	// TopologySpreadConstraints describes how a group of pods ought to spread across topology
	// domains. Scheduler will schedule pods in a way which abides by the constraints.
	// All topologySpreadConstraints are ANDed.
	// +optional
	TopologySpreadConstraints []corev1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
{{ end }}
{{ if tolerationsOverrideEnabled }}
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations"`
{{ end }}
}
{{ if resourcesOverrideEnabled }}
type {{ .StructPrefix }}DeploymentContainer struct {
	// +kubebuilder:validation:Enum={{ join .ContainerNames ";" }}
	Name string `json:"name"`

	// +optional
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`
}
{{ end }}
{{ if strategyOverrideEnabled }}
type {{ .StructPrefix }}DeploymentStrategy struct {
	// Rolling update config params. Present only if DeploymentStrategyType =
	// RollingUpdate.
	// to be.
	// +optional
	RollingUpdate *appsv1.RollingUpdateDeployment `json:"rollingUpdate,omitempty" protobuf:"bytes,2,opt,name=rollingUpdate"`
}
{{ end }}