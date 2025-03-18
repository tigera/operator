package v1

import (
	corev1 "k8s.io/api/core/v1"
)

// GoldmaneDeployment is the configuration for the whisker Deployment.
type GoldmaneDeployment struct {

	// Spec is the specification of the typha Deployment.
	// +optional
	Spec *GoldmaneDeploymentSpec `json:"spec,omitempty"`
}

type GoldmaneDeploymentSpec struct {
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
	Template *GoldmaneDeploymentPodTemplateSpec `json:"template,omitempty"`
}

type GoldmaneDeploymentPodTemplateSpec struct {

	// +optional
	Spec *GoldmaneDeploymentPodSpec `json:"spec,omitempty"`
}

// GoldmaneDeploymentPodSpec is the goldmane Deployment's PodSpec.
type GoldmaneDeploymentPodSpec struct {

	// +optional
	Containers []GoldmaneDeploymentContainer `json:"containers,omitempty"`
}

type GoldmaneDeploymentContainer struct {
	// +kubebuilder:validation:Enum=goldmane
	Name string `json:"name"`

	// +optional
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`
}
