package v1

import (
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

// WhiskerDeployment is the configuration for the whisker Deployment.
type WhiskerDeployment struct {

	// Metadata is a subset of a Kubernetes object's metadata that is added to the Deployment.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`

	// Spec is the specification of the typha Deployment.
	// +optional
	Spec *WhiskerDeploymentSpec `json:"spec,omitempty"`
}

type WhiskerDeploymentSpec struct {
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
	Template *WhiskerDeploymentPodTemplateSpec `json:"template,omitempty"`

	// The deployment strategy to use to replace existing pods with new ones.
	// +optional
	// +patchStrategy=retainKeys
	Strategy *WhiskerDeploymentStrategy `json:"strategy,omitempty" patchStrategy:"retainKeys" protobuf:"bytes,4,opt,name=strategy"`
}

type WhiskerDeploymentPodTemplateSpec struct {

	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`

	// +optional
	Spec *WhiskerDeploymentPodSpec `json:"spec,omitempty"`
}

// WhiskerDeploymentPodSpec is the whisker Deployment's PodSpec.
type WhiskerDeploymentPodSpec struct {

	// +optional
	Affinity *corev1.Affinity `json:"affinity"`

	// +optional
	Containers []WhiskerDeploymentContainer `json:"containers,omitempty"`

	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// TopologySpreadConstraints describes how a group of pods ought to spread across topology
	// domains. Scheduler will schedule pods in a way which abides by the constraints.
	// All topologySpreadConstraints are ANDed.
	// +optional
	TopologySpreadConstraints []corev1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`

	// +optional
	Tolerations []corev1.Toleration `json:"tolerations"`
}

type WhiskerDeploymentContainer struct {
	// +kubebuilder:validation:Enum=whisker;whisker-backend
	Name string `json:"name"`

	// +optional
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`
}

type WhiskerDeploymentStrategy struct {
	// Rolling update config params. Present only if DeploymentStrategyType =
	// RollingUpdate.
	// to be.
	// +optional
	RollingUpdate *appsv1.RollingUpdateDeployment `json:"rollingUpdate,omitempty" protobuf:"bytes,2,opt,name=rollingUpdate"`
}
