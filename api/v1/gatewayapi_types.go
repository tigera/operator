// Copyright (c) 2024 Tigera, Inc. All rights reserved.
/*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GatewayAPISpec has fields that can be used to customize our GatewayAPI support.
type GatewayAPISpec struct {
	// Allow optional customization of the gateway controller deployment.
	GatewayControllerDeployment *GatewayControllerDeployment `json:"gatewayControllerDeployment,omitempty"`

	// Allow optional customization of the gateway certgen job.
	GatewayCertgenJob *GatewayCertgenJob `json:"gatewayCertgenJob,omitempty"`

	// Allow optional customization of gateway deployments.
	GatewayDeployment *GatewayDeployment `json:"gatewayDeployment,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:resource:scope=Cluster

type GatewayAPI struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec GatewayAPISpec `json:"spec,omitempty"`
}

//+kubebuilder:object:root=true

type GatewayAPIList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GatewayAPI `json:"items"`
}

func init() {
	SchemeBuilder.Register(&GatewayAPI{}, &GatewayAPIList{})
}

// Optional customization of the gateway controller deployment.
//
// If GatewayControllerDeployment.Metadata is non-nil, non-clashing labels and annotations from that
// metadata are added into the deployment's top-level metadata.
//
// For customization of the deployment spec see GatewayControllerDeploymentSpec.
type GatewayControllerDeployment struct {
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`

	// +optional
	Spec *GatewayControllerDeploymentSpec `json:"spec,omitempty"`
}

// Optional customization of the gateway controller deployment.
//
// If GatewayControllerDeployment.Spec.MinReadySeconds is non-nil, it sets the minReadySeconds field
// for the deployment.
//
// For customization of the pod template see GatewayControllerDeploymentPodTemplate.
type GatewayControllerDeploymentSpec struct {
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=2147483647
	MinReadySeconds *int32 `json:"minReadySeconds,omitempty"`

	// +optional
	Template *GatewayControllerDeploymentPodTemplate `json:"template,omitempty"`
}

// Optional customization of the gateway controller deployment.
//
// If GatewayControllerDeployment.Spec.Template.Metadata is non-nil, non-clashing labels and
// annotations from that metadata are added into the deployment's pod template.
//
// For customization of the pod template spec see GatewayControllerDeploymentPodSpec.
type GatewayControllerDeploymentPodTemplate struct {
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`

	// +optional
	Spec *GatewayControllerDeploymentPodSpec `json:"spec,omitempty"`
}

// Optional customization of the gateway controller deployment.
//
// If GatewayControllerDeployment.Spec.Template.Spec.Affinity is non-nil, it sets the affinity field
// of the deployment's pod template.
//
// If GatewayControllerDeployment.Spec.Template.Spec.Containers["envoy-gateway"].Resources is
// non-nil, it overrides the ResourceRequirements of the controller's "envoy-gateway" container.
//
// If GatewayControllerDeployment.Spec.Template.Spec.NodeSelector is non-nil, it sets a node
// selector for where controller pods may be scheduled.
//
// If GatewayControllerDeployment.Spec.Template.Spec.Tolerations is non-nil, it sets the tolerations
// field of the deployment's pod template.
type GatewayControllerDeploymentPodSpec struct {
	// +optional
	Affinity *v1.Affinity `json:"affinity"`

	// +optional
	Containers []GatewayControllerDeploymentContainer `json:"containers,omitempty"`

	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// +optional
	Tolerations []v1.Toleration `json:"tolerations"`
}

// See GatewayControllerDeploymentPodSpec for how this struct can be used.
type GatewayControllerDeploymentContainer struct {
	// +kubebuilder:validation:Enum=envoy-gateway
	Name string `json:"name"`

	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

// Optional customization of the gateway certgen job.
//
// If GatewayCertgenJob.Metadata is non-nil, non-clashing labels and annotations from that metadata
// are added into the job's top-level metadata.
//
// For customization of the job spec see GatewayCertgenJobSpec.
type GatewayCertgenJob struct {
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`

	// +optional
	Spec *GatewayCertgenJobSpec `json:"spec,omitempty"`
}

// Optional customization of the gateway certgen job.
//
// For customization of the job template see GatewayCertgenJobPodTemplate.
type GatewayCertgenJobSpec struct {
	// +optional
	Template *GatewayCertgenJobPodTemplate `json:"template,omitempty"`
}

// Optional customization of the gateway certgen job.
//
// If GatewayCertgenJob.Spec.Template.Metadata is non-nil, non-clashing labels and
// annotations from that metadata are added into the job's pod template.
//
// For customization of the pod template spec see GatewayCertgenJobPodSpec.
type GatewayCertgenJobPodTemplate struct {
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`

	// +optional
	Spec *GatewayCertgenJobPodSpec `json:"spec,omitempty"`
}

// Optional customization of the gateway certgen job.
//
// If GatewayCertgenJob.Spec.Template.Spec.Affinity is non-nil, it sets the affinity field of the
// job's pod template.
//
// If GatewayCertgenJob.Spec.Template.Spec.Containers["envoy-gateway-certgen"].Resources is non-nil,
// it overrides the ResourceRequirements of the job's "envoy-gateway-certgen" container.
//
// If GatewayCertgenJob.Spec.Template.Spec.NodeSelector is non-nil, it sets a node selector for
// where job pods may be scheduled.
//
// If GatewayCertgenJob.Spec.Template.Spec.Tolerations is non-nil, it sets the tolerations field of
// the job's pod template.
type GatewayCertgenJobPodSpec struct {
	// +optional
	Affinity *v1.Affinity `json:"affinity"`

	// +optional
	Containers []GatewayCertgenJobContainer `json:"containers,omitempty"`

	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// +optional
	Tolerations []v1.Toleration `json:"tolerations"`
}

// See GatewayCertgenJobPodSpec for how this struct can be used.
type GatewayCertgenJobContainer struct {
	// +kubebuilder:validation:Enum=envoy-gateway-certgen
	Name string `json:"name"`

	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

// Optional customization of gateway deployments.
//
// For customization of the deployment spec see GatewayDeploymentSpec.
type GatewayDeployment struct {
	// +optional
	Spec *GatewayDeploymentSpec `json:"spec,omitempty"`
}

// Optional customization of gateway deployments.
//
// For customization of the pod template see GatewayDeploymentPodTemplate.
type GatewayDeploymentSpec struct {
	// +optional
	Template *GatewayDeploymentPodTemplate `json:"template,omitempty"`

	// The deployment strategy to use to replace existing pods with new ones.
	// +optional
	// +patchStrategy=retainKeys
	Strategy *GatewayDeploymentStrategy `json:"strategy,omitempty" patchStrategy:"retainKeys" protobuf:"bytes,4,opt,name=strategy"`
}

// Optional customization of gateway deployments.
//
// If GatewayDeployment.Spec.Template.Metadata is non-nil, non-clashing labels and annotations from
// that metadata are added into the deployment's pod template.
//
// For customization of the pod template spec see GatewayDeploymentPodSpec.
type GatewayDeploymentPodTemplate struct {
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`

	// +optional
	Spec *GatewayDeploymentPodSpec `json:"spec,omitempty"`
}

// Optional customization of gateway deployments.
//
// If GatewayDeployment.Spec.Template.Spec.Affinity is non-nil, it sets the affinity field of the
// deployment's pod template.
//
// If GatewayDeployment.Spec.Template.Spec.Containers["envoy"].Resources is non-nil, it
// overrides the ResourceRequirements of the "envoy" container.
//
// If GatewayDeployment.Spec.Template.Spec.NodeSelector is non-nil, it sets a node selector for
// where gateway pods may be scheduled.
//
// If GatewayDeployment.Spec.Template.Spec.Tolerations is non-nil, it sets the tolerations field of
// the deployment's pod template.
type GatewayDeploymentPodSpec struct {
	// +optional
	Affinity *v1.Affinity `json:"affinity"`

	// +optional
	Containers []GatewayDeploymentContainer `json:"containers,omitempty"`

	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// TopologySpreadConstraints describes how a group of pods ought to spread across topology
	// domains. Scheduler will schedule pods in a way which abides by the constraints.
	// All topologySpreadConstraints are ANDed.
	// +optional
	TopologySpreadConstraints []v1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`

	// +optional
	Tolerations []v1.Toleration `json:"tolerations"`
}

// See GatewayDeploymentPodSpec for how this struct can be used.
type GatewayDeploymentContainer struct {
	// +kubebuilder:validation:Enum=envoy
	Name string `json:"name"`

	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

// GatewayDeploymentStrategy describes how to replace existing pods with new ones.  Only RollingUpdate is supported
// at this time so the Type field is not exposed.
type GatewayDeploymentStrategy struct {
	// Rolling update config params. Present only if DeploymentStrategyType =
	// RollingUpdate.
	// to be.
	// +optional
	RollingUpdate *appsv1.RollingUpdateDeployment `json:"rollingUpdate,omitempty" protobuf:"bytes,2,opt,name=rollingUpdate"`
}
