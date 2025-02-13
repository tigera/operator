// Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.
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

	// Configure how to manage and update Gateway API CRDs.  The default behaviour - which is
	// used when this field is not set, or is set to "PreferExisting" - is that the Tigera
	// operator will create the Gateway API CRDs if they do not already exist, but will not
	// overwrite any existing Gateway API CRDs.  This setting may be preferable if the customer
	// is using other implementations of the Gateway API concurrently with the Gateway API
	// support in Calico Enterprise.  It is then the customer's responsibility to ensure that
	// CRDs are installed that meet the needs of all the Gateway API implementations in their
	// cluster.
	//
	// Alternatively, if this field is set to "Reconcile", the Tigera operator will keep the
	// cluster's Gateway API CRDs aligned with those that it would install on a cluster that
	// does not yet have any version of those CRDs.
	CRDManagement *CRDManagement `json:"crdManagement,omitempty"`
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

// GatewayControllerDeployment allows customization of the gateway controller deployment.
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

// GatewayControllerDeploymentSpec allows customization of the gateway controller deployment spec.
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

// GatewayControllerDeploymentPodTemplate allows customization of the gateway controller deployment
// pod template.
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

// GatewayControllerDeploymentPodSpec allows customization of the gateway controller deployment pod
// spec.
//
// If GatewayControllerDeployment.Spec.Template.Spec.Affinity is non-nil, it sets the affinity field
// of the deployment's pod template.
//
// If GatewayControllerDeployment.Spec.Template.Spec.NodeSelector is non-nil, it sets a node
// selector for where controller pods may be scheduled.
//
// If GatewayControllerDeployment.Spec.Template.Spec.Tolerations is non-nil, it sets the tolerations
// field of the deployment's pod template.
//
// For customization of container resources see GatewayControllerDeploymentContainer.
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

// GatewayControllerDeploymentContainer allows customization of the gateway controller's resource
// requirements.
//
// If GatewayControllerDeployment.Spec.Template.Spec.Containers["envoy-gateway"].Resources is
// non-nil, it overrides the ResourceRequirements of the controller's "envoy-gateway" container.
type GatewayControllerDeploymentContainer struct {
	// +kubebuilder:validation:Enum=envoy-gateway
	Name string `json:"name"`

	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

// GatewayCertgenJob allows customization of the gateway certgen job.
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

// GatewayCertgenJobSpec allows customization of the gateway certgen job spec.
//
// For customization of the job template see GatewayCertgenJobPodTemplate.
type GatewayCertgenJobSpec struct {
	// +optional
	Template *GatewayCertgenJobPodTemplate `json:"template,omitempty"`
}

// GatewayCertgenJobPodTemplate allows customization of the gateway certgen job's pod template.
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

// GatewayCertgenJobPodSpec allows customization of the gateway certgen job's pod spec.
//
// If GatewayCertgenJob.Spec.Template.Spec.Affinity is non-nil, it sets the affinity field of the
// job's pod template.
//
// If GatewayCertgenJob.Spec.Template.Spec.NodeSelector is non-nil, it sets a node selector for
// where job pods may be scheduled.
//
// If GatewayCertgenJob.Spec.Template.Spec.Tolerations is non-nil, it sets the tolerations field of
// the job's pod template.
//
// For customization of job container resources see GatewayCertgenJobContainer.
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

// GatewayCertgenJobContainer allows customization of the gateway certgen job's resource
// requirements.
//
// If GatewayCertgenJob.Spec.Template.Spec.Containers["envoy-gateway-certgen"].Resources is non-nil,
// it overrides the ResourceRequirements of the job's "envoy-gateway-certgen" container.
type GatewayCertgenJobContainer struct {
	// +kubebuilder:validation:Enum=envoy-gateway-certgen
	Name string `json:"name"`

	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

// GatewayDeployment allows customization of gateway deployments.
//
// For detail see GatewayDeploymentSpec.
type GatewayDeployment struct {
	// +optional
	Spec *GatewayDeploymentSpec `json:"spec,omitempty"`
}

// GatewayDeploymentSpec allows customization of the spec of gateway deployments.
//
// For customization of the pod template see GatewayDeploymentPodTemplate.
//
// For customization of the deployment strategy see GatewayDeploymentStrategy.
type GatewayDeploymentSpec struct {
	// +optional
	Template *GatewayDeploymentPodTemplate `json:"template,omitempty"`

	// The deployment strategy to use to replace existing pods with new ones.
	// +optional
	// +patchStrategy=retainKeys
	Strategy *GatewayDeploymentStrategy `json:"strategy,omitempty" patchStrategy:"retainKeys" protobuf:"bytes,4,opt,name=strategy"`
}

// GatewayDeploymentPodTemplate allows customization of the pod template of gateway deployments.
//
// If GatewayDeployment.Spec.Template.Metadata is non-nil, non-clashing labels and annotations from
// that metadata are added into each deployment's pod template.
//
// For customization of the pod template spec see GatewayDeploymentPodSpec.
type GatewayDeploymentPodTemplate struct {
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`

	// +optional
	Spec *GatewayDeploymentPodSpec `json:"spec,omitempty"`
}

// GatewayDeploymentPodSpec allows customization of the pod spec of gateway deployments.
//
// If GatewayDeployment.Spec.Template.Spec.Affinity is non-nil, it sets the affinity field of each
// deployment's pod template.
//
// If GatewayDeployment.Spec.Template.Spec.NodeSelector is non-nil, it sets a node selector for
// where gateway pods may be scheduled.
//
// If GatewayDeployment.Spec.Template.Spec.Tolerations is non-nil, it sets the tolerations field of
// each deployment's pod template.
//
// If GatewayDeployment.Spec.Template.Spec.TopologySpreadConstraints is non-nil, it sets the
// topology spread constraints of each deployment's pod template.
//
// For customization of container resources see GatewayControllerDeploymentContainer.
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

// GatewayDeploymentContainer allows customization of the resource requirements of gateway
// deployments.
//
// If GatewayDeployment.Spec.Template.Spec.Containers["envoy"].Resources is non-nil, it overrides
// the ResourceRequirements of the "envoy" container in each gateway deployment.
type GatewayDeploymentContainer struct {
	// +kubebuilder:validation:Enum=envoy
	Name string `json:"name"`

	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

// GatewayDeploymentStrategy allows customization of the deployment strategy for gateway
// deployments.
//
// If GatewayDeployment.Spec.Strategy is non-nil, gateway deployments are set to use a rolling
// update strategy, with the parameters specified in GatewayDeployment.Spec.Strategy.
//
// Only RollingUpdate is supported at this time so the Type field is not exposed.
type GatewayDeploymentStrategy struct {
	// +optional
	RollingUpdate *appsv1.RollingUpdateDeployment `json:"rollingUpdate,omitempty" protobuf:"bytes,2,opt,name=rollingUpdate"`
}
