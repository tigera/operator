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
	// Reference to a custom EnvoyGateway YAML to use as the base EnvoyGateway configuration for
	// the gateway controller.  When specified, only the `name` and `namespace` fields of the
	// ObjectReference are significant, and they must identify an existing ConfigMap resource
	// with an "envoy-gateway.yaml" key whose value is the desired EnvoyGateway YAML
	// (i.e. following the same pattern as the default `envoy-gateway-config` ConfigMap).
	// Please note, it is not possible to create an EnvoyGateway resource outside of a ConfigMap
	// because the EnvoyGateway type does not include name or namespace fields.
	//
	// When not specified, the Tigera operator uses the `envoy-gateway-config` from the Envoy
	// Gateway helm chart as its base.
	//
	// Starting from that base, the Tigera operator copies and modifies the EnvoyGateway
	// resource as follows:
	//
	// 1. If not already specified, it sets the ControllerName to
	// "gateway.envoyproxy.io/gatewayclass-controller".
	//
	// 2. It configures the `tigera/envoy-gateway` and `tigera/envoy-ratelimit` images that will
	// be used (according to the current Calico version, private registry and image set
	// settings) and any pull secrets that are needed to pull those images.
	//
	// 3. It enables use of the Backend API.
	//
	// The resulting EnvoyGateway is provisioned as the `envoy-gateway-config` ConfigMap (which
	// the gateway controller then uses as its config).
	EnvoyGatewayRef *v1.ObjectReference `json:"envoyGatewayRef,omitempty"`

	// Allow optional customization of the GatewayClasses that will be available; please see
	// GatewayClassSpec for more detail.  If GatewayClasses is nil, the Tigera operator
	// configures a single GatewayClass named "tigera-gateway-class" without any of the
	// enhanced customizations that are allowed by GatewayClassSpec.
	GatewayClasses []GatewayClassSpec `json:"gatewayClasses,omitempty"`

	// Allow optional customization of the gateway controller deployment.
	GatewayControllerDeployment *GatewayControllerDeployment `json:"gatewayControllerDeployment,omitempty"`

	// Allow optional customization of the gateway certgen job.
	GatewayCertgenJob *GatewayCertgenJob `json:"gatewayCertgenJob,omitempty"`

	// Allow optional customization of gateway deployments (or daemonsets) and services.  These
	// customizations will apply to all of the GatewayClasses that the Tigera operator
	// provisions.  GatewayClass-specific customizations can be specified in
	// `GatewayClasses[*].GatewayDeployment`.
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

type GatewayClassSpec struct {
	// The name of this GatewayClass.
	Name string `json:"name,omitempty"`

	// Reference to a custom EnvoyProxy resource to use as the base EnvoyProxy configuration for
	// this GatewayClass.  When specified, only the `name` and `namespace` fields of the
	// ObjectReference are significant, and they must identify an existing EnvoyProxy resource.
	//
	// When not specified, the Tigera operator uses an empty EnvoyProxy resource as its base.
	//
	// Starting from that base, the Tigera operator copies and modifies the EnvoyProxy resource
	// as follows, in the order described:
	//
	// 1. It configures the `tigera/envoy-proxy` image that will be used (according to the
	// current Calico version, private registry and image set settings) and any pull secrets
	// that are needed to pull that image.
	//
	// 2. It applies common customizations as specified by the `GatewayDeployment` field at the
	// top level of this GatewayAPI resource's Spec.
	//
	// 3. It applies GatewayClass-specific customizations as specified by the following
	// `GatewayDeployment` field.
	//
	// The resulting EnvoyProxy is provisioned in the `tigera-gateway` namespace, together with
	// a GatewayClass that references it.
	//
	// If a custom EnvoyProxy resource is specified and uses `EnvoyDaemonSet` instead of the
	// default `EnvoyDeployment`, deployment-related customizations will be applied within
	// `EnvoyDaemonSet` instead of within `EnvoyDeployment`.
	EnvoyProxyRef *v1.ObjectReference `json:"envoyProxyRef,omitempty"`

	// Allow class-specific customization of gateway deployments (or daemonsets) and services,
	// for Gateways in this GatewayClass.
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
// If GatewayControllerDeployment.Spec.Replicas is non-nil it customizes the number of replicas for
// the deployment.
//
// If GatewayControllerDeployment.Spec.MinReadySeconds is non-nil, it sets the minReadySeconds field
// for the deployment.
//
// For customization of the pod template see GatewayControllerDeploymentPodTemplate.
type GatewayControllerDeploymentSpec struct {
	// +optional
	Replicas *int32 `json:"replicas,omitempty"`

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
// If GatewayControllerDeployment.Spec.Template.Spec.TopologySpreadConstraints is non-nil, it sets the
// topology spread constraints of the deployment's pod template.
//
// For customization of container resources see GatewayControllerDeploymentContainer.
type GatewayControllerDeploymentPodSpec struct {
	// +optional
	Affinity *v1.Affinity `json:"affinity"`

	// +optional
	Containers []GatewayControllerDeploymentContainer `json:"containers,omitempty"`

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

	// +optional
	Service *GatewayService `json:"service,omitempty"`
}

// GatewayDeploymentSpec allows customization of the spec of gateway deployments.
//
// If Replicas is non-nil it customizes the number of replicas for each gateway deployment.
//
// For customization of the pod template see GatewayDeploymentPodTemplate.
//
// For customization of the deployment strategy see GatewayDeploymentStrategy.
//
// If GatewayKind is set to "DaemonSet", gateways (in the relevant GatewayClass) are deployed as
// Kubernetes DaemonSets instead of as Deployments.  Note, GatewayKind is ignored when a custom
// EnvoyProxy is specified and that EnvoyProxy already indicates whether to deploy as a DaemonSet or
// as a Deployment.
type GatewayDeploymentSpec struct {
	// +optional
	Replicas *int32 `json:"replicas,omitempty"`

	// +optional
	Template *GatewayDeploymentPodTemplate `json:"template,omitempty"`

	// The deployment strategy to use to replace existing pods with new ones.
	// +optional
	// +patchStrategy=retainKeys
	Strategy *GatewayDeploymentStrategy `json:"strategy,omitempty" patchStrategy:"retainKeys" protobuf:"bytes,4,opt,name=strategy"`

	// +optional
	GatewayKind *GatewayKind `json:"gatewayKind,omitempty"`
}

type GatewayKind string

const (
	GatewayKindDeployment GatewayKind = "Deployment"
	GatewayKindDaemonSet  GatewayKind = "DaemonSet"
)

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

// GatewayService allows customization of the services that front gateway deployments.
//
// If Metadata is non-nil, non-clashing labels and annotations from that metadata are added into the
// each Gateway service's metadata.
//
// For customization of the service spec see GatewayServiceSpec.
type GatewayService struct {
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`

	// +optional
	Spec *GatewayServiceSpec `json:"spec,omitempty"`
}

// GatewayServiceSpec allows customization of the services that front gateway deployments.
//
// The LoadBalancer fields allow customization of the corresponding fields in the Kubernetes
// ServiceSpec.  These can be used for some cloud-independent control of the external load balancer
// that is provisioned for each Gateway.  For finer-grained cloud-specific control please use
// the Metadata.Annotations field in GatewayService.
//
// For customization of the service spec see GatewayServiceSpec.
type GatewayServiceSpec struct {
	// +optional
	LoadBalancerClass *string `json:"loadBalancerClass,omitempty"`

	// +optional
	AllocateLoadBalancerNodePorts *bool `json:"allocateLoadBalancerNodePorts,omitempty"`

	// +optional
	LoadBalancerSourceRanges []string `json:"loadBalancerSourceRanges,omitempty"`

	// +optional
	LoadBalancerIP *string `json:"loadBalancerIP,omitempty"`
}
