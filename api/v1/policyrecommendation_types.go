// Copyright (c) 2023 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v1

import (
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PolicyRecommendationSpec defines configuration for the Calico Enterprise Policy Recommendation
// service.
type PolicyRecommendationSpec struct {

	// Template describes the PolicyRecommendation Deployment pod that will be created.
	// +optional
	Template *PolicyRecommendationDeploymentPodTemplateSpec `json:"template,omitempty"`
}

// PolicyRecommendationDeploymentPodTemplateSpec is the Manager Deployment's PodTemplateSpec
type PolicyRecommendationDeploymentPodTemplateSpec struct {
	// Metadata is a subset of a Kubernetes object's metadata that is added to
	// the pod's metadata.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`

	// Spec is the PolicyRecommendation Deployment's PodSpec.
	// +optional
	Spec *PolicyRecommendationPodSpec `json:"spec,omitempty"`
}

// PolicyRecommendationPodSpec is the Manager Deployment's PodSpec.
type PolicyRecommendationPodSpec struct {
	// InitContainers is a list of PolicyRecommendation init containers.
	// If specified, this overrides the specified PolicyRecommendation Deployment init containers.
	// If omitted, the PolicyRecommendation Deployment will use its default values for its init containers.
	// +optional
	InitContainers []PolicyRecommendationInitContainer `json:"initContainers,omitempty"`

	// Containers is a list of Manager containers.
	// If specified, this overrides the specified Manager Deployment containers.
	// If omitted, the Manager Deployment will use its default values for its containers.
	// +optional
	Containers []PolicyRecommendationContainer `json:"containers,omitempty"`
}

// PolicyRecommendationContainer is a PolicyRecommendation Deployment container.
type PolicyRecommendationContainer struct {
	// Name is an enum which identifies the PolicyRecommendation Deployment container by name.
	// +kubebuilder:validation:Enum=policy-recommendation-controller
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named PolicyRecommendation Deployment container's resources.
	// If omitted, the PolicyRecommendation Deployment will use its default value for this container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

// PolicyRecommendationInitContainer is a PolicyRecommendation Deployment init container.
type PolicyRecommendationInitContainer struct {
	// Name is an enum which identifies the PolicyRecommendation Deployment init container by name.
	// +kubebuilder:validation:Enum=policy-recommendation-tls-key-cert-provisioner
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named Manager Deployment init container's resources.
	// If omitted, the PolicyRecommendation Deployment will use its default value for this init container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

// PolicyRecommendationStatus defines the observed state of Tigera policy recommendation.
type PolicyRecommendationStatus struct {
	// State provides user-readable status.
	State string `json:"state,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:subresource:status

// PolicyRecommendation is the Schema for the policy recommendation API. At most one instance
// of this resource is supported. It must be named "tigera-secure".
type PolicyRecommendation struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PolicyRecommendationSpec   `json:"spec,omitempty"`
	Status PolicyRecommendationStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// PolicyRecommendationList contains a list of Monitor
type PolicyRecommendationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PolicyRecommendation `json:"items"`
}

func (c *PolicyRecommendation) GetMetadata() *Metadata {
	return nil
}

func (c *PolicyRecommendation) GetMinReadySeconds() *int32 {
	return nil
}

func (c *PolicyRecommendation) GetPodTemplateMetadata() *Metadata {
	return nil
}

func (c *PolicyRecommendation) GetInitContainers() []v1.Container {
	if !c.isEmptyPolicyRecommendationSpec(c.Spec) {
		if c.Spec.Template != nil {
			if c.Spec.Template.Spec != nil {
				if c.Spec.Template.Spec.InitContainers != nil {
					cs := make([]v1.Container, len(c.Spec.Template.Spec.InitContainers))
					for i, v := range c.Spec.Template.Spec.InitContainers {
						// Only copy and return the init container if it has resources set.
						if v.Resources == nil {
							continue
						}
						c := v1.Container{Name: v.Name, Resources: *v.Resources}
						cs[i] = c
					}
					return cs
				}
			}
		}
	}
	return nil
}

func (c *PolicyRecommendation) GetContainers() []v1.Container {
	if !c.isEmptyPolicyRecommendationSpec(c.Spec) {
		if c.Spec.Template != nil {
			if c.Spec.Template.Spec != nil {
				if c.Spec.Template.Spec.Containers != nil {
					cs := make([]v1.Container, len(c.Spec.Template.Spec.Containers))
					for i, v := range c.Spec.Template.Spec.Containers {
						// Only copy and return the container if it has resources set.
						if v.Resources == nil {
							continue
						}
						c := v1.Container{Name: v.Name, Resources: *v.Resources}
						cs[i] = c
					}
					return cs
				}
			}
		}
	}
	return nil
}

func (c *PolicyRecommendation) GetAffinity() *v1.Affinity {
	return nil
}

func (c *PolicyRecommendation) GetTopologySpreadConstraints() []v1.TopologySpreadConstraint {
	return nil
}

func (c *PolicyRecommendation) GetNodeSelector() map[string]string {
	return nil
}

func (c *PolicyRecommendation) GetTolerations() []v1.Toleration {
	return nil
}

func (c *PolicyRecommendation) GetTerminationGracePeriodSeconds() *int64 {
	return nil
}

func (c *PolicyRecommendation) GetDeploymentStrategy() *appsv1.DeploymentStrategy {
	return nil
}

func (c *PolicyRecommendation) isEmptyPolicyRecommendationSpec(spec PolicyRecommendationSpec) bool {
	return spec == PolicyRecommendationSpec{}
}

func init() {
	SchemeBuilder.Register(&PolicyRecommendation{}, &PolicyRecommendationList{})
}
