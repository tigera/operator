// Copyright (c) 2020-2024 Tigera, Inc. All rights reserved.
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

// APIServerSpec defines the desired state of Tigera API server.
type APIServerSpec struct {
	// APIServerDeployment configures the calico-apiserver (or tigera-apiserver in Enterprise) Deployment. If
	// used in conjunction with ControlPlaneNodeSelector or ControlPlaneTolerations, then these overrides
	// take precedence.
	APIServerDeployment *APIServerDeployment `json:"apiServerDeployment,omitempty"`
}

// APIServerStatus defines the observed state of Tigera API server.
type APIServerStatus struct {
	// State provides user-readable status.
	State string `json:"state,omitempty"`

	// Conditions represents the latest observed set of conditions for the component. A component may be one or more of
	// Ready, Progressing, Degraded or other customer types.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// APIServer installs the Tigera API server and related resources. At most one instance
// of this resource is supported. It must be named "default" or "tigera-secure".
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
type APIServer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the desired state for the Tigera API server.
	Spec APIServerSpec `json:"spec,omitempty"`

	// Most recently observed status for the Tigera API server.
	Status APIServerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// APIServerList contains a list of APIServer
type APIServerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []APIServer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&APIServer{}, &APIServerList{})
}

// APIServerDeploymentContainer is an API server Deployment container.
type APIServerDeploymentContainer struct {
	// Name is an enum which identifies the API server Deployment container by name.
	// +kubebuilder:validation:Enum=calico-apiserver;tigera-queryserver
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named API server Deployment container's resources.
	// If omitted, the API server Deployment will use its default value for this container's resources.
	// If used in conjunction with the deprecated ComponentResources, then this value takes precedence.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

// APIServerDeploymentInitContainer is an API server Deployment init container.
type APIServerDeploymentInitContainer struct {
	// Name is an enum which identifies the API server Deployment init container by name.
	// +kubebuilder:validation:Enum=calico-apiserver-certs-key-cert-provisioner
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named API server Deployment init container's resources.
	// If omitted, the API server Deployment will use its default value for this init container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

// APIServerDeploymentDeploymentPodSpec is the API server Deployment's PodSpec.
type APIServerDeploymentPodSpec struct {
	// InitContainers is a list of API server init containers.
	// If specified, this overrides the specified API server Deployment init containers.
	// If omitted, the API server Deployment will use its default values for its init containers.
	// +optional
	InitContainers []APIServerDeploymentInitContainer `json:"initContainers,omitempty"`

	// Containers is a list of API server containers.
	// If specified, this overrides the specified API server Deployment containers.
	// If omitted, the API server Deployment will use its default values for its containers.
	// +optional
	Containers []APIServerDeploymentContainer `json:"containers,omitempty"`

	// Affinity is a group of affinity scheduling rules for the API server pods.
	// If specified, this overrides any affinity that may be set on the API server Deployment.
	// If omitted, the API server Deployment will use its default value for affinity.
	// WARNING: Please note that this field will override the default API server Deployment affinity.
	// +optional
	Affinity *v1.Affinity `json:"affinity,omitempty"`

	// NodeSelector is the API server pod's scheduling constraints.
	// If specified, each of the key/value pairs are added to the API server Deployment nodeSelector provided
	// the key does not already exist in the object's nodeSelector.
	// If used in conjunction with ControlPlaneNodeSelector, that nodeSelector is set on the API server Deployment
	// and each of this field's key/value pairs are added to the API server Deployment nodeSelector provided
	// the key does not already exist in the object's nodeSelector.
	// If omitted, the API server Deployment will use its default value for nodeSelector.
	// WARNING: Please note that this field will modify the default API server Deployment nodeSelector.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// TopologySpreadConstraints describes how a group of pods ought to spread across topology
	// domains. Scheduler will schedule pods in a way which abides by the constraints.
	// All topologySpreadConstraints are ANDed.
	// +optional
	TopologySpreadConstraints []v1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`

	// Tolerations is the API server pod's tolerations.
	// If specified, this overrides any tolerations that may be set on the API server Deployment.
	// If omitted, the API server Deployment will use its default value for tolerations.
	// WARNING: Please note that this field will override the default API server Deployment tolerations.
	// +optional
	Tolerations []v1.Toleration `json:"tolerations,omitempty"`
}

// APIServerDeploymentPodTemplateSpec is the API server Deployment's PodTemplateSpec
type APIServerDeploymentPodTemplateSpec struct {
	// Metadata is a subset of a Kubernetes object's metadata that is added to
	// the pod's metadata.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`

	// Spec is the API server Deployment's PodSpec.
	// +optional
	Spec *APIServerDeploymentPodSpec `json:"spec,omitempty"`
}

// APIServerDeployment is the configuration for the API server Deployment.
type APIServerDeployment struct {
	// Metadata is a subset of a Kubernetes object's metadata that is added to the Deployment.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`

	// Spec is the specification of the API server Deployment.
	// +optional
	Spec *APIServerDeploymentSpec `json:"spec,omitempty"`
}

// APIServerDeploymentSpec defines configuration for the API server Deployment.
type APIServerDeploymentSpec struct {
	// MinReadySeconds is the minimum number of seconds for which a newly created Deployment pod should
	// be ready without any of its container crashing, for it to be considered available.
	// If specified, this overrides any minReadySeconds value that may be set on the API server Deployment.
	// If omitted, the API server Deployment will use its default value for minReadySeconds.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=2147483647
	MinReadySeconds *int32 `json:"minReadySeconds,omitempty"`

	// Template describes the API server Deployment pod that will be created.
	// +optional
	Template *APIServerDeploymentPodTemplateSpec `json:"template,omitempty"`
}

func (c *APIServerDeployment) GetMetadata() *Metadata {
	return c.Metadata
}

func (c *APIServerDeployment) GetMinReadySeconds() *int32 {
	if c.Spec != nil {
		return c.Spec.MinReadySeconds
	}
	return nil
}

func (c *APIServerDeployment) GetPodTemplateMetadata() *Metadata {
	if c.Spec != nil {
		if c.Spec.Template != nil {
			return c.Spec.Template.Metadata
		}
	}
	return nil
}

func (c *APIServerDeployment) GetInitContainers() []v1.Container {
	if c.Spec != nil {
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

func (c *APIServerDeployment) GetContainers() []v1.Container {
	if c.Spec != nil {
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

func (c *APIServerDeployment) GetAffinity() *v1.Affinity {
	if c.Spec != nil {
		if c.Spec.Template != nil {
			if c.Spec.Template.Spec != nil {
				return c.Spec.Template.Spec.Affinity
			}
		}
	}
	return nil
}

func (c *APIServerDeployment) GetTopologySpreadConstraints() []v1.TopologySpreadConstraint {
	if c.Spec != nil {
		if c.Spec.Template != nil {
			if c.Spec.Template.Spec != nil {
				return c.Spec.Template.Spec.TopologySpreadConstraints
			}
		}
	}
	return nil
}

func (c *APIServerDeployment) GetNodeSelector() map[string]string {
	if c.Spec != nil {
		if c.Spec.Template != nil {
			if c.Spec.Template.Spec != nil {
				return c.Spec.Template.Spec.NodeSelector
			}
		}
	}
	return nil
}

func (c *APIServerDeployment) GetTolerations() []v1.Toleration {
	if c.Spec != nil {
		if c.Spec.Template != nil {
			if c.Spec.Template.Spec != nil {
				return c.Spec.Template.Spec.Tolerations
			}
		}
	}
	return nil
}

func (c *APIServerDeployment) GetTerminationGracePeriodSeconds() *int64 {
	return nil
}

func (c *APIServerDeployment) GetDeploymentStrategy() *appsv1.DeploymentStrategy {
	return nil
}

func (c *APIServerDeployment) GetPriorityClassName() string {
	return ""
}
