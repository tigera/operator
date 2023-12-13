// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.
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

// ManagerSpec defines configuration for the Calico Enterprise manager GUI.
type ManagerSpec struct {
	// Deprecated. Please use the Authentication CR for configuring authentication.
	// +optional
	Auth *Auth `json:"auth,omitempty"`

	// Template describes the Manager Deployment pod that will be created.
	// +optional
	Template *ManagerDeploymentPodTemplateSpec `json:"template,omitempty"`
}

// ManagerDeploymentPodTemplateSpec is the Manager Deployment's PodTemplateSpec
type ManagerDeploymentPodTemplateSpec struct {
	// Metadata is a subset of a Kubernetes object's metadata that is added to
	// the pod's metadata.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`

	// Spec is the Manager Deployment's PodSpec.
	// +optional
	Spec *ManagerDeploymentPodSpec `json:"spec,omitempty"`
}

// ManagerDeploymentPodSpec is the Manager Deployment's PodSpec.
type ManagerDeploymentPodSpec struct {
	// InitContainers is a list of Manager init containers.
	// If specified, this overrides the specified Manager Deployment init containers.
	// If omitted, the Manager Deployment will use its default values for its init containers.
	// +optional
	InitContainers []ManagerDeploymentInitContainer `json:"initContainers,omitempty"`

	// Containers is a list of Manager containers.
	// If specified, this overrides the specified Manager Deployment containers.
	// If omitted, the Manager Deployment will use its default values for its containers.
	// +optional
	Containers []ManagerDeploymentContainer `json:"containers,omitempty"`
}

// ManagerDeploymentContainer is a Manager Deployment container.
type ManagerDeploymentContainer struct {
	// Name is an enum which identifies the Manager Deployment container by name.
	// +kubebuilder:validation:Enum=tigera-voltron;tigera-manager;tigera-es-proxy
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named Manager Deployment container's resources.
	// If omitted, the Manager Deployment will use its default value for this container's resources.
	// If used in conjunction with the deprecated ComponentResources, then this value takes precedence.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

// ManagerDeploymentInitContainer is a Manager Deployment init container.
type ManagerDeploymentInitContainer struct {
	// Name is an enum which identifies the Manager Deployment init container by name.
	// +kubebuilder:validation:Enum=manager-tls-key-cert-provisioner;internal-manager-tls-key-cert-provisioner;tigera-voltron-linseed-tls-key-cert-provisioner
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named Manager Deployment init container's resources.
	// If omitted, the Manager Deployment will use its default value for this init container's resources.
	// If used in conjunction with the deprecated ComponentResources, then this value takes precedence.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

// ManagerStatus defines the observed state of the Calico Enterprise manager GUI.
type ManagerStatus struct {
	// Deprecated. Please use the Authentication CR for configuring authentication.
	// +optional
	Auth *Auth `json:"auth,omitempty"`

	// State provides user-readable status.
	State string `json:"state,omitempty"`

	// Conditions represents the latest observed set of conditions for the component. A component may be one or more of
	// Ready, Progressing, Degraded or other customer types.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// Auth defines authentication configuration.
type Auth struct {
	// Type configures the type of authentication used by the manager.
	// Default: Token
	// +kubebuilder:validation:Enum=Token;Basic;OIDC;OAuth
	Type AuthType `json:"type,omitempty"`

	// Authority configures the OAuth2/OIDC authority/issuer when using OAuth2 or OIDC login.
	// +optional
	Authority string `json:"authority,omitempty"`

	// ClientId configures the OAuth2/OIDC client ID to use for OAuth2 or OIDC login.
	// +optional
	ClientID string `json:"clientID,omitempty"`
}

// AuthType represents the type of authentication to use. Valid
// options are: Token, Basic, OIDC, OAuth
type AuthType string

const (
	AuthTypeToken = "Token"
	AuthTypeBasic = "Basic"
	AuthTypeOIDC  = "OIDC"
	AuthTypeOAuth = "OAuth"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster

// Manager installs the Calico Enterprise manager graphical user interface. At most one instance
// of this resource is supported. It must be named "tigera-secure".
type Manager struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the desired state for the Calico Enterprise manager.
	Spec ManagerSpec `json:"spec,omitempty"`
	// Most recently observed state for the Calico Enterprise manager.
	Status ManagerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ManagerList contains a list of Manager
type ManagerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Manager `json:"items"`
}

func (c *Manager) isEmptyManagerSpec(obj ManagerSpec) bool {
	return obj == ManagerSpec{}
}

func (c *Manager) GetMetadata() *Metadata {
	return nil
}

func (c *Manager) GetMinReadySeconds() *int32 {
	return nil
}

func (c *Manager) GetPodTemplateMetadata() *Metadata {
	return nil
}

func (c *Manager) GetInitContainers() []v1.Container {
	if !c.isEmptyManagerSpec(c.Spec) {
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

func (c *Manager) GetContainers() []v1.Container {
	if !c.isEmptyManagerSpec(c.Spec) {
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

func (c *Manager) GetAffinity() *v1.Affinity {
	return nil
}

func (c *Manager) GetTopologySpreadConstraints() []v1.TopologySpreadConstraint {
	return nil
}

func (c *Manager) GetNodeSelector() map[string]string {
	return nil
}

func (c *Manager) GetTolerations() []v1.Toleration {
	return nil
}

func (c *Manager) GetTerminationGracePeriodSeconds() *int64 {
	return nil
}

func (c *Manager) GetDeploymentStrategy() *appsv1.DeploymentStrategy {
	return nil
}

func init() {
	SchemeBuilder.Register(&Manager{}, &ManagerList{})
}
