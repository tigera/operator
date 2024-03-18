// Copyright (c) 2024 Tigera, Inc. All rights reserved.
/*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in with the License.
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
)

// ComplianceServerDeployment is the configuration for the ComplianceServer Deployment.
type ComplianceServerDeployment struct {

	// Spec is the specification of the ComplianceServer Deployment.
	// +optional
	Spec *ComplianceServerDeploymentSpec `json:"spec,omitempty"`
}

// ComplianceServerDeploymentSpec defines configuration for the ComplianceServer Deployment.
type ComplianceServerDeploymentSpec struct {

	// Template describes the ComplianceServer Deployment pod that will be created.
	// +optional
	Template *ComplianceServerDeploymentPodTemplateSpec `json:"template,omitempty"`
}

// ComplianceServerDeploymentPodTemplateSpec is the ComplianceServer Deployment's PodTemplateSpec
type ComplianceServerDeploymentPodTemplateSpec struct {

	// Spec is the ComplianceServer Deployment's PodSpec.
	// +optional
	Spec *ComplianceServerDeploymentPodSpec `json:"spec,omitempty"`
}

// ComplianceServerDeploymentPodSpec is the ComplianceServer Deployment's PodSpec.
type ComplianceServerDeploymentPodSpec struct {
	// InitContainers is a list of ComplianceServer init containers.
	// If specified, this overrides the specified ComplianceServer Deployment init containers.
	// If omitted, the ComplianceServer Deployment will use its default values for its init containers.
	// +optional
	InitContainers []ComplianceServerDeploymentInitContainer `json:"initContainers,omitempty"`

	// Containers is a list of ComplianceServer containers.
	// If specified, this overrides the specified ComplianceServer Deployment containers.
	// If omitted, the ComplianceServer Deployment will use its default values for its containers.
	// +optional
	Containers []ComplianceServerDeploymentContainer `json:"containers,omitempty"`
}

// ComplianceServerDeploymentContainer is a ComplianceServer Deployment container.
type ComplianceServerDeploymentContainer struct {
	// Name is an enum which identifies the ComplianceServer Deployment container by name.
	// Supported values are: compliance-server
	// +kubebuilder:validation:Enum=compliance-server
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named ComplianceServer Deployment container's resources.
	// If omitted, the ComplianceServer Deployment will use its default value for this container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

// ComplianceServerDeploymentInitContainer is a ComplianceServer Deployment init container.
type ComplianceServerDeploymentInitContainer struct {
	// Name is an enum which identifies the ComplianceServer Deployment init container by name.
	// Supported values are: tigera-compliance-server-tls-key-cert-provisioner
	// +kubebuilder:validation:Enum=tigera-compliance-server-tls-key-cert-provisioner
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named ComplianceServer Deployment init container's resources.
	// If omitted, the ComplianceServer Deployment will use its default value for this init container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

func (c *ComplianceServerDeployment) GetMetadata() *Metadata {
	return nil
}

func (c *ComplianceServerDeployment) GetMinReadySeconds() *int32 {
	return nil
}

func (c *ComplianceServerDeployment) GetPodTemplateMetadata() *Metadata {
	return nil
}

func (c *ComplianceServerDeployment) GetInitContainers() []v1.Container {
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

func (c *ComplianceServerDeployment) GetContainers() []v1.Container {
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

func (c *ComplianceServerDeployment) GetAffinity() *v1.Affinity {
	return nil
}

func (c *ComplianceServerDeployment) GetTopologySpreadConstraints() []v1.TopologySpreadConstraint {
	return nil
}

func (c *ComplianceServerDeployment) GetNodeSelector() map[string]string {
	return nil
}

func (c *ComplianceServerDeployment) GetTolerations() []v1.Toleration {
	return nil
}

func (c *ComplianceServerDeployment) GetTerminationGracePeriodSeconds() *int64 {
	return nil
}

func (c *ComplianceServerDeployment) GetDeploymentStrategy() *appsv1.DeploymentStrategy {
	return nil
}

func (c *ComplianceServerDeployment) GetPriorityClassName() string {
	return ""
}
