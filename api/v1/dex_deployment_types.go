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
)

// DexDeployment is the configuration for the Dex Deployment.
type DexDeployment struct {

	// Spec is the specification of the Dex Deployment.
	// +optional
	Spec *DexDeploymentSpec `json:"spec,omitempty"`
}

// DexDeploymentSpec defines configuration for the Dex Deployment.
type DexDeploymentSpec struct {

	// Template describes the Dex Deployment pod that will be created.
	// +optional
	Template *DexDeploymentPodTemplateSpec `json:"template,omitempty"`
}

// DexDeploymentPodTemplateSpec is the Dex Deployment's PodTemplateSpec
type DexDeploymentPodTemplateSpec struct {

	// Spec is the Dex Deployment's PodSpec.
	// +optional
	Spec *DexDeploymentPodSpec `json:"spec,omitempty"`
}

// DexDeploymentPodSpec is the Dex Deployment's PodSpec.
type DexDeploymentPodSpec struct {
	// InitContainers is a list of Dex init containers.
	// If specified, this overrides the specified Dex Deployment init containers.
	// If omitted, the Dex Deployment will use its default values for its init containers.
	// +optional
	InitContainers []DexDeploymentInitContainer `json:"initContainers,omitempty"`

	// Containers is a list of Dex containers.
	// If specified, this overrides the specified Dex Deployment containers.
	// If omitted, the Dex Deployment will use its default values for its containers.
	// +optional
	Containers []DexDeploymentContainer `json:"containers,omitempty"`
}

// DexDeploymentContainer is a Dex Deployment container.
type DexDeploymentContainer struct {
	// Name is an enum which identifies the Dex Deployment container by name.
	// +kubebuilder:validation:Enum=tigera-dex
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named Dex Deployment container's resources.
	// If omitted, the Dex Deployment will use its default value for this container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

// DexDeploymentInitContainer is a Dex Deployment init container.
type DexDeploymentInitContainer struct {
	// Name is an enum which identifies the Dex Deployment init container by name.
	// +kubebuilder:validation:Enum=tigera-dex-tls-key-cert-provisioner
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named Dex Deployment init container's resources.
	// If omitted, the Dex Deployment will use its default value for this init container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

func (c *DexDeployment) GetMetadata() *Metadata {
	return nil
}

func (c *DexDeployment) GetMinReadySeconds() *int32 {
	return nil
}

func (c *DexDeployment) GetPodTemplateMetadata() *Metadata {
	return nil
}

func (c *DexDeployment) GetInitContainers() []v1.Container {
	if c != nil {
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

func (c *DexDeployment) GetContainers() []v1.Container {
	if c != nil {
		if c.Spec != nil {
			if c.Spec.Template != nil {
				if c.Spec.Template.Spec != nil {
					if c.Spec.Template.Spec.Containers != nil {
						cs := make([]v1.Container, len(c.Spec.Template.Spec.Containers))
						for i, v := range c.Spec.Template.Spec.Containers {
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
	}
	return nil
}

func (c *DexDeployment) GetAffinity() *v1.Affinity {
	return nil
}

func (c *DexDeployment) GetTopologySpreadConstraints() []v1.TopologySpreadConstraint {
	return nil
}

func (c *DexDeployment) GetNodeSelector() map[string]string {
	return nil
}

func (c *DexDeployment) GetTolerations() []v1.Toleration {
	return nil
}

func (c *DexDeployment) GetTerminationGracePeriodSeconds() *int64 {
	return nil
}

func (c *DexDeployment) GetDeploymentStrategy() *appsv1.DeploymentStrategy {
	return nil
}

func (c *DexDeployment) GetPriorityClassName() string {
	return ""
}
