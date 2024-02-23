// Copyright (c) 2023-2024 Tigera, Inc. All rights reserved.
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

// LinseedDeployment is the configuration for the linseed Deployment.
type LinseedDeployment struct {

	// Spec is the specification of the linseed Deployment.
	// +optional
	Spec *LinseedDeploymentSpec `json:"spec,omitempty"`
}

// LinseedDeploymentSpec defines configuration for the linseed Deployment.
type LinseedDeploymentSpec struct {

	// Template describes the linseed Deployment pod that will be created.
	// +optional
	Template *LinseedDeploymentPodTemplateSpec `json:"template,omitempty"`
}

// LinseedDeploymentPodTemplateSpec is the linseed Deployment's PodTemplateSpec
type LinseedDeploymentPodTemplateSpec struct {

	// Spec is the linseed Deployment's PodSpec.
	// +optional
	Spec *LinseedDeploymentPodSpec `json:"spec,omitempty"`
}

// LinseedDeploymentPodSpec is the linseed Deployment's PodSpec.
type LinseedDeploymentPodSpec struct {
	// InitContainers is a list of linseed init containers.
	// If specified, this overrides the specified linseed Deployment init containers.
	// If omitted, the linseed Deployment will use its default values for its init containers.
	// +optional
	InitContainers []LinseedDeploymentInitContainer `json:"initContainers,omitempty"`

	// Containers is a list of linseed containers.
	// If specified, this overrides the specified linseed Deployment containers.
	// If omitted, the linseed Deployment will use its default values for its containers.
	// +optional
	Containers []LinseedDeploymentContainer `json:"containers,omitempty"`
}

// LinseedDeploymentContainer is a linseed Deployment container.
type LinseedDeploymentContainer struct {
	// Name is an enum which identifies the linseed Deployment container by name.
	// +kubebuilder:validation:Enum=tigera-linseed
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named linseed Deployment container's resources.
	// If omitted, the linseed Deployment will use its default value for this container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

// LinseedDeploymentInitContainer is a linseed Deployment init container.
type LinseedDeploymentInitContainer struct {
	// Name is an enum which identifies the linseed Deployment init container by name.
	// +kubebuilder:validation:Enum=tigera-secure-linseed-token-tls-key-cert-provisioner;tigera-secure-linseed-cert-key-cert-provisioner
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named linseed Deployment init container's resources.
	// If omitted, the linseed Deployment will use its default value for this init container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

func (c *LinseedDeployment) GetMetadata() *Metadata {
	return nil
}

func (c *LinseedDeployment) GetMinReadySeconds() *int32 {
	return nil
}

func (c *LinseedDeployment) GetPodTemplateMetadata() *Metadata {
	return nil
}

func (c *LinseedDeployment) GetInitContainers() []v1.Container {
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

func (c *LinseedDeployment) GetContainers() []v1.Container {
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

func (c *LinseedDeployment) GetAffinity() *v1.Affinity {
	return nil
}

func (c *LinseedDeployment) GetTopologySpreadConstraints() []v1.TopologySpreadConstraint {
	return nil
}

func (c *LinseedDeployment) GetNodeSelector() map[string]string {
	return nil
}

func (c *LinseedDeployment) GetTolerations() []v1.Toleration {
	return nil
}

func (c *LinseedDeployment) GetTerminationGracePeriodSeconds() *int64 {
	return nil
}

func (c *LinseedDeployment) GetDeploymentStrategy() *appsv1.DeploymentStrategy {
	return nil
}

func (c *LinseedDeployment) GetPriorityClassName() string {
	return ""
}
