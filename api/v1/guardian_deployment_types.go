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

// GuardianDeployment is the configuration for the guardian Deployment.
type GuardianDeployment struct {

	// Spec is the specification of the guardian Deployment.
	// +optional
	Spec *GuardianDeploymentSpec `json:"spec,omitempty"`
}

// GuardianDeploymentSpec defines configuration for the guardian Deployment.
type GuardianDeploymentSpec struct {

	// Template describes the guardian Deployment pod that will be created.
	// +optional
	Template *GuardianDeploymentPodTemplateSpec `json:"template,omitempty"`
}

// GuardianDeploymentPodTemplateSpec is the guardian Deployment's PodTemplateSpec
type GuardianDeploymentPodTemplateSpec struct {

	// Spec is the guardian Deployment's PodSpec.
	// +optional
	Spec *GuardianDeploymentPodSpec `json:"spec,omitempty"`
}

// GuardianDeploymentPodSpec is the guardian Deployment's PodSpec.
type GuardianDeploymentPodSpec struct {
	// InitContainers is a list of guardian init containers.
	// If specified, this overrides the specified guardian Deployment init containers.
	// If omitted, the guardian Deployment will use its default values for its init containers.
	// +optional
	InitContainers []GuardianDeploymentInitContainer `json:"initContainers,omitempty"`

	// Containers is a list of guardian containers.
	// If specified, this overrides the specified guardian Deployment containers.
	// If omitted, the guardian Deployment will use its default values for its containers.
	// +optional
	Containers []GuardianDeploymentContainer `json:"containers,omitempty"`
}

// GuardianDeploymentContainer is a guardian Deployment container.
type GuardianDeploymentContainer struct {
	// Name is an enum which identifies the guardian Deployment container by name.
	// Supported values are: tigera-guardian
	// +kubebuilder:validation:Enum=tigera-guardian
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named guardian Deployment container's resources.
	// If omitted, the guardian Deployment will use its default value for this container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

// GuardianDeploymentInitContainer is a guardian Deployment init container.
type GuardianDeploymentInitContainer struct {
	// Name is an enum which identifies the guardian Deployment init container by name.
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named guardian Deployment init container's resources.
	// If omitted, the guardian Deployment will use its default value for this init container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

func (c *GuardianDeployment) GetMetadata() *Metadata {
	return nil
}

func (c *GuardianDeployment) GetMinReadySeconds() *int32 {
	return nil
}

func (c *GuardianDeployment) GetPodTemplateMetadata() *Metadata {
	return nil
}

func (c *GuardianDeployment) GetInitContainers() []v1.Container {
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

func (c *GuardianDeployment) GetContainers() []v1.Container {
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

func (c *GuardianDeployment) GetAffinity() *v1.Affinity {
	return nil
}

func (c *GuardianDeployment) GetTopologySpreadConstraints() []v1.TopologySpreadConstraint {
	return nil
}

func (c *GuardianDeployment) GetNodeSelector() map[string]string {
	return nil
}

func (c *GuardianDeployment) GetTolerations() []v1.Toleration {
	return nil
}

func (c *GuardianDeployment) GetTerminationGracePeriodSeconds() *int64 {
	return nil
}

func (c *GuardianDeployment) GetDeploymentStrategy() *appsv1.DeploymentStrategy {
	return nil
}

func (c *GuardianDeployment) GetPriorityClassName() string {
	return ""
}
