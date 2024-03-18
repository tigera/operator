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

// EKSLogForwarderDeployment is the configuration for the EKSLogForwarder Deployment.
type EKSLogForwarderDeployment struct {

	// Spec is the specification of the EKSLogForwarder Deployment.
	// +optional
	Spec *EKSLogForwarderDeploymentSpec `json:"spec,omitempty"`
}

// EKSLogForwarderDeploymentSpec defines configuration for the EKSLogForwarder Deployment.
type EKSLogForwarderDeploymentSpec struct {

	// Template describes the EKSLogForwarder Deployment pod that will be created.
	// +optional
	Template *EKSLogForwarderDeploymentPodTemplateSpec `json:"template,omitempty"`
}

// EKSLogForwarderDeploymentPodTemplateSpec is the EKSLogForwarder Deployment's PodTemplateSpec
type EKSLogForwarderDeploymentPodTemplateSpec struct {

	// Spec is the EKSLogForwarder Deployment's PodSpec.
	// +optional
	Spec *EKSLogForwarderDeploymentPodSpec `json:"spec,omitempty"`
}

// EKSLogForwarderDeploymentPodSpec is the EKSLogForwarder Deployment's PodSpec.
type EKSLogForwarderDeploymentPodSpec struct {
	// InitContainers is a list of EKSLogForwarder init containers.
	// If specified, this overrides the specified EKSLogForwarder Deployment init containers.
	// If omitted, the EKSLogForwarder Deployment will use its default values for its init containers.
	// +optional
	InitContainers []EKSLogForwarderDeploymentInitContainer `json:"initContainers,omitempty"`

	// Containers is a list of EKSLogForwarder containers.
	// If specified, this overrides the specified EKSLogForwarder Deployment containers.
	// If omitted, the EKSLogForwarder Deployment will use its default values for its containers.
	// +optional
	Containers []EKSLogForwarderDeploymentContainer `json:"containers,omitempty"`
}

// EKSLogForwarderDeploymentContainer is a EKSLogForwarder Deployment container.
type EKSLogForwarderDeploymentContainer struct {
	// Name is an enum which identifies the EKSLogForwarder Deployment container by name.
	// Supported values are: eks-log-forwarder
	// +kubebuilder:validation:Enum=eks-log-forwarder
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named EKSLogForwarder Deployment container's resources.
	// If omitted, the EKSLogForwarder Deployment will use its default value for this container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

// EKSLogForwarderDeploymentInitContainer is a EKSLogForwarder Deployment init container.
type EKSLogForwarderDeploymentInitContainer struct {
	// Name is an enum which identifies the EKSLogForwarder Deployment init container by name.
	// Supported values are: eks-log-forwarder-startup
	// +kubebuilder:validation:Enum=eks-log-forwarder-startup
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named EKSLogForwarder Deployment init container's resources.
	// If omitted, the EKSLogForwarder Deployment will use its default value for this init container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

func (c *EKSLogForwarderDeployment) GetMetadata() *Metadata {
	return nil
}

func (c *EKSLogForwarderDeployment) GetMinReadySeconds() *int32 {
	return nil
}

func (c *EKSLogForwarderDeployment) GetPodTemplateMetadata() *Metadata {
	return nil
}

func (c *EKSLogForwarderDeployment) GetInitContainers() []v1.Container {
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

func (c *EKSLogForwarderDeployment) GetContainers() []v1.Container {
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

func (c *EKSLogForwarderDeployment) GetAffinity() *v1.Affinity {
	return nil
}

func (c *EKSLogForwarderDeployment) GetTopologySpreadConstraints() []v1.TopologySpreadConstraint {
	return nil
}

func (c *EKSLogForwarderDeployment) GetNodeSelector() map[string]string {
	return nil
}

func (c *EKSLogForwarderDeployment) GetTolerations() []v1.Toleration {
	return nil
}

func (c *EKSLogForwarderDeployment) GetTerminationGracePeriodSeconds() *int64 {
	return nil
}

func (c *EKSLogForwarderDeployment) GetDeploymentStrategy() *appsv1.DeploymentStrategy {
	return nil
}

func (c *EKSLogForwarderDeployment) GetPriorityClassName() string {
	return ""
}
