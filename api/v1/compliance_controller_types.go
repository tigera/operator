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

// ComplianceControllerDeployment is the configuration for the compliance controller Deployment.
type ComplianceControllerDeployment struct {

	// Spec is the specification of the compliance controller Deployment.
	// +optional
	Spec *ComplianceControllerDeploymentSpec `json:"spec,omitempty"`
}

// ComplianceControllerDeploymentSpec defines configuration for the compliance controller Deployment.
type ComplianceControllerDeploymentSpec struct {

	// Template describes the compliance controller Deployment pod that will be created.
	// +optional
	Template *ComplianceControllerDeploymentPodTemplateSpec `json:"template,omitempty"`
}

// ComplianceControllerDeploymentPodTemplateSpec is the compliance controller Deployment's PodTemplateSpec
type ComplianceControllerDeploymentPodTemplateSpec struct {

	// Spec is the compliance controller Deployment's PodSpec.
	// +optional
	Spec *ComplianceControllerDeploymentPodSpec `json:"spec,omitempty"`
}

// ComplianceControllerDeploymentPodSpec is the compliance controller Deployment's PodSpec.
type ComplianceControllerDeploymentPodSpec struct {
	// InitContainers is a list of compliance controller init containers.
	// If specified, this overrides the specified compliance controller Deployment init containers.
	// If omitted, the compliance controller Deployment will use its default values for its init containers.
	// +optional
	InitContainers []ComplianceControllerDeploymentInitContainer `json:"initContainers,omitempty"`

	// Containers is a list of compliance controller containers.
	// If specified, this overrides the specified compliance controller Deployment containers.
	// If omitted, the compliance controller Deployment will use its default values for its containers.
	// +optional
	Containers []ComplianceControllerDeploymentContainer `json:"containers,omitempty"`
}

// ComplianceControllerDeploymentContainer is a compliance controller Deployment container.
type ComplianceControllerDeploymentContainer struct {
	// Name is an enum which identifies the compliance controller Deployment container by name.
	// Supported values are: compliance-controller
	// +kubebuilder:validation:Enum=compliance-controller
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named compliance controller Deployment container's resources.
	// If omitted, the compliance controller Deployment will use its default value for this container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

// ComplianceControllerDeploymentInitContainer is a compliance controller Deployment init container.
type ComplianceControllerDeploymentInitContainer struct {
	// Name is an enum which identifies the compliance controller Deployment init container by name.
	// Supported values are: tigera-compliance-controller-tls-key-cert-provisioner
	// +kubebuilder:validation:Enum=tigera-compliance-controller-tls-key-cert-provisioner
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named compliance controller Deployment init container's resources.
	// If omitted, the compliance controller Deployment will use its default value for this init container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

func (c *ComplianceControllerDeployment) GetMetadata() *Metadata {
	return nil
}

func (c *ComplianceControllerDeployment) GetMinReadySeconds() *int32 {
	return nil
}

func (c *ComplianceControllerDeployment) GetPodTemplateMetadata() *Metadata {
	return nil
}

func (c *ComplianceControllerDeployment) GetInitContainers() []v1.Container {
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

func (c *ComplianceControllerDeployment) GetContainers() []v1.Container {
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

func (c *ComplianceControllerDeployment) GetAffinity() *v1.Affinity {
	return nil
}

func (c *ComplianceControllerDeployment) GetTopologySpreadConstraints() []v1.TopologySpreadConstraint {
	return nil
}

func (c *ComplianceControllerDeployment) GetNodeSelector() map[string]string {
	return nil
}

func (c *ComplianceControllerDeployment) GetTolerations() []v1.Toleration {
	return nil
}

func (c *ComplianceControllerDeployment) GetTerminationGracePeriodSeconds() *int64 {
	return nil
}

func (c *ComplianceControllerDeployment) GetDeploymentStrategy() *appsv1.DeploymentStrategy {
	return nil
}

func (c *ComplianceControllerDeployment) GetPriorityClassName() string {
	return ""
}
