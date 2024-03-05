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

// ComplianceReportPodTemplate is the configuration for the ComplianceReport PodTemplate.
type ComplianceReportPodTemplate struct {

	// Spec is the specification of the ComplianceReport PodTemplateSpec.
	// +optional
	Template *ComplianceReportPodTemplateSpec `json:"spec,omitempty"`
}

// ComplianceReportPodTemplateSpec is the ComplianceReport PodTemplateSpec.
type ComplianceReportPodTemplateSpec struct {

	// Spec is the ComplianceReport PodTemplate's PodSpec.
	// +optional
	Spec *ComplianceReportPodSpec `json:"spec,omitempty"`
}

// ComplianceReportPodSpec is the ComplianceReport PodSpec.
type ComplianceReportPodSpec struct {
	// InitContainers is a list of ComplianceReport PodSpec init containers.
	// If specified, this overrides the specified ComplianceReport PodSpec init containers.
	// If omitted, the ComplianceServer Deployment will use its default values for its init containers.
	// +optional
	InitContainers []ComplianceReportPodTemplateInitContainer `json:"initContainers,omitempty"`

	// Containers is a list of ComplianceServer containers.
	// If specified, this overrides the specified ComplianceReport PodSpec containers.
	// If omitted, the ComplianceServer Deployment will use its default values for its containers.
	// +optional
	Containers []ComplianceReportPodTemplateContainer `json:"containers,omitempty"`
}

// ComplianceReportPodTemplateContainer is a ComplianceServer Deployment container.
type ComplianceReportPodTemplateContainer struct {
	// Name is an enum which identifies the ComplianceServer Deployment container by name.
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named ComplianceServer Deployment container's resources.
	// If omitted, the ComplianceServer Deployment will use its default value for this container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

// ComplianceReportPodTemplateInitContainer is a ComplianceServer Deployment init container.
type ComplianceReportPodTemplateInitContainer struct {
	// Name is an enum which identifies the ComplianceReport PodSpec init container by name.
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named ComplianceReport PodSpec init container's resources.
	// If omitted, the ComplianceServer Deployment will use its default value for this init container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

func (c *ComplianceReportPodTemplate) GetMetadata() *Metadata {
	return nil
}

func (c *ComplianceReportPodTemplate) GetMinReadySeconds() *int32 {
	return nil
}

func (c *ComplianceReportPodTemplate) GetPodTemplateMetadata() *Metadata {
	return nil
}

func (c *ComplianceReportPodTemplate) GetInitContainers() []v1.Container {
	if c.Template != nil {
		if c.Template.Spec != nil {
			if c.Template.Spec.InitContainers != nil {
				cs := make([]v1.Container, len(c.Template.Spec.InitContainers))
				for i, v := range c.Template.Spec.InitContainers {
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
	return nil
}

func (c *ComplianceReportPodTemplate) GetContainers() []v1.Container {
	if c.Template != nil {
		if c.Template.Spec != nil {
			if c.Template.Spec.Containers != nil {
				cs := make([]v1.Container, len(c.Template.Spec.Containers))
				for i, v := range c.Template.Spec.Containers {
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
	return nil
}

func (c *ComplianceReportPodTemplate) GetAffinity() *v1.Affinity {
	return nil
}

func (c *ComplianceReportPodTemplate) GetTopologySpreadConstraints() []v1.TopologySpreadConstraint {
	return nil
}

func (c *ComplianceReportPodTemplate) GetNodeSelector() map[string]string {
	return nil
}

func (c *ComplianceReportPodTemplate) GetTolerations() []v1.Toleration {
	return nil
}

func (c *ComplianceReportPodTemplate) GetTerminationGracePeriodSeconds() *int64 {
	return nil
}

func (c *ComplianceReportPodTemplate) GetDeploymentStrategy() *appsv1.DeploymentStrategy {
	return nil
}

func (c *ComplianceReportPodTemplate) GetPriorityClassName() string {
	return ""
}
