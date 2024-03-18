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

// ComplianceSnapshotterDeployment is the configuration for the compliance snapshotter Deployment.
type ComplianceSnapshotterDeployment struct {

	// Spec is the specification of the compliance snapshotter Deployment.
	// +optional
	Spec *ComplianceSnapshotterDeploymentSpec `json:"spec,omitempty"`
}

// ComplianceSnapshotterDeploymentSpec defines configuration for the compliance snapshotter Deployment.
type ComplianceSnapshotterDeploymentSpec struct {

	// Template describes the compliance snapshotter Deployment pod that will be created.
	// +optional
	Template *ComplianceSnapshotterDeploymentPodTemplateSpec `json:"template,omitempty"`
}

// ComplianceSnapshotterDeploymentPodTemplateSpec is the compliance snapshotter Deployment's PodTemplateSpec
type ComplianceSnapshotterDeploymentPodTemplateSpec struct {

	// Spec is the compliance snapshotter Deployment's PodSpec.
	// +optional
	Spec *ComplianceSnapshotterDeploymentPodSpec `json:"spec,omitempty"`
}

// ComplianceSnapshotterDeploymentPodSpec is the compliance snapshotter Deployment's PodSpec.
type ComplianceSnapshotterDeploymentPodSpec struct {
	// InitContainers is a list of compliance snapshotter init containers.
	// If specified, this overrides the specified compliance snapshotter Deployment init containers.
	// If omitted, the compliance snapshotter Deployment will use its default values for its init containers.
	// +optional
	InitContainers []ComplianceSnapshotterDeploymentInitContainer `json:"initContainers,omitempty"`

	// Containers is a list of compliance snapshotter containers.
	// If specified, this overrides the specified compliance snapshotter Deployment containers.
	// If omitted, the compliance snapshotter Deployment will use its default values for its containers.
	// +optional
	Containers []ComplianceSnapshotterDeploymentContainer `json:"containers,omitempty"`
}

// ComplianceSnapshotterDeploymentContainer is a compliance snapshotter Deployment container.
type ComplianceSnapshotterDeploymentContainer struct {
	// Name is an enum which identifies the compliance snapshotter Deployment container by name.
	// Supported values are: compliance-snapshotter
	// +kubebuilder:validation:Enum=compliance-snapshotter
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named compliance snapshotter Deployment container's resources.
	// If omitted, the compliance snapshotter Deployment will use its default value for this container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

// ComplianceSnapshotterDeploymentInitContainer is a compliance snapshotter Deployment init container.
type ComplianceSnapshotterDeploymentInitContainer struct {
	// Name is an enum which identifies the compliance snapshotter Deployment init container by name.
	// Supported values are: tigera-compliance-snapshotter-tls-key-cert-provisioner
	// +kubebuilder:validation:Enum=tigera-compliance-snapshotter-tls-key-cert-provisioner
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named compliance snapshotter Deployment init container's resources.
	// If omitted, the compliance snapshotter Deployment will use its default value for this init container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

func (c *ComplianceSnapshotterDeployment) GetMetadata() *Metadata {
	return nil
}

func (c *ComplianceSnapshotterDeployment) GetMinReadySeconds() *int32 {
	return nil
}

func (c *ComplianceSnapshotterDeployment) GetPodTemplateMetadata() *Metadata {
	return nil
}

func (c *ComplianceSnapshotterDeployment) GetInitContainers() []v1.Container {
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

func (c *ComplianceSnapshotterDeployment) GetContainers() []v1.Container {
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

func (c *ComplianceSnapshotterDeployment) GetAffinity() *v1.Affinity {
	return nil
}

func (c *ComplianceSnapshotterDeployment) GetTopologySpreadConstraints() []v1.TopologySpreadConstraint {
	return nil
}

func (c *ComplianceSnapshotterDeployment) GetNodeSelector() map[string]string {
	return nil
}

func (c *ComplianceSnapshotterDeployment) GetTolerations() []v1.Toleration {
	return nil
}

func (c *ComplianceSnapshotterDeployment) GetTerminationGracePeriodSeconds() *int64 {
	return nil
}

func (c *ComplianceSnapshotterDeployment) GetDeploymentStrategy() *appsv1.DeploymentStrategy {
	return nil
}

func (c *ComplianceSnapshotterDeployment) GetPriorityClassName() string {
	return ""
}
