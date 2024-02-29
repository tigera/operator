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

// SnapshotterDeployment is the configuration for the compliance Snapshotter Deployment.
type SnapshotterDeployment struct {

	// Spec is the specification of the compliance Snapshotter Deployment.
	// +optional
	Spec *SnapshotterDeploymentSpec `json:"spec,omitempty"`
}

// SnapshotterDeploymentSpec defines configuration for the compliance Snapshotter Deployment.
type SnapshotterDeploymentSpec struct {

	// Template describes the compliance Snapshotter Deployment pod that will be created.
	// +optional
	Template *SnapshotterDeploymentPodTemplateSpec `json:"template,omitempty"`
}

// SnapshotterDeploymentPodTemplateSpec is the compliance Snapshotter Deployment's PodTemplateSpec
type SnapshotterDeploymentPodTemplateSpec struct {

	// Spec is the compliance Snapshotter Deployment's PodSpec.
	// +optional
	Spec *SnapshotterDeploymentPodSpec `json:"spec,omitempty"`
}

// SnapshotterDeploymentPodSpec is the compliance Snapshotter Deployment's PodSpec.
type SnapshotterDeploymentPodSpec struct {
	// InitContainers is a list of compliance Snapshotter init containers.
	// If specified, this overrides the specified compliance Snapshotter Deployment init containers.
	// If omitted, the compliance Snapshotter Deployment will use its default values for its init containers.
	// +optional
	InitContainers []SnapshotterDeploymentInitContainer `json:"initContainers,omitempty"`

	// Containers is a list of compliance Snapshotter containers.
	// If specified, this overrides the specified compliance Snapshotter Deployment containers.
	// If omitted, the compliance Snapshotter Deployment will use its default values for its containers.
	// +optional
	Containers []SnapshotterDeploymentContainer `json:"containers,omitempty"`
}

// SnapshotterDeploymentContainer is a compliance Snapshotter Deployment container.
type SnapshotterDeploymentContainer struct {
	// Name is an enum which identifies the compliance Snapshotter Deployment container by name.
	// +kubebuilder:validation:Enum=compliance-snapshotter
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named compliance Snapshotter Deployment container's resources.
	// If omitted, the compliance Snapshotter Deployment will use its default value for this container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

// SnapshotterDeploymentInitContainer is a compliance Snapshotter Deployment init container.
type SnapshotterDeploymentInitContainer struct {
	// Name is an enum which identifies the compliance Snapshotter Deployment init container by name.
	// +kubebuilder:validation:Enum=tigera-compliance-snapshotter-tls-key-cert-provisioner
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named compliance Snapshotter Deployment init container's resources.
	// If omitted, the compliance Snapshotter Deployment will use its default value for this init container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

func (c *SnapshotterDeployment) GetMetadata() *Metadata {
	return nil
}

func (c *SnapshotterDeployment) GetMinReadySeconds() *int32 {
	return nil
}

func (c *SnapshotterDeployment) GetPodTemplateMetadata() *Metadata {
	return nil
}

func (c *SnapshotterDeployment) GetInitContainers() []v1.Container {
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

func (c *SnapshotterDeployment) GetContainers() []v1.Container {
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

func (c *SnapshotterDeployment) GetAffinity() *v1.Affinity {
	return nil
}

func (c *SnapshotterDeployment) GetTopologySpreadConstraints() []v1.TopologySpreadConstraint {
	return nil
}

func (c *SnapshotterDeployment) GetNodeSelector() map[string]string {
	return nil
}

func (c *SnapshotterDeployment) GetTolerations() []v1.Toleration {
	return nil
}

func (c *SnapshotterDeployment) GetTerminationGracePeriodSeconds() *int64 {
	return nil
}

func (c *SnapshotterDeployment) GetDeploymentStrategy() *appsv1.DeploymentStrategy {
	return nil
}

func (c *SnapshotterDeployment) GetPriorityClassName() string {
	return ""
}
