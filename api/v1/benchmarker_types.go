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

// BenchmarkerDaemonSet is the configuration for the Compliance Benchmarker DaemonSet.
type BenchmarkerDaemonSet struct {

	// Spec is the specification of the Compliance Benchmarker DaemonSet.
	// +optional
	Spec *BenchmarkerDaemonSetSpec `json:"spec,omitempty"`
}

// BenchmarkerDaemonSetSpec defines configuration for the Compliance Benchmarker DaemonSet.
type BenchmarkerDaemonSetSpec struct {

	// Template describes the Compliance Benchmarker DaemonSet pod that will be created.
	// +optional
	Template *BenchmarkerDaemonSetPodTemplateSpec `json:"template,omitempty"`
}

// BenchmarkerDaemonSetPodTemplateSpec is the Compliance Benchmarker DaemonSet's PodTemplateSpec
type BenchmarkerDaemonSetPodTemplateSpec struct {

	// Spec is the Compliance Benchmarker DaemonSet's PodSpec.
	// +optional
	Spec *BenchmarkerDaemonSetPodSpec `json:"spec,omitempty"`
}

// BenchmarkerDaemonSetPodSpec is the Compliance Benchmarker DaemonSet's PodSpec.
type BenchmarkerDaemonSetPodSpec struct {
	// InitContainers is a list of Compliance benchmark init containers.
	// If specified, this overrides the specified Compliance Benchmarker DaemonSet init containers.
	// If omitted, the Compliance Benchmarker DaemonSet will use its default values for its init containers.
	// +optional
	InitContainers []BenchmarkerDaemonSetInitContainer `json:"initContainers,omitempty"`

	// Containers is a list of Compliance benchmark containers.
	// If specified, this overrides the specified Compliance Benchmarker DaemonSet containers.
	// If omitted, the Compliance Benchmarker DaemonSet will use its default values for its containers.
	// +optional
	Containers []BenchmarkerDaemonSetContainer `json:"containers,omitempty"`
}

// BenchmarkerDaemonSetContainer is a Compliance Benchmarker DaemonSet container.
type BenchmarkerDaemonSetContainer struct {
	// Name is an enum which identifies the Compliance Benchmarker DaemonSet container by name.
	// +kubebuilder:validation:Enum=compliance-benchmarker
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named Compliance Benchmarker DaemonSet container's resources.
	// If omitted, the Compliance Benchmarker DaemonSet will use its default value for this container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

// BenchmarkerDaemonSetInitContainer is a Compliance Benchmarker DaemonSet init container.
type BenchmarkerDaemonSetInitContainer struct {
	// Name is an enum which identifies the Compliance Benchmarker DaemonSet init container by name.
	// +kubebuilder:validation:Enum=tigera-compliance-benchmarker-tls-key-cert-provisioner
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named Compliance Benchmarker DaemonSet init container's resources.
	// If omitted, the Compliance Benchmarker DaemonSet will use its default value for this init container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

func (c *BenchmarkerDaemonSet) GetMetadata() *Metadata {
	return nil
}

func (c *BenchmarkerDaemonSet) GetMinReadySeconds() *int32 {
	return nil
}

func (c *BenchmarkerDaemonSet) GetPodTemplateMetadata() *Metadata {
	return nil
}

func (c *BenchmarkerDaemonSet) GetInitContainers() []v1.Container {
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

func (c *BenchmarkerDaemonSet) GetContainers() []v1.Container {
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

func (c *BenchmarkerDaemonSet) GetAffinity() *v1.Affinity {
	return nil
}

func (c *BenchmarkerDaemonSet) GetTopologySpreadConstraints() []v1.TopologySpreadConstraint {
	return nil
}

func (c *BenchmarkerDaemonSet) GetNodeSelector() map[string]string {
	return nil
}

func (c *BenchmarkerDaemonSet) GetTolerations() []v1.Toleration {
	return nil
}

func (c *BenchmarkerDaemonSet) GetTerminationGracePeriodSeconds() *int64 {
	return nil
}

func (c *BenchmarkerDaemonSet) GetDeploymentStrategy() *appsv1.DeploymentStrategy {
	return nil
}

func (c *BenchmarkerDaemonSet) GetPriorityClassName() string {
	return ""
}
