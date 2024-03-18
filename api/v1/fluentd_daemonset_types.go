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

// FluentdDaemonSet is the configuration for the Fluentd DaemonSet.
type FluentdDaemonSet struct {

	// Spec is the specification of the Fluentd DaemonSet.
	// +optional
	Spec *FluentdDaemonSetSpec `json:"spec,omitempty"`
}

// FluentdDaemonSetSpec defines configuration for the Fluentd DaemonSet.
type FluentdDaemonSetSpec struct {

	// Template describes the Fluentd DaemonSet pod that will be created.
	// +optional
	Template *FluentdDaemonSetPodTemplateSpec `json:"template,omitempty"`
}

// FluentdDaemonSetPodTemplateSpec is the Fluentd DaemonSet's PodTemplateSpec
type FluentdDaemonSetPodTemplateSpec struct {

	// Spec is the Fluentd DaemonSet's PodSpec.
	// +optional
	Spec *FluentdDaemonSetPodSpec `json:"spec,omitempty"`
}

// FluentdDaemonSetPodSpec is the Fluentd DaemonSet's PodSpec.
type FluentdDaemonSetPodSpec struct {
	// InitContainers is a list of Fluentd DaemonSet init containers.
	// If specified, this overrides the specified Fluentd DaemonSet init containers.
	// If omitted, the Fluentd DaemonSet will use its default values for its init containers.
	// +optional
	InitContainers []FluentdDaemonSetInitContainer `json:"initContainers,omitempty"`

	// Containers is a list of Fluentd DaemonSet containers.
	// If specified, this overrides the specified Fluentd DaemonSet containers.
	// If omitted, the Fluentd DaemonSet will use its default values for its containers.
	// +optional
	Containers []FluentdDaemonSetContainer `json:"containers,omitempty"`
}

// FluentdDaemonSetContainer is a Fluentd DaemonSet container.
type FluentdDaemonSetContainer struct {
	// Name is an enum which identifies the Fluentd DaemonSet container by name.
	// Supported values are: fluentd
	// +kubebuilder:validation:Enum=fluentd
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named Fluentd DaemonSet container's resources.
	// If omitted, the Fluentd DaemonSet will use its default value for this container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

// FluentdDaemonSetInitContainer is a Fluentd DaemonSet init container.
type FluentdDaemonSetInitContainer struct {
	// Name is an enum which identifies the Fluentd DaemonSet init container by name.
	// Supported values are: tigera-fluentd-prometheus-tls-key-cert-provisioner
	// +kubebuilder:validation:Enum=tigera-fluentd-prometheus-tls-key-cert-provisioner
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named Fluentd DaemonSet init container's resources.
	// If omitted, the Fluentd DaemonSet will use its default value for this init container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

func (c *FluentdDaemonSet) GetMetadata() *Metadata {
	return nil
}

func (c *FluentdDaemonSet) GetMinReadySeconds() *int32 {
	return nil
}

func (c *FluentdDaemonSet) GetPodTemplateMetadata() *Metadata {
	return nil
}

func (c *FluentdDaemonSet) GetInitContainers() []v1.Container {
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

func (c *FluentdDaemonSet) GetContainers() []v1.Container {
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

func (c *FluentdDaemonSet) GetAffinity() *v1.Affinity {
	return nil
}

func (c *FluentdDaemonSet) GetTopologySpreadConstraints() []v1.TopologySpreadConstraint {
	return nil
}

func (c *FluentdDaemonSet) GetNodeSelector() map[string]string {
	return nil
}

func (c *FluentdDaemonSet) GetTolerations() []v1.Toleration {
	return nil
}

func (c *FluentdDaemonSet) GetTerminationGracePeriodSeconds() *int64 {
	return nil
}

func (c *FluentdDaemonSet) GetDeploymentStrategy() *appsv1.DeploymentStrategy {
	return nil
}

func (c *FluentdDaemonSet) GetPriorityClassName() string {
	return ""
}
