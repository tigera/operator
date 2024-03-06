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

// ESMetricsDeployment is the configuration for the tigera-elasticsearch-metric Deployment.
type ESMetricsDeployment struct {

	// Spec is the specification of the esMetrics Deployment.
	// +optional
	Spec *ESMetricsDeploymentSpec `json:"spec,omitempty"`
}

// ESMetricsDeploymentSpec defines configuration for the ESMetricsDeployment Deployment.
type ESMetricsDeploymentSpec struct {

	// Template describes the esMetrics Deployment pod that will be created.
	// +optional
	Template *ESMetricsDeploymentPodTemplateSpec `json:"template,omitempty"`
}

// ESMetricsDeploymentPodTemplateSpec is the ESMetricsDeployment's PodTemplateSpec
type ESMetricsDeploymentPodTemplateSpec struct {

	// Spec is the esMetrics Deployment's PodSpec.
	// +optional
	Spec *ESMetricsDeploymentPodSpec `json:"spec,omitempty"`
}

// ESMetricsDeploymentPodSpec is the tESMetricsDeployment's PodSpec.
type ESMetricsDeploymentPodSpec struct {
	// InitContainers is a list of ESMetricsDeployment init containers.
	// If specified, this overrides the specified ESMetricsDeployment init containers.
	// If omitted, the esMetrics Deployment will use its default values for its init containers.
	// +optional
	InitContainers []ESMetricsDeploymentInitContainer `json:"initContainers,omitempty"`

	// Containers is a list of ESMetricsDeployment containers.
	// If specified, this overrides the specified ESMetricsDeployment containers.
	// If omitted, the esMetrics Deployment will use its default values for its containers.
	// +optional
	Containers []ESMetricsDeploymentContainer `json:"containers,omitempty"`
}

// ESMetricsDeploymentContainer is a ESMetricsDeployment container.
type ESMetricsDeploymentContainer struct {
	// Name is an enum which identifies the ESMetricsDeployment container by name.
	// +kubebuilder:validation:Enum=tigera-elasticsearch-metrics
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named ESMetricsDeployment container's resources.
	// If omitted, the esMetrics Deployment will use its default value for this container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

// ESMetricsDeploymentInitContainer is a ESMetricsDeployment init container.
type ESMetricsDeploymentInitContainer struct {
	// Name is an enum which identifies the ESMetricsDeployment init container by name.
	// +kubebuilder:validation:Enum=tigera-ee-elasticsearch-metrics-tls-key-cert-provisioner
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named ESMetricsDeployment init container's resources.
	// If omitted, the esMetrics Deployment will use its default value for this init container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

func (c *ESMetricsDeployment) GetMetadata() *Metadata {
	return nil
}

func (c *ESMetricsDeployment) GetMinReadySeconds() *int32 {
	return nil
}

func (c *ESMetricsDeployment) GetPodTemplateMetadata() *Metadata {
	return nil
}

func (c *ESMetricsDeployment) GetInitContainers() []v1.Container {
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

func (c *ESMetricsDeployment) GetContainers() []v1.Container {
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

func (c *ESMetricsDeployment) GetAffinity() *v1.Affinity {
	return nil
}

func (c *ESMetricsDeployment) GetTopologySpreadConstraints() []v1.TopologySpreadConstraint {
	return nil
}

func (c *ESMetricsDeployment) GetNodeSelector() map[string]string {
	return nil
}

func (c *ESMetricsDeployment) GetTolerations() []v1.Toleration {
	return nil
}

func (c *ESMetricsDeployment) GetTerminationGracePeriodSeconds() *int64 {
	return nil
}

func (c *ESMetricsDeployment) GetDeploymentStrategy() *appsv1.DeploymentStrategy {
	return nil
}

func (c *ESMetricsDeployment) GetPriorityClassName() string {
	return ""
}
