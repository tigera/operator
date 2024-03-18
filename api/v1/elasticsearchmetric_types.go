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

// ElasticsearchMetricsDeployment is the configuration for the tigera-elasticsearch-metric Deployment.
type ElasticsearchMetricsDeployment struct {

	// Spec is the specification of the ElasticsearchMetrics Deployment.
	// +optional
	Spec *ElasticsearchMetricsDeploymentSpec `json:"spec,omitempty"`
}

// ElasticsearchMetricsDeploymentSpec defines configuration for the ElasticsearchMetricsDeployment Deployment.
type ElasticsearchMetricsDeploymentSpec struct {

	// Template describes the ElasticsearchMetrics Deployment pod that will be created.
	// +optional
	Template *ElasticsearchMetricsDeploymentPodTemplateSpec `json:"template,omitempty"`
}

// ElasticsearchMetricsDeploymentPodTemplateSpec is the ElasticsearchMetricsDeployment's PodTemplateSpec
type ElasticsearchMetricsDeploymentPodTemplateSpec struct {

	// Spec is the ElasticsearchMetrics Deployment's PodSpec.
	// +optional
	Spec *ElasticsearchMetricsDeploymentPodSpec `json:"spec,omitempty"`
}

// ElasticsearchMetricsDeploymentPodSpec is the tElasticsearchMetricsDeployment's PodSpec.
type ElasticsearchMetricsDeploymentPodSpec struct {
	// InitContainers is a list of ElasticsearchMetricsDeployment init containers.
	// If specified, this overrides the specified ElasticsearchMetricsDeployment init containers.
	// If omitted, the ElasticsearchMetrics Deployment will use its default values for its init containers.
	// +optional
	InitContainers []ElasticsearchMetricsDeploymentInitContainer `json:"initContainers,omitempty"`

	// Containers is a list of ElasticsearchMetricsDeployment containers.
	// If specified, this overrides the specified ElasticsearchMetricsDeployment containers.
	// If omitted, the ElasticsearchMetrics Deployment will use its default values for its containers.
	// +optional
	Containers []ElasticsearchMetricsDeploymentContainer `json:"containers,omitempty"`
}

// ElasticsearchMetricsDeploymentContainer is a ElasticsearchMetricsDeployment container.
type ElasticsearchMetricsDeploymentContainer struct {
	// Name is an enum which identifies the ElasticsearchMetricsDeployment container by name.
	// Supported values are: tigera-elasticsearch-metrics
	// +kubebuilder:validation:Enum=tigera-elasticsearch-metrics
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named ElasticsearchMetricsDeployment container's resources.
	// If omitted, the ElasticsearchMetrics Deployment will use its default value for this container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

// ElasticsearchMetricsDeploymentInitContainer is a ElasticsearchMetricsDeployment init container.
type ElasticsearchMetricsDeploymentInitContainer struct {
	// Name is an enum which identifies the ElasticsearchMetricsDeployment init container by name.
	// Supported values are: tigera-ee-elasticsearch-metrics-tls-key-cert-provisioner
	// +kubebuilder:validation:Enum=tigera-ee-elasticsearch-metrics-tls-key-cert-provisioner
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named ElasticsearchMetricsDeployment init container's resources.
	// If omitted, the ElasticsearchMetrics Deployment will use its default value for this init container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

func (c *ElasticsearchMetricsDeployment) GetMetadata() *Metadata {
	return nil
}

func (c *ElasticsearchMetricsDeployment) GetMinReadySeconds() *int32 {
	return nil
}

func (c *ElasticsearchMetricsDeployment) GetPodTemplateMetadata() *Metadata {
	return nil
}

func (c *ElasticsearchMetricsDeployment) GetInitContainers() []v1.Container {
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

func (c *ElasticsearchMetricsDeployment) GetContainers() []v1.Container {
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

func (c *ElasticsearchMetricsDeployment) GetAffinity() *v1.Affinity {
	return nil
}

func (c *ElasticsearchMetricsDeployment) GetTopologySpreadConstraints() []v1.TopologySpreadConstraint {
	return nil
}

func (c *ElasticsearchMetricsDeployment) GetNodeSelector() map[string]string {
	return nil
}

func (c *ElasticsearchMetricsDeployment) GetTolerations() []v1.Toleration {
	return nil
}

func (c *ElasticsearchMetricsDeployment) GetTerminationGracePeriodSeconds() *int64 {
	return nil
}

func (c *ElasticsearchMetricsDeployment) GetDeploymentStrategy() *appsv1.DeploymentStrategy {
	return nil
}

func (c *ElasticsearchMetricsDeployment) GetPriorityClassName() string {
	return ""
}
