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

// EksCloudwatchLogsDeployment is the configuration for the EksCloudwatchLogs Deployment.
type EksCloudwatchLogsDeployment struct {

	// Spec is the specification of the EksCloudwatchLogs Deployment.
	// +optional
	Spec *EksCloudwatchLogsDeploymentSpec `json:"spec,omitempty"`
}

// EksCloudwatchLogsDeploymentSpec defines configuration for the EksCloudwatchLogs Deployment.
type EksCloudwatchLogsDeploymentSpec struct {

	// Template describes the EksCloudwatchLogs Deployment pod that will be created.
	// +optional
	Template *EksCloudwatchLogsDeploymentPodTemplateSpec `json:"template,omitempty"`
}

// EksCloudwatchLogsDeploymentPodTemplateSpec is the EksCloudwatchLogs Deployment's PodTemplateSpec
type EksCloudwatchLogsDeploymentPodTemplateSpec struct {

	// Spec is the EksCloudwatchLogs Deployment's PodSpec.
	// +optional
	Spec *EksCloudwatchLogsDeploymentPodSpec `json:"spec,omitempty"`
}

// EksCloudwatchLogsDeploymentPodSpec is the EksCloudwatchLogs Deployment's PodSpec.
type EksCloudwatchLogsDeploymentPodSpec struct {
	// InitContainers is a list of EksCloudwatchLogs init containers.
	// If specified, this overrides the specified EksCloudwatchLogs Deployment init containers.
	// If omitted, the EksCloudwatchLogs Deployment will use its default values for its init containers.
	// +optional
	InitContainers []EksCloudwatchLogsDeploymentInitContainer `json:"initContainers,omitempty"`

	// Containers is a list of EksCloudwatchLogs containers.
	// If specified, this overrides the specified EksCloudwatchLogs Deployment containers.
	// If omitted, the EksCloudwatchLogs Deployment will use its default values for its containers.
	// +optional
	Containers []EksCloudwatchLogsDeploymentContainer `json:"containers,omitempty"`
}

// EksCloudwatchLogsDeploymentContainer is a EksCloudwatchLogs Deployment container.
type EksCloudwatchLogsDeploymentContainer struct {
	// Name is an enum which identifies the EksCloudwatchLogs Deployment container by name.
	// +kubebuilder:validation:Enum=eks-log-forwarder
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named EksCloudwatchLogs Deployment container's resources.
	// If omitted, the EksCloudwatchLogs Deployment will use its default value for this container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

// EksCloudwatchLogsDeploymentInitContainer is a EksCloudwatchLogs Deployment init container.
type EksCloudwatchLogsDeploymentInitContainer struct {
	// Name is an enum which identifies the EksCloudwatchLogs Deployment init container by name.
	// +kubebuilder:validation:Enum=eks-log-forwarder-startup
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named EksCloudwatchLogs Deployment init container's resources.
	// If omitted, the EksCloudwatchLogs Deployment will use its default value for this init container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

func (c *EksCloudwatchLogsDeployment) GetMetadata() *Metadata {
	return nil
}

func (c *EksCloudwatchLogsDeployment) GetMinReadySeconds() *int32 {
	return nil
}

func (c *EksCloudwatchLogsDeployment) GetPodTemplateMetadata() *Metadata {
	return nil
}

func (c *EksCloudwatchLogsDeployment) GetInitContainers() []v1.Container {
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

func (c *EksCloudwatchLogsDeployment) GetContainers() []v1.Container {
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

func (c *EksCloudwatchLogsDeployment) GetAffinity() *v1.Affinity {
	return nil
}

func (c *EksCloudwatchLogsDeployment) GetTopologySpreadConstraints() []v1.TopologySpreadConstraint {
	return nil
}

func (c *EksCloudwatchLogsDeployment) GetNodeSelector() map[string]string {
	return nil
}

func (c *EksCloudwatchLogsDeployment) GetTolerations() []v1.Toleration {
	return nil
}

func (c *EksCloudwatchLogsDeployment) GetTerminationGracePeriodSeconds() *int64 {
	return nil
}

func (c *EksCloudwatchLogsDeployment) GetDeploymentStrategy() *appsv1.DeploymentStrategy {
	return nil
}

func (c *EksCloudwatchLogsDeployment) GetPriorityClassName() string {
	return ""
}
