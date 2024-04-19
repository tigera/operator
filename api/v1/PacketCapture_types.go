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

// PacketCaptureDeployment is the configuration for the PacketCapture Deployment.
type PacketCaptureDeployment struct {

	// Spec is the specification of the PacketCapture Deployment.
	// +optional
	Spec *PacketCaptureDeploymentSpec `json:"spec,omitempty"`
}

// PacketCaptureDeploymentSpec defines configuration for the PacketCapture Deployment.
type PacketCaptureDeploymentSpec struct {

	// Template describes the PacketCapture Deployment pod that will be created.
	// +optional
	Template *PacketCaptureDeploymentPodTemplateSpec `json:"template,omitempty"`
}

// PacketCaptureDeploymentPodTemplateSpec is the PacketCapture Deployment's PodTemplateSpec
type PacketCaptureDeploymentPodTemplateSpec struct {

	// Spec is the PacketCapture Deployment's PodSpec.
	// +optional
	Spec *PacketCaptureDeploymentPodSpec `json:"spec,omitempty"`
}

// PacketCaptureDeploymentPodSpec is the PacketCapture Deployment's PodSpec.
type PacketCaptureDeploymentPodSpec struct {
	// InitContainers is a list of PacketCapture init containers.
	// If specified, this overrides the specified PacketCapture Deployment init containers.
	// If omitted, the PacketCapture Deployment will use its default values for its init containers.
	// +optional
	InitContainers []PacketCaptureDeploymentInitContainer `json:"initContainers,omitempty"`

	// Containers is a list of PacketCapture containers.
	// If specified, this overrides the specified PacketCapture Deployment containers.
	// If omitted, the PacketCapture Deployment will use its default values for its containers.
	// +optional
	Containers []PacketCaptureDeploymentContainer `json:"containers,omitempty"`
}

// PacketCaptureDeploymentContainer is a PacketCapture Deployment container.
type PacketCaptureDeploymentContainer struct {
	// Name is an enum which identifies the PacketCapture Deployment container by name.
	// Supported values are: tigera-packetcapture-server
	// +kubebuilder:validation:Enum=tigera-packetcapture-server
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named PacketCapture Deployment container's resources.
	// If omitted, the PacketCapture Deployment will use its default value for this container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

// PacketCaptureDeploymentInitContainer is a PacketCapture Deployment init container.
type PacketCaptureDeploymentInitContainer struct {
	// Name is an enum which identifies the PacketCapture Deployment init container by name.
	// Supported values are: tigera-packetcapture-server-tls-key-cert-provisioner
	// +kubebuilder:validation:Enum=tigera-packetcapture-server-tls-key-cert-provisioner
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named PacketCapture Deployment init container's resources.
	// If omitted, the PacketCapture Deployment will use its default value for this init container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

func (c *PacketCaptureDeployment) GetMetadata() *Metadata {
	return nil
}

func (c *PacketCaptureDeployment) GetMinReadySeconds() *int32 {
	return nil
}

func (c *PacketCaptureDeployment) GetPodTemplateMetadata() *Metadata {
	return nil
}

func (c *PacketCaptureDeployment) GetInitContainers() []v1.Container {
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

func (c *PacketCaptureDeployment) GetContainers() []v1.Container {
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

func (c *PacketCaptureDeployment) GetAffinity() *v1.Affinity {
	return nil
}

func (c *PacketCaptureDeployment) GetTopologySpreadConstraints() []v1.TopologySpreadConstraint {
	return nil
}

func (c *PacketCaptureDeployment) GetNodeSelector() map[string]string {
	return nil
}

func (c *PacketCaptureDeployment) GetTolerations() []v1.Toleration {
	return nil
}

func (c *PacketCaptureDeployment) GetTerminationGracePeriodSeconds() *int64 {
	return nil
}

func (c *PacketCaptureDeployment) GetDeploymentStrategy() *appsv1.DeploymentStrategy {
	return nil
}

func (c *PacketCaptureDeployment) GetPriorityClassName() string {
	return ""
}
