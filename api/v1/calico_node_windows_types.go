// Copyright (c) 2023-2024 Tigera, Inc. All rights reserved.
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

// CalicoNodeWindowsDaemonSetContainer is a calico-node-windows DaemonSet container.
type CalicoNodeWindowsDaemonSetContainer struct {
	// Name is an enum which identifies the calico-node-windows DaemonSet container by name.
	// +kubebuilder:validation:Enum=calico-node-windows
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named calico-node-windows DaemonSet container's resources.
	// If omitted, the calico-node-windows DaemonSet will use its default value for this container's resources.
	// If used in conjunction with the deprecated ComponentResources, then this value takes precedence.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

// CalicoNodeWindowsDaemonSetInitContainer is a calico-node-windows DaemonSet init container.
type CalicoNodeWindowsDaemonSetInitContainer struct {
	// Name is an enum which identifies the calico-node-windows DaemonSet init container by name.
	// +kubebuilder:validation:Enum=install-cni;hostpath-init;flexvol-driver;mount-bpffs;node-certs-key-cert-provisioner;calico-node-windows-prometheus-server-tls-key-cert-provisioner
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named calico-node-windows DaemonSet init container's resources.
	// If omitted, the calico-node-windows DaemonSet will use its default value for this container's resources.
	// If used in conjunction with the deprecated ComponentResources, then this value takes precedence.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

// CalicoNodeWindowsDaemonSetPodSpec is the calico-node-windows DaemonSet's PodSpec.
type CalicoNodeWindowsDaemonSetPodSpec struct {
	// InitContainers is a list of calico-node-windows init containers.
	// If specified, this overrides the specified calico-node-windows DaemonSet init containers.
	// If omitted, the calico-node-windows DaemonSet will use its default values for its init containers.
	// +optional
	InitContainers []CalicoNodeWindowsDaemonSetInitContainer `json:"initContainers,omitempty"`

	// Containers is a list of calico-node-windows containers.
	// If specified, this overrides the specified calico-node-windows DaemonSet containers.
	// If omitted, the calico-node-windows DaemonSet will use its default values for its containers.
	// +optional
	Containers []CalicoNodeWindowsDaemonSetContainer `json:"containers,omitempty"`

	// Affinity is a group of affinity scheduling rules for the calico-node-windows pods.
	// If specified, this overrides any affinity that may be set on the calico-node-windows DaemonSet.
	// If omitted, the calico-node-windows DaemonSet will use its default value for affinity.
	// WARNING: Please note that this field will override the default calico-node-windows DaemonSet affinity.
	// +optional
	Affinity *v1.Affinity `json:"affinity"`

	// NodeSelector is the calico-node-windows pod's scheduling constraints.
	// If specified, each of the key/value pairs are added to the calico-node-windows DaemonSet nodeSelector provided
	// the key does not already exist in the object's nodeSelector.
	// If omitted, the calico-node-windows DaemonSet will use its default value for nodeSelector.
	// WARNING: Please note that this field will modify the default calico-node-windows DaemonSet nodeSelector.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Tolerations is the calico-node-windows pod's tolerations.
	// If specified, this overrides any tolerations that may be set on the calico-node-windows DaemonSet.
	// If omitted, the calico-node-windows DaemonSet will use its default value for tolerations.
	// WARNING: Please note that this field will override the default calico-node-windows DaemonSet tolerations.
	// +optional
	Tolerations []v1.Toleration `json:"tolerations"`
}

// CalicoNodeWindowsDaemonSetPodTemplateSpec is the calico-node-windows DaemonSet's PodTemplateSpec
type CalicoNodeWindowsDaemonSetPodTemplateSpec struct {
	// Metadata is a subset of a Kubernetes object's metadata that is added to
	// the pod's metadata.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`

	// Spec is the calico-node-windows DaemonSet's PodSpec.
	// +optional
	Spec *CalicoNodeWindowsDaemonSetPodSpec `json:"spec,omitempty"`
}

// CalicoNodeWindowsDaemonSet is the configuration for the calico-node-windows DaemonSet.
type CalicoNodeWindowsDaemonSet struct {
	// Metadata is a subset of a Kubernetes object's metadata that is added to the DaemonSet.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`

	// Spec is the specification of the calico-node-windows DaemonSet.
	// +optional
	Spec *CalicoNodeWindowsDaemonSetSpec `json:"spec,omitempty"`
}

// CalicoNodeWindowsDaemonSetSpec defines configuration for the calico-node-windows DaemonSet.
type CalicoNodeWindowsDaemonSetSpec struct {
	// MinReadySeconds is the minimum number of seconds for which a newly created DaemonSet pod should
	// be ready without any of its container crashing, for it to be considered available.
	// If specified, this overrides any minReadySeconds value that may be set on the calico-node-windows DaemonSet.
	// If omitted, the calico-node-windows DaemonSet will use its default value for minReadySeconds.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=2147483647
	MinReadySeconds *int32 `json:"minReadySeconds,omitempty"`

	// Template describes the calico-node-windows DaemonSet pod that will be created.
	// +optional
	Template *CalicoNodeWindowsDaemonSetPodTemplateSpec `json:"template,omitempty"`
}

func (c *CalicoNodeWindowsDaemonSet) GetMetadata() *Metadata {
	return c.Metadata
}

func (c *CalicoNodeWindowsDaemonSet) GetMinReadySeconds() *int32 {
	if c.Spec != nil {
		return c.Spec.MinReadySeconds
	}
	return nil
}

func (c *CalicoNodeWindowsDaemonSet) GetPodTemplateMetadata() *Metadata {
	if c.Spec != nil {
		if c.Spec.Template != nil {
			return c.Spec.Template.Metadata
		}
	}
	return nil
}

func (c *CalicoNodeWindowsDaemonSet) GetInitContainers() []v1.Container {
	if c.Spec != nil {
		if c.Spec.Template != nil {
			if c.Spec.Template.Spec != nil {
				if c.Spec.Template.Spec.InitContainers != nil {
					cs := make([]v1.Container, len(c.Spec.Template.Spec.InitContainers))
					for i, v := range c.Spec.Template.Spec.InitContainers {
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

func (c *CalicoNodeWindowsDaemonSet) GetContainers() []v1.Container {
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

func (c *CalicoNodeWindowsDaemonSet) GetAffinity() *v1.Affinity {
	if c.Spec != nil {
		if c.Spec.Template != nil {
			if c.Spec.Template.Spec != nil {
				return c.Spec.Template.Spec.Affinity
			}
		}
	}
	return nil
}

func (c *CalicoNodeWindowsDaemonSet) GetTopologySpreadConstraints() []v1.TopologySpreadConstraint {
	// TopologySpreadConstraints aren't needed for Calico DaemonSet resources.
	return nil
}

func (c *CalicoNodeWindowsDaemonSet) GetNodeSelector() map[string]string {
	if c.Spec != nil {
		if c.Spec.Template != nil {
			if c.Spec.Template.Spec != nil {
				return c.Spec.Template.Spec.NodeSelector
			}
		}
	}
	return nil
}

func (c *CalicoNodeWindowsDaemonSet) GetTolerations() []v1.Toleration {
	if c.Spec != nil {
		if c.Spec.Template != nil {
			if c.Spec.Template.Spec != nil {
				return c.Spec.Template.Spec.Tolerations
			}
		}
	}
	return nil
}

func (c *CalicoNodeWindowsDaemonSet) GetTerminationGracePeriodSeconds() *int64 {
	return nil
}

func (c *CalicoNodeWindowsDaemonSet) GetDeploymentStrategy() *appsv1.DeploymentStrategy {
	return nil
}

func (c *CalicoNodeWindowsDaemonSet) GetPriorityClassName() string {
	return ""
}
