// Copyright (c) 2022-2024 Tigera, Inc. All rights reserved.
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

// CalicoKubeControllersDeploymentContainer is a calico-kube-controllers Deployment container.
type CalicoKubeControllersDeploymentContainer struct {
	// Name is an enum which identifies the calico-kube-controllers Deployment container by name.
	// Supported values are: calico-kube-controllers, es-calico-kube-controllers
	// +kubebuilder:validation:Enum=calico-kube-controllers;es-calico-kube-controllers
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named calico-kube-controllers Deployment container's resources.
	// If omitted, the calico-kube-controllers Deployment will use its default value for this container's resources.
	// If used in conjunction with the deprecated ComponentResources, then this value takes precedence.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

// CalicoKubeControllersDeploymentPodSpec is the calico-kube-controller Deployment's PodSpec.
type CalicoKubeControllersDeploymentPodSpec struct {
	// Containers is a list of calico-kube-controllers containers.
	// If specified, this overrides the specified calico-kube-controllers Deployment containers.
	// If omitted, the calico-kube-controllers Deployment will use its default values for its containers.
	// +optional
	Containers []CalicoKubeControllersDeploymentContainer `json:"containers,omitempty"`

	// Affinity is a group of affinity scheduling rules for the calico-kube-controllers pods.
	// If specified, this overrides any affinity that may be set on the calico-kube-controllers Deployment.
	// If omitted, the calico-kube-controllers Deployment will use its default value for affinity.
	// WARNING: Please note that this field will override the default calico-kube-controllers Deployment affinity.
	// +optional
	Affinity *v1.Affinity `json:"affinity"`

	// NodeSelector is the calico-kube-controllers pod's scheduling constraints.
	// If specified, each of the key/value pairs are added to the calico-kube-controllers Deployment nodeSelector provided
	// the key does not already exist in the object's nodeSelector.
	// If used in conjunction with ControlPlaneNodeSelector, that nodeSelector is set on the calico-kube-controllers Deployment
	// and each of this field's key/value pairs are added to the calico-kube-controllers Deployment nodeSelector provided
	// the key does not already exist in the object's nodeSelector.
	// If omitted, the calico-kube-controllers Deployment will use its default value for nodeSelector.
	// WARNING: Please note that this field will modify the default calico-kube-controllers Deployment nodeSelector.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Tolerations is the calico-kube-controllers pod's tolerations.
	// If specified, this overrides any tolerations that may be set on the calico-kube-controllers Deployment.
	// If omitted, the calico-kube-controllers Deployment will use its default value for tolerations.
	// WARNING: Please note that this field will override the default calico-kube-controllers Deployment tolerations.
	// +optional
	Tolerations []v1.Toleration `json:"tolerations"`
}

// CalicoKubeControllersDeploymentPodTemplateSpec is the calico-kube-controllers Deployment's PodTemplateSpec
type CalicoKubeControllersDeploymentPodTemplateSpec struct {
	// Metadata is a subset of a Kubernetes object's metadata that is added to
	// the pod's metadata.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`

	// Spec is the calico-kube-controllers Deployment's PodSpec.
	// +optional
	Spec *CalicoKubeControllersDeploymentPodSpec `json:"spec,omitempty"`
}

// CalicoKubeControllersDeployment is the configuration for the calico-kube-controllers Deployment.
type CalicoKubeControllersDeployment struct {
	// Metadata is a subset of a Kubernetes object's metadata that is added to the Deployment.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`

	// Spec is the specification of the calico-kube-controllers Deployment.
	// +optional
	Spec *CalicoKubeControllersDeploymentSpec `json:"spec,omitempty"`
}

// CalicoKubeControllersDeploymentSpec defines configuration for the calico-kube-controllers Deployment.
type CalicoKubeControllersDeploymentSpec struct {
	// MinReadySeconds is the minimum number of seconds for which a newly created Deployment pod should
	// be ready without any of its container crashing, for it to be considered available.
	// If specified, this overrides any minReadySeconds value that may be set on the calico-kube-controllers Deployment.
	// If omitted, the calico-kube-controllers Deployment will use its default value for minReadySeconds.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=2147483647
	MinReadySeconds *int32 `json:"minReadySeconds,omitempty"`

	// Template describes the calico-kube-controllers Deployment pod that will be created.
	// +optional
	Template *CalicoKubeControllersDeploymentPodTemplateSpec `json:"template,omitempty"`
}

func (c *CalicoKubeControllersDeployment) GetMetadata() *Metadata {
	return c.Metadata
}

func (c *CalicoKubeControllersDeployment) GetMinReadySeconds() *int32 {
	if c.Spec != nil {
		return c.Spec.MinReadySeconds
	}
	return nil
}

func (c *CalicoKubeControllersDeployment) GetPodTemplateMetadata() *Metadata {
	if c.Spec != nil {
		if c.Spec.Template != nil {
			return c.Spec.Template.Metadata
		}
	}
	return nil
}

func (c *CalicoKubeControllersDeployment) GetInitContainers() []v1.Container {
	// no init containers defined
	return nil
}

func (c *CalicoKubeControllersDeployment) GetContainers() []v1.Container {
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

func (c *CalicoKubeControllersDeployment) GetAffinity() *v1.Affinity {
	if c.Spec != nil {
		if c.Spec.Template != nil {
			if c.Spec.Template.Spec != nil {
				return c.Spec.Template.Spec.Affinity
			}
		}
	}
	return nil
}

func (c *CalicoKubeControllersDeployment) GetTopologySpreadConstraints() []v1.TopologySpreadConstraint {
	// TopologySpreadConstraints don't apply to kube-controllers since we only ever run a single
	// replica of this deployment. kube-controllers is designed to be a singleton. Other scheduling
	// mechanisms like node selector and tolerations should be used instead.
	return nil
}

func (c *CalicoKubeControllersDeployment) GetNodeSelector() map[string]string {
	if c.Spec != nil {
		if c.Spec.Template != nil {
			if c.Spec.Template.Spec != nil {
				return c.Spec.Template.Spec.NodeSelector
			}
		}
	}
	return nil
}

func (c *CalicoKubeControllersDeployment) GetTolerations() []v1.Toleration {
	if c.Spec != nil {
		if c.Spec.Template != nil {
			if c.Spec.Template.Spec != nil {
				return c.Spec.Template.Spec.Tolerations
			}
		}
	}
	return nil
}

func (c *CalicoKubeControllersDeployment) GetTerminationGracePeriodSeconds() *int64 {
	return nil
}

func (c *CalicoKubeControllersDeployment) GetDeploymentStrategy() *appsv1.DeploymentStrategy {
	return nil
}

func (c *CalicoKubeControllersDeployment) GetPriorityClassName() string {
	return ""
}
