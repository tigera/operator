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

// ECKOperatorStatefulSet is the configuration for the ECKOperator StatefulSet.
type ECKOperatorStatefulSet struct {

	// Spec is the specification of the ECKOperator StatefulSet.
	// +optional
	Spec *ECKOperatorStatefulSetSpec `json:"spec,omitempty"`
}

// ECKOperatorStatefulSetSpec defines configuration for the ECKOperator StatefulSet.
type ECKOperatorStatefulSetSpec struct {

	// Template describes the ECKOperator StatefulSet pod that will be created.
	// +optional
	Template *ECKOperatorStatefulSetPodTemplateSpec `json:"template,omitempty"`
}

// ECKOperatorStatefulSetPodTemplateSpec is the ECKOperator StatefulSet's PodTemplateSpec
type ECKOperatorStatefulSetPodTemplateSpec struct {

	// Spec is the ECKOperator StatefulSet's PodSpec.
	// +optional
	Spec *ECKOperatorStatefulSetPodSpec `json:"spec,omitempty"`
}

// ECKOperatorStatefulSetPodSpec is the ECKOperator StatefulSet's PodSpec.
type ECKOperatorStatefulSetPodSpec struct {
	// InitContainers is a list of ECKOperator StatefulSet init containers.
	// If specified, this overrides the specified ECKOperator StatefulSet init containers.
	// If omitted, the ECKOperator StatefulSet will use its default values for its init containers.
	// +optional
	InitContainers []ECKOperatorStatefulSetInitContainer `json:"initContainers,omitempty"`

	// Containers is a list of ECKOperator StatefulSet containers.
	// If specified, this overrides the specified ECKOperator StatefulSet containers.
	// If omitted, the ECKOperator StatefulSet will use its default values for its containers.
	// +optional
	Containers []ECKOperatorStatefulSetContainer `json:"containers,omitempty"`
}

// ECKOperatorStatefulSetContainer is a ECKOperator StatefulSet container.
type ECKOperatorStatefulSetContainer struct {
	// Name is an enum which identifies the ECKOperator StatefulSet container by name.
	// +kubebuilder:validation:Enum=manager
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named ECKOperator StatefulSet container's resources.
	// If omitted, the ECKOperator StatefulSet will use its default value for this container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

// ECKOperatorStatefulSetInitContainer is a ECKOperator StatefulSet init container.
type ECKOperatorStatefulSetInitContainer struct {
	// Name is an enum which identifies the ECKOperator StatefulSet init container by name.
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named ECKOperator StatefulSet init container's resources.
	// If omitted, the ECKOperator StatefulSet will use its default value for this init container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

func (c *ECKOperatorStatefulSet) GetMetadata() *Metadata {
	return nil
}

func (c *ECKOperatorStatefulSet) GetMinReadySeconds() *int32 {
	return nil
}

func (c *ECKOperatorStatefulSet) GetPodTemplateMetadata() *Metadata {
	return nil
}

func (c *ECKOperatorStatefulSet) GetInitContainers() []v1.Container {
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

func (c *ECKOperatorStatefulSet) GetContainers() []v1.Container {
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

func (c *ECKOperatorStatefulSet) GetAffinity() *v1.Affinity {
	return nil
}

func (c *ECKOperatorStatefulSet) GetTopologySpreadConstraints() []v1.TopologySpreadConstraint {
	return nil
}

func (c *ECKOperatorStatefulSet) GetNodeSelector() map[string]string {
	return nil
}

func (c *ECKOperatorStatefulSet) GetTolerations() []v1.Toleration {
	return nil
}

func (c *ECKOperatorStatefulSet) GetTerminationGracePeriodSeconds() *int64 {
	return nil
}

func (c *ECKOperatorStatefulSet) GetDeploymentStrategy() *appsv1.DeploymentStrategy {
	return nil
}

func (c *ECKOperatorStatefulSet) GetPriorityClassName() string {
	return ""
}
