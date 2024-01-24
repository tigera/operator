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

// DashboardsJob is the configuration for the Dashboards job.
type DashboardsJob struct {

	// Spec is the specification of the dashboards job.
	// +optional
	Spec *DashboardsJobSpec `json:"spec,omitempty"`
}

func (in *DashboardsJob) GetMetadata() *Metadata {
	return nil
}

func (in *DashboardsJob) GetMinReadySeconds() *int32 {
	return nil
}

func (in *DashboardsJob) GetPodTemplateMetadata() *Metadata {
	return nil
}

func (in *DashboardsJob) GetInitContainers() []v1.Container {
	return nil
}

func (in *DashboardsJob) GetContainers() []v1.Container {
	if in.Spec != nil {
		if in.Spec.Template != nil {
			if in.Spec.Template.Spec != nil {
				if in.Spec.Template.Spec.Containers != nil {
					cs := make([]v1.Container, len(in.Spec.Template.Spec.Containers))
					for i, v := range in.Spec.Template.Spec.Containers {
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

func (in *DashboardsJob) GetAffinity() *v1.Affinity {
	return nil
}

func (in *DashboardsJob) GetNodeSelector() map[string]string {
	return nil
}

func (in *DashboardsJob) GetTopologySpreadConstraints() []v1.TopologySpreadConstraint {
	return nil
}

func (in *DashboardsJob) GetTolerations() []v1.Toleration {
	return nil
}

func (in *DashboardsJob) GetTerminationGracePeriodSeconds() *int64 {
	return nil
}

func (in *DashboardsJob) GetDeploymentStrategy() *appsv1.DeploymentStrategy {
	return nil
}

// DashboardsJobSpec defines configuration for the Dashboards job.
type DashboardsJobSpec struct {

	// Template describes the Dashboards job pod that will be created.
	// +optional
	Template *DashboardsJobPodTemplateSpec `json:"template,omitempty"`
}

// DashboardsJobPodTemplateSpec is the Dashboards job's PodTemplateSpec
type DashboardsJobPodTemplateSpec struct {

	// Spec is the Dashboard job's PodSpec.
	// +optional
	Spec *DashboardsJobPodSpec `json:"spec,omitempty"`
}

// DashboardsJobPodSpec is the Dashboards job's PodSpec.
type DashboardsJobPodSpec struct {

	// Containers is a list of dashboards job containers.
	// If specified, this overrides the specified Dashboard job containers.
	// If omitted, the Dashboard job will use its default values for its containers.
	// +optional
	Containers []DashboardsJobContainer `json:"containers,omitempty"`
}

// DashboardsJobContainer is the Dashboards job container.
type DashboardsJobContainer struct {
	// Name is an enum which identifies the Dashboard Job container by name.
	// +kubebuilder:validation:Enum=dashboards-installer
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named Dashboard Job container's resources.
	// If omitted, the Dashboard Job will use its default value for this container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}
