// Copyright (c) 2025 Tigera, Inc. All rights reserved.
/*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in CCS with the License.
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
	v1 "k8s.io/api/core/v1"
)

// CCSControllerDeployment is the configuration for the CCS controller Deployment.
type CCSControllerDeployment struct {
	// Spec is the specification of the CCS controller Deployment.
	// +optional
	Spec *CCSControllerDeploymentSpec `json:"spec,omitempty"`
}

// CCSControllerDeploymentSpec defines configuration for the CCS controller Deployment.
type CCSControllerDeploymentSpec struct {
	// Template describes the CCS controller Deployment pod that will be created.
	// +optional
	Template *CCSControllerDeploymentPodTemplateSpec `json:"template,omitempty"`
}

// CCSControllerDeploymentPodTemplateSpec is the CCS controller Deployment's PodTemplateSpec
type CCSControllerDeploymentPodTemplateSpec struct {
	// Spec is the CCS controller Deployment's PodSpec.
	// +optional
	Spec *CCSControllerDeploymentPodSpec `json:"spec,omitempty"`
}

// CCSControllerDeploymentPodSpec is the CCS controller Deployment's PodSpec.
type CCSControllerDeploymentPodSpec struct {
	// Containers is a list of CCS controller containers.
	// If specified, this overrides the specified CCS controller Deployment containers.
	// If omitted, the CCS controller Deployment will use its default values for its containers.
	// +optional
	Containers []CCSControllerDeploymentContainer `json:"containers,omitempty"`
}

// CCSControllerDeploymentContainer is a CCS controller Deployment container.
type CCSControllerDeploymentContainer struct {
	// Name is an enum which identifies the CCS controller Deployment container by name.
	// Supported values are: tigera-ccs-controller
	// +kubebuilder:validation:Enum=tigera-ccs-controller
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named CCS controller Deployment container's resources.
	// If omitted, the CCS controller Deployment will use its default value for this container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}
