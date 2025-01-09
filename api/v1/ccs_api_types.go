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

// CCSAPIDeployment is the configuration for the CCS API Deployment.
type CCSAPIDeployment struct {
	// Spec is the specification of the CCS API Deployment.
	// +optional
	Spec *CCSAPIDeploymentSpec `json:"spec,omitempty"`
}

// CCSAPIDeploymentSpec defines configuration for the CCS API Deployment.
type CCSAPIDeploymentSpec struct {
	// Template describes the CCS API Deployment pod that will be created.
	// +optional
	Template *CCSAPIDeploymentPodTemplateSpec `json:"template,omitempty"`
}

// CCSAPIDeploymentPodTemplateSpec is the CCS API Deployment's PodTemplateSpec
type CCSAPIDeploymentPodTemplateSpec struct {
	// Spec is the CCS API Deployment's PodSpec.
	// +optional
	Spec *CCSAPIDeploymentPodSpec `json:"spec,omitempty"`
}

// CCSAPIDeploymentPodSpec is the CCS API Deployment's PodSpec.
type CCSAPIDeploymentPodSpec struct {
	// Containers is a list of CCS API containers.
	// If specified, this overrides the specified CCS API Deployment containers.
	// If omitted, the CCS API Deployment will use its default values for its containers.
	// +optional
	Containers []CCSAPIDeploymentContainer `json:"containers,omitempty"`
}

// CCSAPIDeploymentContainer is a CCS API Deployment container.
type CCSAPIDeploymentContainer struct {
	// Name is an enum which identifies the CCS API Deployment container by name.
	// Supported values are: tigera-ccs-api
	// +kubebuilder:validation:Enum=tigera-ccs-api
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named CCS API Deployment container's resources.
	// If omitted, the CCS API Deployment will use its default value for this container's resources.
	// +optional
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}
