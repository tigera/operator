// Copyright (c) 2020-2024 Tigera, Inc. All rights reserved.
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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// IntrusionDetectionSpec defines the desired state of Tigera intrusion detection capabilities.
type IntrusionDetectionSpec struct {
	// ComponentResources can be used to customize the resource requirements for each component.
	// Only DeepPacketInspection is supported for this spec.
	// +optional
	ComponentResources []IntrusionDetectionComponentResource `json:"componentResources,omitempty"`

	// AnomalyDetection is now deprecated, and configuring it has no effect.
	// +optional
	AnomalyDetection AnomalyDetectionSpec `json:"anomalyDetection,omitempty"`
}

type AnomalyDetectionSpec struct {

	// StorageClassName is now deprecated, and configuring it has no effect.
	// +optional
	StorageClassName string `json:"storageClassName,omitempty"`
}

// IntrusionDetectionStatus defines the observed state of Tigera intrusion detection capabilities.
type IntrusionDetectionStatus struct {
	// State provides user-readable status.
	State string `json:"state,omitempty"`

	// Conditions represents the latest observed set of conditions for the component. A component may be one or more of
	// Ready, Progressing, Degraded or other customer types.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster

// IntrusionDetection installs the components required for Tigera intrusion detection. At most one instance
// of this resource is supported. It must be named "tigera-secure".
type IntrusionDetection struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the desired state for Tigera intrusion detection.
	Spec IntrusionDetectionSpec `json:"spec,omitempty"`
	// Most recently observed state for Tigera intrusion detection.
	Status IntrusionDetectionStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// IntrusionDetectionList contains a list of IntrusionDetection
type IntrusionDetectionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []IntrusionDetection `json:"items"`
}

type IntrusionDetectionComponentName string

const (
	ComponentNameDeepPacketInspection IntrusionDetectionComponentName = "DeepPacketInspection"
)

// The ComponentResource struct associates a ResourceRequirements with a component by name
type IntrusionDetectionComponentResource struct {
	// ComponentName is an enum which identifies the component
	// +kubebuilder:validation:Enum=DeepPacketInspection
	ComponentName IntrusionDetectionComponentName `json:"componentName"`
	// ResourceRequirements allows customization of limits and requests for compute resources such as cpu and memory.
	ResourceRequirements *corev1.ResourceRequirements `json:"resourceRequirements"`
}

func init() {
	SchemeBuilder.Register(&IntrusionDetection{}, &IntrusionDetectionList{})
}
