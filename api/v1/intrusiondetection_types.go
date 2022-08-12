// Copyright (c) 2020, 2022 Tigera, Inc. All rights reserved.
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

	// AnomalyDetection provides configuration for running AnomalyDetection Component within
	// IntrusionDetection.Anomaly Detection configuration will only be applied to standalone and
	// management clusters. The field is not used for managed clusters in a Multi-cluster
	// management setup.
	// +optional
	AnomalyDetection AnomalyDetectionSpec `json:"anomalyDetection,omitempty"`
}

type AnomalyDetectionSpec struct {
	// StorageType sets the type of storage to use for storing Anomaly Detection Models. By default it will use the ephemeral
	// emptyDir on the node Anomaly Detection will be deployed to.
	// default: Ephemeral
	// +optional
	// +kubebuilder:validation:Enum=Ephemeral;Persistent
	StorageType StorageType `json:"storageType,omitempty"`

	// StorageClassName will populate the PersistentVolumeClaim.StorageClassName that is used to provision disks for the
	// Anomaly Detection API pod for model storage. The StorageClassName should only be modified when no StorageClass is currently
	// active. We recommend choosing a storage class dedicated to AnomalyDetection only. Otherwise, model retention
	// cannot be guaranteed during upgrades. See https://docs.tigera.io/maintenance/upgrading for up-to-date instructions.
	// Default: tigera-anomaly-detection
	// +optional
	StorageClassName string `json:"storageClassName,omitempty"`
}

// StorageType sets the type of storage to be used for the specified component.
// One of: Ephemeral, Persistent
type StorageType string

const (
	// ephemeral storage type sets the ephemeral emptyDir() to be used by the component. Data created in this storage type will
	// follow the Pod's lifetime and get created and deleted along with the Pod.
	EphemeralStorageType StorageType = "Ephemeral"
	// PersistentStorageType mounts a PersistentVolume of the provided StorageClassName to Anomaly Detection pods in order to store data.
	PersistentStorageType StorageType = "Persistent"
)

// IntrusionDetectionStatus defines the observed state of Tigera intrusion detection capabilities.
type IntrusionDetectionStatus struct {
	// State provides user-readable status.
	State string `json:"state,omitempty"`
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
