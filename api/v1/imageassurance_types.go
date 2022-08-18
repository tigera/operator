// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ImageAssuranceSpec defines the desired state of ImageAssurance
type ImageAssuranceSpec struct {
	// APIProxyURL is the url the api proxy should proxy too.
	APIProxyURL string `json:"apiProxyURL,omitempty"`
}

// ImageAssuranceStatus defines the observed state of ImageAssurance
type ImageAssuranceStatus struct {
	// State provides user-readable status.
	State string `json:"state,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster

// ImageAssurance is the Schema for the imageassurances API
type ImageAssurance struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ImageAssuranceSpec   `json:"spec,omitempty"`
	Status ImageAssuranceStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ImageAssuranceList contains a list of ImageAssurance
type ImageAssuranceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ImageAssurance `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ImageAssurance{}, &ImageAssuranceList{})
}
