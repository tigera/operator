// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CloudRBACSpec defines the desired state of CloudRBAC
type CloudRBACSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	PortalURL string `json:"portalURL,omitempty"`
}

// CloudRBACStatus defines the observed state of CloudRBAC
type CloudRBACStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster

// CloudRBAC is the Schema for the cloudrbacs API
type CloudRBAC struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CloudRBACSpec   `json:"spec,omitempty"`
	Status CloudRBACStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// CloudRBACList contains a list of CloudRBAC
type CloudRBACList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CloudRBAC `json:"items"`
}

func init() {
	SchemeBuilder.Register(&CloudRBAC{}, &CloudRBACList{})
}
