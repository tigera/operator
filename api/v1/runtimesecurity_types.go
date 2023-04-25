// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package v1

import (
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// RuntimeSecuritySpec defines the desired state of RuntimeSecurity
type RuntimeSecuritySpec struct {
	Sasha    SashaSpec    `json:"sasha,omitempty"`
	ThreatId ThreatIdSpec `json:"threatId,omitempty"`
}

type SashaSpec struct {
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

type ThreatIdSpec struct {
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

// RuntimeSecurityStatus defines the observed state of RuntimeSecurity
type RuntimeSecurityStatus struct {
	State string `json:"state,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster

// RuntimeSecurity is the Schema for the runtimesecurities API
type RuntimeSecurity struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RuntimeSecuritySpec   `json:"spec,omitempty"`
	Status RuntimeSecurityStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// RuntimeSecurityList contains a list of RuntimeSecurity
type RuntimeSecurityList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []RuntimeSecurity `json:"items"`
}

func init() {
	SchemeBuilder.Register(&RuntimeSecurity{}, &RuntimeSecurityList{})
}
