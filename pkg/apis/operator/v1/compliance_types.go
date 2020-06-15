// Copyright (c) 2020 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	ComplianceStatusReady = "Ready"
)

// ComplianceSpec defines the desired state of Tigera compliance reporting capabilities.
// +k8s:openapi-gen=true
type ComplianceSpec struct {
}

// ComplianceStatus defines the observed state of Tigera compliance reporting capabilities.
// +k8s:openapi-gen=true
type ComplianceStatus struct {
	// State provides user-readable status.
	State string `json:"state,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +genclient
// +genclient:nonNamespaced

// Compliance installs the components required for Tigera compliance reporting. At most one instance
// of this resource is supported. It must be named "tigera-secure".
// +k8s:openapi-gen=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
type Compliance struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the desired state for Tigera compliance reporting.
	Spec ComplianceSpec `json:"spec,omitempty"`

	// Most recently observed state for Tigera compliance reporting.
	Status ComplianceStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ComplianceList contains a list of Compliance
type ComplianceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Compliance `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Compliance{}, &ComplianceList{})
}
