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

// ManagementClusterConnectionSpec defines the desired state of ManagementClusterConnection
// +k8s:openapi-gen=true
type ManagementClusterConnectionSpec struct {

	// Specify where the managed cluster can reach the management cluster. Ex.: "10.128.0.10:30449". A managed cluster
	// should be able to access this address. This field is used by managed clusters only.
	// +optional
	ManagementClusterAddr string `json:"managementClusterAddr,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +genclient
// +genclient:nonNamespaced

// ManagementClusterConnection represents a link between a managed cluster and a management cluster. At most one
// instance of this resource is supported. It must be named "tigera-secure".
// +k8s:openapi-gen=true
type ManagementClusterConnection struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ManagementClusterConnectionSpec `json:"spec,omitempty"`

	Status ManagementClusterConnectionStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ManagementClusterConnectionList contains a list of ManagementClusterConnection.
type ManagementClusterConnectionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ManagementClusterConnection `json:"items"`
}

// ManagementClusterConnectionStatus gives recently the observed state of tunnel between managed and management cluster
// +k8s:openapi-gen=true
type ManagementClusterConnectionStatus struct {
	State string `json:"state,omitempty"`
}

func init() {
	SchemeBuilder.Register(&ManagementClusterConnection{}, &ManagementClusterConnectionList{})
}
