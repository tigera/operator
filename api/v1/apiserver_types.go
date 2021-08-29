// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// APIServerSpec defines the desired state of Tigera API server.
type APIServerSpec struct {
	// Replicas defines how many replicas of the API server components will be deployed. Defaults to 1.
	// +optional
	Replicas *int32 `json:"replicas,omitempty"`
}

// APIServerStatus defines the observed state of Tigera API server.
type APIServerStatus struct {
	// State provides user-readable status.
	State string `json:"state,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// APIServer installs the Tigera API server and related resources. At most one instance
// of this resource is supported. It must be named "tigera-secure".
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
type APIServer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the desired state for the Tigera API server.
	Spec APIServerSpec `json:"spec,omitempty"`

	// Most recently observed status for the Tigera API server.
	Status APIServerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// APIServerList contains a list of APIServer
type APIServerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []APIServer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&APIServer{}, &APIServerList{})
}
