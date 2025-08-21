// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

// TigeraIstioSpec defines the desired state of TigeraIstio
type TigeraIstioSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Foo is an example field of TigeraIstio. Edit tigeraistio_types.go to remove/update
	// Foo string `json:"foo,omitempty"`
}

// TigeraIstioStatus defines the observed state of TigeraIstio
type TigeraIstioStatus struct {
	// IstioStatus reports the overall status of Istio resources managed by the operator
	IstioStatus string `json:"istioStatus,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster

// TigeraIstio is the Schema for the tigeraistios API
type TigeraIstio struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TigeraIstioSpec   `json:"spec,omitempty"`
	Status TigeraIstioStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TigeraIstioList contains a list of TigeraIstio
type TigeraIstioList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TigeraIstio `json:"items"`
}

func init() {
	SchemeBuilder.Register(&TigeraIstio{}, &TigeraIstioList{})
}
