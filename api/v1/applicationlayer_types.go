// Copyright (c) 2021 Tigera, Inc. All rights reserved.
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
	"k8s.io/apimachinery/pkg/runtime"
)

// ApplicationLayerSpec defines the desired state of ApplicationLayer
type ApplicationLayerSpec struct {
	// specification for L7 log collection
	L7LogCollection *L7LogCollectionSpec `json:"l7LogCollection,omitempty"`
}

type L7LogCollectionStatusType string

const (
	L7LogCollectionDisabled L7LogCollectionStatusType = "Disabled"
	L7LogCollectionEnabled  L7LogCollectionStatusType = "Enabled"
)

type L7LogCollectionSpec struct {

	// Setting this option to Enabled will enable l7 log collection
	// +optional
	CollectL7Logs *L7LogCollectionStatusType `json:"collectL7Logs,omitempty"`

	// Interval in seconds for sending L7 log information for processing.
	// adjust this to limit the frequency at which logs are sent from l7-collector
	// +optional
	// Default: 5 sec
	LogIntervalSeconds *int64 `json:"logIntervalSeconds,omitempty"`

	// Maximum number of unique L7 logs that are sent LogIntervalSeconds
	// adjust this to limit the number of L7 logs sent per LogIntervalSeconds
	// to felix for further processing, use negative number to ignore limits
	// +optional
	// Default: -1
	LogRequestsPerInterval *int64 `json:"logRequestsPerInterval,omitempty"`
}

// ApplicationLayerStatus defines the observed state of ApplicationLayer
type ApplicationLayerStatus struct {
	// State provides user-readable status.
	State string `json:"state,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster

// ApplicationLayer is the Schema for the applicationlayers API
type ApplicationLayer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ApplicationLayerSpec   `json:"spec,omitempty"`
	Status ApplicationLayerStatus `json:"status,omitempty"`
}

func (a ApplicationLayer) DeepCopyObject() runtime.Object {
	panic("implement me")
}

// +kubebuilder:object:root=true

// ApplicationLayerList contains a list of ApplicationLayer
type ApplicationLayerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ApplicationLayer `json:"items"`
}

func (a ApplicationLayerList) DeepCopyObject() runtime.Object {
	panic("implement me")
}

func init() {
	SchemeBuilder.Register(&ApplicationLayer{}, &ApplicationLayerList{})
}
