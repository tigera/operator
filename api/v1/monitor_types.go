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
)

// MonitorSpec defines the desired state of Tigera monitor.
type MonitorSpec struct {

	// PrometheusServiceListenPort defines the port that tigera-prometheus-service
	// pod listens to and the TargetPort of calico-node-prometheus service.
	// If not set it defaults to port 9090. In the scenario that the cluster
	// is hosted on EKS and using Calico as it's CNI, tigera-prometheus-service
	// will be HostNetwoked.  Configure this, if the default port value conflicts
	// with any other ports currently used in the cluster's node network namespace.
	PrometheusServiceListenPort int `json:"prometheusServiceListenPort,omitempty"`
}

// MonitorStatus defines the observed state of Tigera monitor.
type MonitorStatus struct {
	// State provides user-readable status.
	State string `json:"state,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:subresource:status

// Monitor is the Schema for the monitor API. At most one instance
// of this resource is supported. It must be named "tigera-secure".
type Monitor struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   MonitorSpec   `json:"spec,omitempty"`
	Status MonitorStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// MonitorList contains a list of Monitor
type MonitorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Monitor `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Monitor{}, &MonitorList{})
}
