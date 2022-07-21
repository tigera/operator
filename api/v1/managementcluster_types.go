// Copyright (c) 2012,2015-2022 Tigera, Inc. All rights reserved.
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

// ManagementClusterSpec defines the desired state of a ManagementCluster
type ManagementClusterSpec struct {
	// This field specifies the externally reachable address to which your managed cluster will connect. When a managed
	// cluster is added, this field is used to populate an easy-to-apply manifest that will connect both clusters.
	// Valid examples are: "0.0.0.0:31000", "example.com:32000", "[::1]:32500"
	// +optional
	Address string `json:"address,omitempty"`

	// TunnelCertType configures the product to serve the voltron tunnel using a publicly signed CA certificate instead
	// of using the same cert bundle which guardian client certs are signed with.
	//
	// Use of this flag requires uploading a ca bundle.
	//
	// Once enabled, all managed clusters will disconnect as they will no longer be able to verify Voltron's identity.
	// The apiserver will no longer include the management cluster cert in the resource bundle produced when
	// a new managed cluster resource is created. To reconnect existing managed clusters, generate a new cert bundle
	// which will not include the management cluster's cert, which will indicate to guardian it should use it's
	// installed certificates (in combination with the management cluster's hostname) to verify voltron's identity.
	// Default: SelfSigned
	// +optional
	TunnelCertType TunnelCertType `json:"tunnelCertType,omitempty"`
}

type TunnelCertType string

const (
	TunnelCertSelfSigned TunnelCertType = "SelfSigned"
	TunnelCertCASigned   TunnelCertType = "CASigned"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster

// The presence of ManagementCluster in your cluster, will configure it to be the management plane to which managed
// clusters can connect. At most one instance of this resource is supported. It must be named "tigera-secure".
type ManagementCluster struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ManagementClusterSpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true

// ManagementClusterList contains a list of ManagementCluster
type ManagementClusterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ManagementCluster `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ManagementCluster{}, &ManagementClusterList{})
}
