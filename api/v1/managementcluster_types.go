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

	// TLS provides options for configuring how Managed Clusters can establish an mTLS connection with the Management Cluster.
	// +optional
	TLS TLS `json:"tls,omitempty"`
}

type TLS struct {
	// secretName indicates the name of the secret in the tigera-operator namespace that contains a certificate bundle which should be used to serve voltron's tunnel.
	//
	// Currently, only two values are supported: tigera-management-cluster-connection and manager-tls.
	//
	// When set to tigera-management-cluster-connection voltron will use the same cert bundle which Guardian client certs are signed with.
	//
	// When set to manager-tls, voltron will use the same cert bundle which Manager UI is served with.
	//
	// If changed on a running cluster with connected managed clusters, all managed clusters will disconnect as they will no longer be able to verify Voltron's identity.
	// To reconnect existing managed clusters, change the tls.ca of the  managed clusters' ManagementClusterConnection resource.
	//
	// +optional
	// Default: tigera-management-cluster-connection
	SecretName string `json:"secretName,omitempty"`

	// ca indicates how the tls.secretName cert which Voltron is using was signed.
	// This information is used by the Tigera API Server when generating ManagementClusterConnection resources as it does in response to the creation of a ManagedCluster resource.
	// See information on ManagementClusterConnectionTLS for more information on the effects of its values.
	//
	// Currently, 'Public' is only supported with a tls.secretName of manager-tls, and Tigera is only supported with a tls.secretName of tigera-management-cluster-connection.
	//
	// Note that using a self-signed bundle in tls.secretName=manager-tls while setting tls.ca=Public will result in tunnel clients being unable to verify the tunnel server's identity. If using tls.ca=Public with tls.secretName=manager-tls, a publicly signed cert bundle must be uploaded as manager-tls, as otherwise the operator will generate a self-signed one resulting in tunnel clients being unable to verify voltron's identity.
	//
	// +optional
	// Default: SelfSigned
	CA CAType `json:"ca,omitempty"`
}

type CAType string

const (
	CATypeTigera CAType = "Tigera"
	CATypePublic CAType = "Public"
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
