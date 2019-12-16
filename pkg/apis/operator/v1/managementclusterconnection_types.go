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

// ManagementClusterConnection installs the components required to establish a tunnel between two clusters. At most one
// instance of this resource is supported. It must be named "tigera-secure".
// +k8s:openapi-gen=true
type ManagementClusterConnection struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ManagementClusterConnectionSpec `json:"spec,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ManagementClusterConnectionList contains a list of ManagementClusterConnection.
type ManagementClusterConnectionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ManagementClusterConnection `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ManagementClusterConnection{}, &ManagementClusterConnectionList{})
}
