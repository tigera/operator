package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// MulticlusterConfigSpec defines the desired state of MulticlusterConfig
// +k8s:openapi-gen=true
type MulticlusterConfigSpec struct {

	// Valid values for this field are: "standalone", "management", "managed"
	// +optional
	// +kubebuilder:validation:Enum=standalone,management,managed
	ClusterManagementType string `json:"clusterManagementType,omitempty"`

	// Specify where the managed cluster can reach the management cluster.
	// +optional
	ManagementClusterAddr string `json:"managementClusterAddr,omitempty"`

	// Specify the port that the management cluster is listening on.
	// +optional
	ManagementClusterPort int `json:"managementClusterPort,omitempty"`

	// This certificate is used to establish a secure connection between clusters. If this field is omitted, a
	// self-signed certificate will be created when a managed cluster is added to a management cluster.
	// +optional
	ManagedClusterIdentityCert string `json:"managedClusterIdentityCert,omitempty"`
}

// MulticlusterConfigStatus defines the observed state of MulticlusterConfig
// +k8s:openapi-gen=true
type MulticlusterConfigStatus struct {

	// State provides user-readable status.
	// +optional
	State string `json:"state,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +genclient
// +genclient:nonNamespaced

// MulticlusterConfig is the Schema for the multiclusterconfigs API
// +k8s:openapi-gen=true
type MulticlusterConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   MulticlusterConfigSpec   `json:"spec,omitempty"`
	Status MulticlusterConfigStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// MulticlusterConfigList contains a list of MulticlusterConfig
type MulticlusterConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []MulticlusterConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(&MulticlusterConfig{}, &MulticlusterConfigList{})
}
