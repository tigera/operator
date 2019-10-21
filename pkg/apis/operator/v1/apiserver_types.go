package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	APIServerStatusReady = "Ready"
)

// APIServerSpec defines the desired state of Tigera API server.
// +k8s:openapi-gen=true
type APIServerSpec struct {
}

// APIServerStatus defines the observed state of Tigera API server.
// +k8s:openapi-gen=true
type APIServerStatus struct {
	// State provides user-readable status.
	State string `json:"state,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// APIServer installs the Tigera API server and related resources. At most one instance
// of this resource is supported. It must be named "tigera-secure".
// +k8s:openapi-gen=true
// +kubebuilder:subresource:status
type APIServer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the desired state for the Tigera API server.
	Spec APIServerSpec `json:"spec,omitempty"`

	// Most recently observed status for the Tigera API server.
	Status APIServerStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// APIServerList contains a list of APIServer
type APIServerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []APIServer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&APIServer{}, &APIServerList{})
}
