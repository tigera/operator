package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	APIServerStatusReady = "Ready"
)

// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// APIServerSpec defines the desired state of APIServer
// +k8s:openapi-gen=true
type APIServerSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book.kubebuilder.io/beyond_basics/generating_crd.html
}

// APIServerStatus defines the observed state of APIServer
// +k8s:openapi-gen=true
type APIServerStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book.kubebuilder.io/beyond_basics/generating_crd.html
	State string `json:"state,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// APIServer is the Schema for the apiservers API
// +k8s:openapi-gen=true
// +kubebuilder:subresource:status
type APIServer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   APIServerSpec   `json:"spec,omitempty"`
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
