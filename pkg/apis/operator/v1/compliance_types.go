package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	ComplianceStatusReady = "Ready"
)

// ComplianceSpec defines the desired state of Compliance
// +k8s:openapi-gen=true
type ComplianceSpec struct {
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book.kubebuilder.io/beyond_basics/generating_crd.html
}

// ComplianceStatus defines the observed state of Compliance
// +k8s:openapi-gen=true
type ComplianceStatus struct {
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book.kubebuilder.io/beyond_basics/generating_crd.html

	// State indicates the state of the deployment by the IntrusionDetection controller
	State string `json:"state,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Compliance is the Schema for the compliances API
// +k8s:openapi-gen=true
// +kubebuilder:subresource:status
type Compliance struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ComplianceSpec   `json:"spec,omitempty"`
	Status ComplianceStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ComplianceList contains a list of Compliance
type ComplianceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Compliance `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Compliance{}, &ComplianceList{})
}
