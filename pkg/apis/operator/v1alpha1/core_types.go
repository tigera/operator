package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.
// NOTE: After modifying this file, run `make gen-files` to regenerate code.

// CoreSpec defines the desired state of Core
// +k8s:openapi-gen=true
type CoreSpec struct {
	CNINetDir    string `json:"cniNetDir,omitempty"`
	CNIBinDir    string `json:"cniBinDir,omitempty"`
	RunKubeProxy bool   `json:"kubeProxyRequired,omitempty"`
}

// CoreStatus defines the observed state of Core
// +k8s:openapi-gen=true
type CoreStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book.kubebuilder.io/beyond_basics/generating_crd.html
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Core is the Schema for the cores API
// +k8s:openapi-gen=true
// +kubebuilder:subresource:status
type Core struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CoreSpec   `json:"spec,omitempty"`
	Status CoreStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CoreList contains a list of Core
type CoreList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Core `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Core{}, &CoreList{})
}
