package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// ElasticsearchConfigurationSpec defines the desired state of ElasticsearchConfiguration
// +k8s:openapi-gen=true
type ElasticsearchConfigurationSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book.kubebuilder.io/beyond_basics/generating_crd.html
}

// ElasticsearchConfigurationStatus defines the observed state of ElasticsearchConfiguration
// +k8s:openapi-gen=true
type ElasticsearchConfigurationStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book.kubebuilder.io/beyond_basics/generating_crd.html
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ElasticsearchConfiguration is the Schema for the elasticsearchconfigurations API
// +k8s:openapi-gen=true
// +kubebuilder:subresource:status
type ElasticsearchConfiguration struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ElasticsearchConfigurationSpec   `json:"spec,omitempty"`
	Status ElasticsearchConfigurationStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ElasticsearchConfigurationList contains a list of ElasticsearchConfiguration
type ElasticsearchConfigurationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ElasticsearchConfiguration `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ElasticsearchConfiguration{}, &ElasticsearchConfigurationList{})
}
