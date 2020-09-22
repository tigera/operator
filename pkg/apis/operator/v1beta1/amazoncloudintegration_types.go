package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AmazonCloudIntegrationSpec defines the desired state of AmazonCloudIntegration
type AmazonCloudIntegrationSpec struct {
}

// AmazonCloudIntegrationStatus defines the observed state of AmazonCloudIntegration
type AmazonCloudIntegrationStatus struct {
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AmazonCloudIntegration is the Schema for the amazoncloudintegrations API
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=amazoncloudintegrations,scope=Cluster
// +kubebuilder:unservedversion
type AmazonCloudIntegration struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AmazonCloudIntegrationSpec   `json:"spec,omitempty"`
	Status AmazonCloudIntegrationStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AmazonCloudIntegrationList contains a list of AmazonCloudIntegration
type AmazonCloudIntegrationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AmazonCloudIntegration `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AmazonCloudIntegration{}, &AmazonCloudIntegrationList{})
}
