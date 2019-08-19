package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// MonitoringConfigurationSpec defines the desired state of MonitoringConfiguration
// +k8s:openapi-gen=true
type MonitoringConfigurationSpec struct {
	ClusterName   string         `json:"clusterName"`
	Elasticsearch *ElasticConfig `json:"elasticsearch"`
}

type ElasticConfig struct {
	Endpoint string `json:"endpoint"`
}

// MonitoringConfigurationStatus defines the observed state of MonitoringConfiguration
// +k8s:openapi-gen=true
type MonitoringConfigurationStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book.kubebuilder.io/beyond_basics/generating_crd.html
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// MonitoringConfiguration is the Schema for the monitoringconfigurations API
// +k8s:openapi-gen=true
// +kubebuilder:subresource:status
type MonitoringConfiguration struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   MonitoringConfigurationSpec   `json:"spec,omitempty"`
	Status MonitoringConfigurationStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// MonitoringConfigurationList contains a list of MonitoringConfiguration
type MonitoringConfigurationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []MonitoringConfiguration `json:"items"`
}

func init() {
	SchemeBuilder.Register(&MonitoringConfiguration{}, &MonitoringConfigurationList{})
}
