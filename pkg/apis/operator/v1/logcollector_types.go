package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	LogControllerStatusReady = "Ready"
)

// LogCollectorSpec defines the desired state of LogCollector
// Valid only for the variant 'TigeraSecureEnterprise'.
// +k8s:openapi-gen=true
type LogCollectorSpec struct {
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book.kubebuilder.io/beyond_basics/generating_crd.html

	S3     *S3StoreSpec     `json:"s3,omitempty"`
	Syslog *SyslogStoreSpec `json:"syslog,omitempty"`
}

type S3StoreSpec struct {
	// AWS Region of the S3 bucket
	Region string `json:"region"`
	// Name of the S3 bucket to send logs
	BucketName string `json:"bucketName"`
	// Path in the S3 bucket where to send logs
	BucketPath string `json:"bucketPath"`
}

type SyslogStoreSpec struct {
	// Endpoint where to seen syslog. exmple: tcp://1.2.3.4:601
	Endpoint string `json:"endpoint"`
	// PacketSize is only needed if you notice long logs being truncated.
	// The default for the fluentd output plugin is 1024.
	PacketSize *int32 `json:"packetsize,omitempty"`
}

// LogCollectorStatus defines the observed state of LogCollector
// +k8s:openapi-gen=true
type LogCollectorStatus struct {
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book.kubebuilder.io/beyond_basics/generating_crd.html

	// State indicates the state of the daemonset by the LogCollector controller
	State string `json:"state,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// LogCollector is the Schema for the logcollectors API
// +k8s:openapi-gen=true
// +kubebuilder:subresource:status
type LogCollector struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   LogCollectorSpec   `json:"spec,omitempty"`
	Status LogCollectorStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// LogCollectorList contains a list of LogCollector
type LogCollectorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []LogCollector `json:"items"`
}

func init() {
	SchemeBuilder.Register(&LogCollector{}, &LogCollectorList{})
}
