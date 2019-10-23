package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	LogControllerStatusReady = "Ready"
)

// LogCollectorSpec defines the desired state of Tigera flow, audit, and DNS log collection.
// +k8s:openapi-gen=true
type LogCollectorSpec struct {

	// Configuration for exporting flow, audit, and DNS logs to external storage.
	// +optional
	AdditionalStores *AdditionalLogStoreSpec `json:"additionalStores,omitempty"`
}

type AdditionalLogStoreSpec struct {
	// If specified, enables exporting of flow, audit, and DNS logs to Amazon S3 storage.
	// +optional
	S3 *S3StoreSpec `json:"s3,omitempty"`
	// If specified, enables exporting of flow, audit, and DNS logs to syslog.
	// +optional
	Syslog *SyslogStoreSpec `json:"syslog,omitempty"`
}

// S3StoreSpec defines configuration for exporting logs to Amazon S3.
// +k8s:openapi-gen=true
type S3StoreSpec struct {
	// AWS Region of the S3 bucket
	Region string `json:"region"`

	// Name of the S3 bucket to send logs
	BucketName string `json:"bucketName"`

	// Path in the S3 bucket where to send logs
	BucketPath string `json:"bucketPath"`
}

// SyslogStoreSpec defines configuration for exporting lgos to syslog.
type SyslogStoreSpec struct {
	// Location of the syslog server. exmple: tcp://1.2.3.4:601
	Endpoint string `json:"endpoint"`

	// PacketSize defines the maximum size of packets to send to syslog.
	// In general this is only needed if you notice long logs being truncated.
	// Default: 1024
	// +optional
	PacketSize *int32 `json:"packetsize,omitempty"`
}

// LogCollectorStatus defines the observed state of Tigera flow and DNS log collection
// +k8s:openapi-gen=true
type LogCollectorStatus struct {
	// State provides user-readable status.
	State string `json:"state,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +genclient

// LogCollector installs the components required for Tigera flow and DNS log collection. At most one instance
// of this resource is supported. It must be named "tigera-secure". When created, this installs fluentd on all nodes
// configured to collect Tigera log data and export it to Tigera's Elasticsearch cluster as well as any additionally configured destinations.
// +k8s:openapi-gen=true
// +kubebuilder:subresource:status
type LogCollector struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the desired state for Tigera log collection.
	Spec LogCollectorSpec `json:"spec,omitempty"`

	// Most recently observed state for Tigera log collection.
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
