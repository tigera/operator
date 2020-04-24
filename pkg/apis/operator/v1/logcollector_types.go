// Copyright (c) 2020 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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

	// Configuration for importing audit logs from managed kubernetes cluster log sources.
	// +optional
	AdditionalSources *AdditionalLogSourceSpec `json:"additionalSources,omitempty"`
}

type AdditionalLogStoreSpec struct {
	// If specified, enables exporting of flow, audit, and DNS logs to Amazon S3 storage.
	// +optional
	S3 *S3StoreSpec `json:"s3,omitempty"`
	// If specified, enables exporting of flow, audit, and DNS logs to syslog.
	// +optional
	Syslog *SyslogStoreSpec `json:"syslog,omitempty"`
	// If specified, enables exporting of flow, audit, and DNS logs to splunk.
	// +optional
	Splunk *SplunkStoreSpec `json:"splunk,omitempty"`
}

type AdditionalLogSourceSpec struct {
	// If specified with EKS Provider in Installation, enables fetching EKS
	// audit logs.
	// +optional
	EksCloudwatchLog *EksCloudwatchLogsSpec `json:"eksCloudwatchLog,omitempty"`
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

// SyslogStoreSpec defines configuration for exporting logs to syslog.
type SyslogStoreSpec struct {
	// Location of the syslog server. example: tcp://1.2.3.4:601
	Endpoint string `json:"endpoint"`

	// PacketSize defines the maximum size of packets to send to syslog.
	// In general this is only needed if you notice long logs being truncated.
	// Default: 1024
	// +optional
	PacketSize *int32 `json:"packetsize,omitempty"`
}

// SplunkStoreSpec defines configuration for exporting logs to splunk.
type SplunkStoreSpec struct {
	// Location for splunk's http event collector end point. example https://1.2.3.4:8088
	Endpoint string `json:"endpoint"`
}

// EksConfigSpec defines configuration for fetching EKS audit logs.
type EksCloudwatchLogsSpec struct {
	// AWS Region EKS cluster is hosted in.
	Region string `json:"region"`

	// Cloudwatch log-group name containing EKS audit logs.
	GroupName string `json:"groupName"`

	// Prefix of Cloudwatch log stream containing EKS audit logs in the log-group.
	// Default: kube-apiserver-audit-
	// +optional
	StreamPrefix string `json:"streamPrefix,omitempty"`

	// Cloudwatch audit logs fetching interval in seconds.
	// Default: 60
	// +optional
	FetchInterval int32 `json:"fetchInterval,omitempty"`
}

// LogCollectorStatus defines the observed state of Tigera flow and DNS log collection
// +k8s:openapi-gen=true
type LogCollectorStatus struct {
	// State provides user-readable status.
	State string `json:"state,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +genclient
// +genclient:nonNamespaced

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
