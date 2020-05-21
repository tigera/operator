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
	CloudIntegrationStatusReady = "Ready"
)

// MetadataAccessAllowedType
type MetadataAccessAllowedType string

const (
	MetadataAccessAllowed MetadataAccessAllowedType = "Allowed"
	MetadataAccessDenied  MetadataAccessAllowedType = "Denied"
)

// AmazonCloudIntegrationSpec defines the desired state of AmazonCloudIntegration
// +k8s:openapi-gen=true
type AmazonCloudIntegrationSpec struct {
	// DefaultPodMetadataAccess defines what the default behavior will be for accessing
	// metadata from a pod.
	// Default: Denied
	// +optional
	// +kubebuilder:validation:Enum=Allowed,Denied
	DefaultPodMetadataAccess string `json:defaultPodMetadataAccess,omitempty"`

	NodeSecurityGroupIds         []string `json:"nodeSecurityGroupIds,omitempty"`
	PodSecurityGroupId           string   `json:"podSecurityGroupId,omitempty"`
	Vpcs                         []string `json:"vpcs,omitempty"`
	SqsUrl                       string   `json:"sqsUrl,omitempty"`
	AwsRegion                    string   `json:"awsRegion,omitempty"`
	EnforcedSecurityGroupId      string   `json:"enforcedSecurityGroupId,omitempty"`
	TrustEnforcedSecurityGroupId string   `json:"trustEnforcedSecurityGroupId,omitemtpy"`
}

// AmazonCloudIntegrationStatus defines the observed state of AmazonCloudIntegration
// +k8s:openapi-gen=true
type AmazonCloudIntegrationStatus struct {
	// State provides user-readable status.
	State string `json:"state,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AmazonCloudIntegration is the Schema for the amazoncloudintegrations API
// +k8s:openapi-gen=true
// +kubebuilder:subresource:status
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
