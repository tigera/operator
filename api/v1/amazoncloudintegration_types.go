// Copyright (c) 2020-2024 Tigera, Inc. All rights reserved.
/*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// MetadataAccessAllowedType
type MetadataAccessAllowedType string

const (
	MetadataAccessAllowed MetadataAccessAllowedType = "Allowed"
	MetadataAccessDenied  MetadataAccessAllowedType = "Denied"
)

// AmazonCloudIntegrationSpec defines the desired state of AmazonCloudIntegration
type AmazonCloudIntegrationSpec struct {
	// DefaultPodMetadataAccess defines what the default behavior will be for accessing
	// the AWS metadata service from a pod.
	// Default: Denied
	// +optional
	// +kubebuilder:validation:Enum=Allowed;Denied
	DefaultPodMetadataAccess MetadataAccessAllowedType `json:"defaultPodMetadataAccess,omitempty"`

	// NodeSecurityGroupIDs is a list of Security Group IDs that all nodes and masters
	// will be in.
	NodeSecurityGroupIDs []string `json:"nodeSecurityGroupIDs,omitempty"`
	// PodSecurityGroupID is the ID of the Security Group which all pods should be placed
	// in by default.
	PodSecurityGroupID string `json:"podSecurityGroupID,omitempty"`
	// VPCS is a list of VPC IDs to monitor for ENIs and Security Groups, only one is supported.
	VPCS []string `json:"vpcs,omitempty"`
	// SQSURL is the SQS URL needed to access the Simple Queue Service.
	SQSURL string `json:"sqsURL,omitempty"`
	// AWSRegion is the region in which your cluster is located.
	AWSRegion string `json:"awsRegion,omitempty"`
	// EnforcedSecurityGroupID is the ID of the Security Group which will be applied to all
	// ENIs that are on a host that is also part of the Kubernetes cluster.
	EnforcedSecurityGroupID string `json:"enforcedSecurityGroupID,omitempty"`
	// TrustEnforcedSecurityGroupID is the ID of the Security Group which will be applied
	// to all ENIs in the VPC.
	TrustEnforcedSecurityGroupID string `json:"trustEnforcedSecurityGroupID,omitempty"`
}

// AmazonCloudIntegrationStatus defines the observed state of AmazonCloudIntegration
type AmazonCloudIntegrationStatus struct {
	// State provides user-readable status.
	State string `json:"state,omitempty"`

	// Conditions represents the latest observed set of conditions for the component. A component may be one or more of
	// Ready, Progressing, Degraded or other customer types.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// AmazonCloudIntegration is the Schema for the amazoncloudintegrations API
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:storageversion
type AmazonCloudIntegration struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AmazonCloudIntegrationSpec   `json:"spec,omitempty"`
	Status AmazonCloudIntegrationStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AmazonCloudIntegrationList contains a list of AmazonCloudIntegration
type AmazonCloudIntegrationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AmazonCloudIntegration `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AmazonCloudIntegration{}, &AmazonCloudIntegrationList{})
}
