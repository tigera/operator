// Copyright (c) 2021-2023 Tigera, Inc. All rights reserved.
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

// ApplicationLayerSpec defines the desired state of ApplicationLayer
type ApplicationLayerSpec struct {
	// WebApplicationFirewall controls whether or not ModSecurity enforcement is enabled for the cluster.
	// When enabled, Services may opt-in to having ingress traffic examed by ModSecurity.
	WebApplicationFirewall *WAFStatusType `json:"webApplicationFirewall,omitempty"`
	// Specification for application layer (L7) log collection.
	LogCollection *LogCollectionSpec `json:"logCollection,omitempty"`
	// Application Layer Policy controls whether or not ALP enforcement is enabled for the cluster.
	// When enabled, NetworkPolicies with HTTP Match rules may be defined to opt-in workloads for traffic enforcement on the application layer.
	ApplicationLayerPolicy *ApplicationLayerPolicyStatusType `json:"applicationLayerPolicy,omitempty"`
	// WAF services holds a list of the services the user wants to apply the l7-logging annotation to
	WebApplicationFirewallServices *WAFServices `json:"webApplicationFirewallServices,omitempty"`
}

type LogCollectionStatusType string
type WAFStatusType string
type ApplicationLayerPolicyStatusType string

type WAFServices struct {
	Name string `json:"name"`
	Namespace string `json:"namespace"`
}

const (
	WAFDisabled                    WAFStatusType                    = "Disabled"
	WAFEnabled                     WAFStatusType                    = "Enabled"
	L7LogCollectionDisabled        LogCollectionStatusType          = "Disabled"
	L7LogCollectionEnabled         LogCollectionStatusType          = "Enabled"
	ApplicationLayerPolicyEnabled  ApplicationLayerPolicyStatusType = "Enabled"
	ApplicationLayerPolicyDisabled ApplicationLayerPolicyStatusType = "Disabled"
)

type LogCollectionSpec struct {

	// This setting enables or disable log collection.
	// Allowed values are Enabled or Disabled.
	// +optional
	CollectLogs *LogCollectionStatusType `json:"collectLogs,omitempty"`

	// Interval in seconds for sending L7 log information for processing.
	// +optional
	// Default: 5 sec
	LogIntervalSeconds *int64 `json:"logIntervalSeconds,omitempty"`

	// Maximum number of unique L7 logs that are sent LogIntervalSeconds.
	// Adjust this to limit the number of L7 logs sent per LogIntervalSeconds
	// to felix for further processing, use negative number to ignore limits.
	// +optional
	// Default: -1
	LogRequestsPerInterval *int64 `json:"logRequestsPerInterval,omitempty"`
}

// ApplicationLayerStatus defines the observed state of ApplicationLayer
type ApplicationLayerStatus struct {
	// WebApplicationFirewallServicesActive holds the currently services with the l7-logging annotation for WAF
	WebApplicationFirewallServicesActive *WAFServicesActive `json:"webApplicationFirewallServicesActive,omitempty"`

	// State provides user-readable status.
	State string `json:"state,omitempty"`

	// Conditions represents the latest observed set of conditions for the component. A component may be one or more of
	// Ready, Progressing, Degraded or other customer types.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

type WAFServicesActive struct {
	Name string `json:"name"`
	Namespace string `json:"namespace"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster

// ApplicationLayer is the Schema for the applicationlayers API
type ApplicationLayer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ApplicationLayerSpec   `json:"spec,omitempty"`
	Status ApplicationLayerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ApplicationLayerList contains a list of ApplicationLayer
type ApplicationLayerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ApplicationLayer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ApplicationLayer{}, &ApplicationLayerList{})
}
