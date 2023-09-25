// Copyright (c) 2023 Tigera, Inc. All rights reserved.
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

type TenantSpec struct {
	// ID is the unique identifier for this tenant.
	// +required
	ID string `json:"id,omitempty"`

	// DataRetention defines the how to store a tenant's data
	DataRetention []DataRetention `json:"dataRetention"`
}

// DataRetention defines the amount of time for tenant's
// data to be stored based on predefined tiers
type DataRetention struct {
	// PolicyName identifies the ILM policy used
	// store data in Elastic
	PolicyName string `json:"policyName"`

	// IndexName defines the name of the index
	// that will be used to store data (this name
	// excludes the numerical identifier suffix)
	IndexName string `json:"indexName"`

	// +kubebuilder:validation:Enum=alerts;audit;bgp;compliance_benchmarks;compliance_reports;compliance_snapshots;dns;flow;l7;runtime;threat_feeds_domain_name;thread_feeds_ip_set;waf
	Type string `json:"type"`
}

type TenantStatus struct{}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// Tenant is the Schema for the tenants API
type Tenant struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TenantSpec   `json:"spec,omitempty"`
	Status TenantStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TenantList contains a list of Tenant
type TenantList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Tenant `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Tenant{}, &TenantList{})
}
