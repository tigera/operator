// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

// ComplianceConfigurationSecuritySpec defines the desired state of CCS.
type ComplianceConfigurationSecuritySpec struct {
	// This controls the deployment of the CCS controller.
	CCSControllerDeployment *CCSControllerDeployment `json:"ccsControllerDeployment,omitempty"`

	// This controls the deployment of the CCS API.
	CCSAPIDeployment *CCSAPIDeployment `json:"ccsAPIDeployment,omitempty"`
}

// ComplianceConfigurationSecurityStatus defines the observed state of CCS.
type ComplianceConfigurationSecurityStatus struct {
	// State provides user-readable status.
	State string `json:"state,omitempty"`

	// Conditions represents the latest observed set of conditions for the component. A component may be one or more of
	// Ready, Progressing, Degraded or other customer types.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster

// ComplianceConfigurationSecurity installs the components required for CCS reports.
type ComplianceConfigurationSecurity struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// Specification of the desired state for CCS.
	Spec ComplianceConfigurationSecuritySpec `json:"spec,omitempty"`
	// Most recently observed state for CCS.
	Status ComplianceConfigurationSecurityStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ComplianceConfigurationSecurityList contains a list of ComplianceConfigurationSecurity
type ComplianceConfigurationSecurityList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ComplianceConfigurationSecurity `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ComplianceConfigurationSecurity{}, &ComplianceConfigurationSecurityList{})
}
