// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
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

// ManagerSpec defines configuration for the Calico Enterprise manager GUI.
type ManagerSpec struct {
	// Deprecated. Please use the Authentication CR for configuring authentication.
	// +optional
	Auth *Auth `json:"auth,omitempty"`
}

// ManagerStatus defines the observed state of the Calico Enterprise manager GUI.
type ManagerStatus struct {
	// Deprecated. Please use the Authentication CR for configuring authentication.
	// +optional
	Auth *Auth `json:"auth,omitempty"`

	// State provides user-readable status.
	State string `json:"state,omitempty"`

	// Conditions represents the latest observed set of conditions for the component. A component may be one or more of
	// Ready, Progressing, Degraded or other customer types.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// Auth defines authentication configuration.
type Auth struct {
	// Type configures the type of authentication used by the manager.
	// Default: Token
	// +kubebuilder:validation:Enum=Token;Basic;OIDC;OAuth
	Type AuthType `json:"type,omitempty"`

	// Authority configures the OAuth2/OIDC authority/issuer when using OAuth2 or OIDC login.
	// +optional
	Authority string `json:"authority,omitempty"`

	// ClientId configures the OAuth2/OIDC client ID to use for OAuth2 or OIDC login.
	// +optional
	ClientID string `json:"clientID,omitempty"`
}

// AuthType represents the type of authentication to use. Valid
// options are: Token, Basic, OIDC, OAuth
type AuthType string

const (
	AuthTypeToken = "Token"
	AuthTypeBasic = "Basic"
	AuthTypeOIDC  = "OIDC"
	AuthTypeOAuth = "OAuth"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster

// Manager installs the Calico Enterprise manager graphical user interface. At most one instance
// of this resource is supported. It must be named "tigera-secure".
type Manager struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the desired state for the Calico Enterprise manager.
	Spec ManagerSpec `json:"spec,omitempty"`
	// Most recently observed state for the Calico Enterprise manager.
	Status ManagerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ManagerList contains a list of Manager
type ManagerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Manager `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Manager{}, &ManagerList{})
}
