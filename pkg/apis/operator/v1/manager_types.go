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

// ManagerSpec defines configuration for the Tigera Secure manager GUI.
// +k8s:openapi-gen=true
type ManagerSpec struct {
	// Auth defines the authentication strategy for the Tigera Secure manager GUI.
	// +optional
	Auth *Auth `json:"auth,omitempty"`
}

// ManagerStatus defines the observed state of the Tigera Secure manager GUI.
// +k8s:openapi-gen=true
type ManagerStatus struct {
	// The last successfully applied authentication configuration.
	// +optional
	Auth *Auth `json:"auth,omitempty"`
}

// Auth defines authentication configuration.
// +k8s:openapi-gen=true
type Auth struct {
	// Type configures the type of authentication used by the manager.
	// Default: Token
	// +kubebuilder:validation:Enum=Token,Basic,OIDC,OAuth
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

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +genclient
// +genclient:nonNamespaced

// Manager installs the Tigera Secure manager graphical user interface. At most one instance
// of this resource is supported. It must be named "tigera-secure".
// +k8s:openapi-gen=true
// +kubebuilder:subresource:status
type Manager struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the desired state for the Tigera Secure EE manager.
	Spec ManagerSpec `json:"spec,omitempty"`

	// Most recently observed state for the Tigera Secure EE manager.
	Status ManagerStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ManagerList contains a list of Manager
type ManagerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Manager `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Manager{}, &ManagerList{})
}
