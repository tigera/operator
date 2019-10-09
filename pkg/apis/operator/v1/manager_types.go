package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ManagerSpec defines optional configuration for the Tigera Secure management console.
// Valid only for the variant 'TigeraSecureEnterprise'.
// +k8s:openapi-gen=true
type ManagerSpec struct {
	// Auth is optional authentication configuration for the Tigera Secure management console.
	// +optional
	Auth *Auth `json:"auth,omitempty"`
}

// ManagerStatus defines the observed state of Manager
// +k8s:openapi-gen=true
type ManagerStatus struct {
	Auth *Auth `json:"auth,omitempty"`
}

// Auth defines authentication configuration.
// +k8s:openapi-gen=true
type Auth struct {
	// Type configures the type of authentication used by the manager.
	// Default: "Basic"
	Type AuthType `json:"type,omitempty"`

	// Authority configures the OAuth2/OIDC authority/issuer when using OAuth2 or OIDC login.
	// Default: ""https://accounts.google.com"
	// +optional
	Authority string `json:"authority,omitempty"`

	// ClientId configures the OAuth2/OIDC client ID to use for OAuth2 or OIDC login.
	// +optional
	ClientID string `json:"clientID,omitempty"`
}

type AuthType string

const (
	AuthTypeToken = "Token"
	AuthTypeBasic = "Basic"
	AuthTypeOIDC  = "OIDC"
	AuthTypeOAuth = "OAuth"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Manager is the Schema for the managers API
// +k8s:openapi-gen=true
// +kubebuilder:subresource:status
type Manager struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ManagerSpec   `json:"spec,omitempty"`
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
