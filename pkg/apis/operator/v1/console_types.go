package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ConsoleSpec defines optional configuration for the Tigera Secure management console.
// Valid only for the variant 'TigeraSecureEnterprise'.
// +k8s:openapi-gen=true
type ConsoleSpec struct {
	// Auth is optional authentication configuration for the Tigera Secure management console.
	// +optional
	Auth *Auth `json:"auth,omitempty"`
}

// ConsoleStatus defines the observed state of Console
// +k8s:openapi-gen=true
type ConsoleStatus struct {
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

// Console is the Schema for the consoles API
// +k8s:openapi-gen=true
// +kubebuilder:subresource:status
type Console struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ConsoleSpec   `json:"spec,omitempty"`
	Status ConsoleStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ConsoleList contains a list of Console
type ConsoleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Console `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Console{}, &ConsoleList{})
}
