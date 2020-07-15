package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type AuthMethod string

const (
	AuthMethodOIDC AuthMethod = "OIDC"
)

// AuthenticationSpec defines the desired state of Authentication
type AuthenticationSpec struct {
	// Method configures the method of authentication used by Kibana.
	// Default: Basic
	// +kubebuilder:validation:Enum=Basic;OIDC
	// +required
	Method AuthMethod `json:"method,omitempty"`

	// ManagerDomain is the domain name of the Manager
	// +required
	ManagerDomain string `json:"managerDomain,omitempty"`

	// OIDC contains the configuration needed to setup OIDC authentication. If the method is OIDC then this is required, if
	// the method is not OIDC then this must not be specified.
	// +optional
	OIDC *AuthenticationOIDC `json:"oidc"`
}

// AuthenticationStatus defines the observed state of Authentication
type AuthenticationStatus struct {
	// State provides user-readable status.
	State string `json:"state,omitempty"`
}

// AuthenticationOIDC is the configuration needed to setup OIDC.
type AuthenticationOIDC struct {
	// IssuerURL is the URL to the OIDC provider.
	// +required
	IssuerURL string `json:"issuerURL"`

	// UsernameClaim specifies which claim to use from the OIDC provider as the username.
	// +required
	UsernameClaim string `json:"usernameClaim"`

	// RequestedScopes is a list of scopes to request from the OIDC provider. If not provided, all the available scopes
	// are requested.
	// + optional
	RequestedScopes []string `json:"requestedScopes"`

	// If specified, UsernamePrefix is prepended to each user obtained from the claims specified by UsernameClaim. Note that
	// Kibana does not support a user prefix, so this prefix is removed from Kubernetes User when translating log access
	// ClusterRoleBindings into Elastic.
	// +optional
	UsernamePrefix string `json:"usernamePrefix,omitempty"`

	// GroupsClaim specifies which claim to use from the OIDC provider as the group.
	// +optional
	GroupsClaim string `json:"groupsClaim,omitempty"`

	// If specified, GroupsPrefix is prepended to each group obtained from the claims specified by GroupsClaim. Note that
	// Kibana does not support a groups prefix, so this prefix is removed from Kubernetes Groups when translating log access
	// ClusterRoleBindings into Elastic.
	// +optional
	GroupsPrefix string `json:"groupsPrefix,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Authentication is the Schema for the authentications API
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=authentications,scope=Cluster
type Authentication struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AuthenticationSpec   `json:"spec,omitempty"`
	Status AuthenticationStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AuthenticationList contains a list of Authentication
type AuthenticationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Authentication `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Authentication{}, &AuthenticationList{})
}
