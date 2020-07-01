package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type AuthMethod string

const (
	AuthMethodOIDC AuthMethod = "OIDC"
)

// AuthorizationSpec defines the desired state of Authorization
type AuthorizationSpec struct {
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
	OIDC *AuthorizationOIDC `json:"oidc"`
}

// AuthorizationStatus defines the observed state of Authorization
type AuthorizationStatus struct {
	// State provides user-readable status.
	State string `json:"state,omitempty"`
}

// AuthorizationOIDC is the configuration needed to setup OIDC
type AuthorizationOIDC struct {
	// IssueURL is the URL to the OIDC provider
	// +required
	IssuerURL string `json:"issuerURL,omitempty"`

	// UsernameClaim specifies which claim to use from the OIDC provider as the username
	// +required
	UsernameClaim string `json:"usernameClaim,omitempty"`

	// UsernamePrefix is used to identify a ClusterRoleBinding User subject that has a prefix with the authenticated user
	// +optional
	UsernamePrefix string `json:"usernamePrefix,omitempty"`

	// GroupsClaim specifies which claim to use from the OIDC provider as the group
	// +optional
	GroupsClaim string `json:"groupsClaim,omitempty"`

	// UsernamePrefix is used to identify a ClusterRoleBinding Group subject that has a prefix with the authenticated user
	// +optional
	GroupsPrefix string `json:"groupsPrefix,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Authorization is the Schema for the authorizations API
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=authorizations,scope=Cluster
type Authorization struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AuthorizationSpec   `json:"spec,omitempty"`
	Status AuthorizationStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AuthorizationList contains a list of Authorization
type AuthorizationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Authorization `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Authorization{}, &AuthorizationList{})
}
