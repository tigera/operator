package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.
// NOTE: After modifying this file, run `make gen-files` to regenerate code.

// CoreSpec defines the desired state of Core
// +k8s:openapi-gen=true
type CoreSpec struct {
	// IPPools contains a list of IP pools to use for allocating pod IP addresses. For now,
	// a maximum of one IP pool is supported.
	// Default: 192.168.0.0/16.
	IPPools []IPPool `json:"ipPools,omitempty"`

	// CNINetDir configures the path on the host where CNI network configuration files will be installed.
	// Default: /etc/cni/net.d
	CNINetDir string `json:"cniNetDir,omitempty"`

	// CNIBinDir configures the path on the host where CNI binaries will be installed.
	// Default: /opt/cni/bin
	CNIBinDir string `json:"cniBinDir,omitempty"`
}

type IPPool struct {
	CIDR string `json:"cidr"`
}

// CoreStatus defines the observed state of Core
// +k8s:openapi-gen=true
type CoreStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book.kubebuilder.io/beyond_basics/generating_crd.html
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Core is the Schema for the cores API
// +k8s:openapi-gen=true
// +kubebuilder:subresource:status
type Core struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CoreSpec   `json:"spec,omitempty"`
	Status CoreStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CoreList contains a list of Core
type CoreList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Core `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Core{}, &CoreList{})
}
