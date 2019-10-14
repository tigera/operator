// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NOTE: json tags are required. Any new fields you add must have json tags for the fields to be serialized.
// NOTE: After modifying this file, run `make gen-files` to regenerate code.

// InstallationSpec defines the desired state of Installation.
// +k8s:openapi-gen=true
type InstallationSpec struct {
	// Variant is the product to install - one of Calico or TigeraSecureEnterprise
	// Default: Calico
	// +optional
	Variant ProductVariant `json:"variant,omitempty"`

	// Registry is the default Docker registry used for component Docker images.
	// Default: docker.io/
	// +optional
	Registry string `json:"registry,omitempty"`

	// ImagePullSecrets is an array of references to Docker registry pull secrets.
	// +optional
	ImagePullSecrets []v1.LocalObjectReference `json:"imagePullSecrets,omitempty"`

	// KubernetesProvider specifies which platform this cluster is running on. Operator will
	// do it's best to autodetect and set this. But can be overridden here.
	// +optional
	KubernetesProvider Provider `json:"kubernetesProvider,omitempty"`

	// CalicoNetwork specifies configuration options when using Calico provided pod networking.
	// +optional
	CalicoNetwork *CalicoNetworkSpec `json:"calicoNetwork,omitempty"`
}

type Provider string

var (
	ProviderNone      Provider = ""
	ProviderEKS       Provider = "EKS"
	ProviderGKE       Provider = "GKE"
	ProviderAKS       Provider = "AKS"
	ProviderOpenShift Provider = "OpenShift"
	ProviderDockerEE  Provider = "DockerEnterprise"
)

type ProductVariant string

var (
	Calico                 ProductVariant = "Calico"
	TigeraSecureEnterprise ProductVariant = "TigeraSecureEnterprise"
)

type CalicoNetworkSpec struct {
	// IPPools contains a list of IP pools to use for allocating pod IP addresses. For now,
	// a maximum of one IP pool is supported.
	// Default: 192.168.0.0/16
	// +optional
	IPPools []IPPool `json:"ipPools,omitempty"`

	// MTU specifies the maximum transmission unit to use for pods on the Calico network.
	// Default: 1410
	// +optional
	MTU *int32 `json:"mtu,omitempty"`
}

type EncapsulationType string

const (
	EncapsulationIPIPCrossSubnet  EncapsulationType = "IPIPCrossSubnet"
	EncapsulationIPIP             EncapsulationType = "IPIP"
	EncapsulationVXLAN            EncapsulationType = "VXLAN"
	EncapsulationVXLANCrossSubnet EncapsulationType = "VXLANCrossSubnet"
	EncapsulationNone             EncapsulationType = "None"
	EncapsulationDefault          EncapsulationType = "IPIP"
)

var EncapsulationTypes []EncapsulationType = []EncapsulationType{
	EncapsulationIPIPCrossSubnet,
	EncapsulationIPIP,
	EncapsulationVXLAN,
	EncapsulationVXLANCrossSubnet,
	EncapsulationNone,
}
var EncapsulationTypesString []string = []string{
	EncapsulationIPIPCrossSubnet.String(),
	EncapsulationIPIP.String(),
	EncapsulationVXLAN.String(),
	EncapsulationVXLANCrossSubnet.String(),
	EncapsulationNone.String(),
}

func (et EncapsulationType) String() string {
	return string(et)
}

type NATOutgoingType string

const (
	NATOutgoingEnabled  NATOutgoingType = "Enabled"
	NATOutgoingDisabled NATOutgoingType = "Disabled"
	NATOutgoingDefault  NATOutgoingType = "Enabled"
)

var NATOutgoingTypes []NATOutgoingType = []NATOutgoingType{
	NATOutgoingEnabled,
	NATOutgoingDisabled,
}
var NATOutgoingTypesString []string = []string{
	NATOutgoingEnabled.String(),
	NATOutgoingDisabled.String(),
}

func (nt NATOutgoingType) String() string {
	return string(nt)
}

const NodeSelectorDefault string = "all()"

type IPPool struct {
	// CIDR contains the CIDR of the IP Pool.
	CIDR string `json:"cidr"`
	// Encapsulation specifies the encapsulation type that will be used with
	// the IP Pool. IPIP is the default.
	// +optional
	// +kubebuilder:validation:Enum=IPIPCrossSubnet,IPIP,VXLAN,None
	Encapsulation EncapsulationType `json:"encapsulation,omitempty"`
	// NATOutgoing specifies if NAT will be enabled or disabled for outgoing
	// traffic. Enabled is the default.
	// +optional
	// +kubebuilder:validation:Enum=Enabled,Disabled
	NATOutgoing NATOutgoingType `json:"natOutgoing,omitempty"`
	// NodeSelector specifies the node selector that will be set for the
	// IP Pool. Default is 'all()'.
	// +optional
	NodeSelector string `json:"nodeSelector,omitempty"`
}

// InstallationStatus defines the observed state of Installation
// +k8s:openapi-gen=true
type InstallationStatus struct {
	// Variant is the installed product - one of Calico or TigeraSecureEnterprise
	Variant ProductVariant `json:"variant,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Installation is the Schema for the cores API
// +k8s:openapi-gen=true
// +kubebuilder:subresource:status
type Installation struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   InstallationSpec   `json:"spec,omitempty"`
	Status InstallationStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// InstallationList contains a list of Installation
type InstallationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Installation `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Installation{}, &InstallationList{})
}
