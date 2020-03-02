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

// InstallationSpec defines configuration for a Calico or Calico Enterprise installation.
// +k8s:openapi-gen=true
type InstallationSpec struct {
	// Variant is the product to install - one of Calico or TigeraSecureEnterprise
	// Default: Calico
	// +optional
	// +kubebuilder:validation:Enum=Calico,TigeraSecureEnterprise
	Variant ProductVariant `json:"variant,omitempty"`

	// Registry is the default Docker registry used for component Docker images. If specified,
	// all images will be pulled from this registry. If not specified then the default registries
	// will be used.
	//
	// Image format:
	//    `<registry>/<imagePath>/<imageName>:<tag-name>`
	//
	// This option allows configuring the `<registry>` portion of the above format.
	// +optional
	Registry string `json:"registry,omitempty"`

	// ImagePath allows for the path part of an image to be specified. If specified
	// then the specified value will be used as the image path for each image. If not specified
	// or empty, the default for each image will be used.
	//
	// Image format:
	//    `<registry>/<imagePath>/<imageName>:<tag-name>`
	//
	// This option allows configuring the `<imagePath>` portion of the above format.
	// +optional
	ImagePath string `json:"imagePath,omitempty"`

	// ImagePullSecrets is an array of references to container registry pull secrets to use. These are
	// applied to all images to be pulled.
	// +optional
	ImagePullSecrets []v1.LocalObjectReference `json:"imagePullSecrets,omitempty"`

	// KubernetesProvider specifies a particular provider of the Kubernetes platform. This is often auto-detected.
	// If specified, this enables provider-specific configuration and must match the auto-detected value (if any).
	// +optional
	// +kubebuilder:validation:Enum=EKS,GKE,AKS,OpenShift,DockerEnterprise
	KubernetesProvider Provider `json:"kubernetesProvider,omitempty"`

	// CalicoNetwork specifies configuration options for Calico provided pod networking.
	// +optional
	CalicoNetwork *CalicoNetworkSpec `json:"calicoNetwork,omitempty"`
}

// Provider represents a particular provider or flavor of Kubernetes. Valid options
// are: EKS, GKE, AKS, OpenShift, DockerEnterprise.
type Provider string

var (
	ProviderNone      Provider = ""
	ProviderEKS       Provider = "EKS"
	ProviderGKE       Provider = "GKE"
	ProviderAKS       Provider = "AKS"
	ProviderOpenShift Provider = "OpenShift"
	ProviderDockerEE  Provider = "DockerEnterprise"
)

// ProductVariant represents the variant of the product. Valid options are: Calico, TigeraSecureEnterprise.
type ProductVariant string

var (
	Calico                 ProductVariant = "Calico"
	TigeraSecureEnterprise ProductVariant = "TigeraSecureEnterprise"
)

// CalicoNetwork specifies configuration options for Calico provided pod networking.
type CalicoNetworkSpec struct {
	// IPPools contains a list of IP pools to use for allocating pod IP addresses. At most one IP pool
	// may be specified. If omitted, a single pool will be configured when needed.
	// +optional
	IPPools []IPPool `json:"ipPools,omitempty"`

	// MTU specifies the maximum transmission unit to use for pods on the Calico network.
	// Default: 1410
	// +optional
	MTU *int32 `json:"mtu,omitempty"`
}

// EncapsulationType is the type of encapsulation to use on an IP pool. Valid
// options are: IPIP, VXLAN, IPIPCrossSubnet, VXLANCrossSubnet, None.
type EncapsulationType string

const (
	EncapsulationIPIPCrossSubnet  EncapsulationType = "IPIPCrossSubnet"
	EncapsulationIPIP             EncapsulationType = "IPIP"
	EncapsulationVXLAN            EncapsulationType = "VXLAN"
	EncapsulationVXLANCrossSubnet EncapsulationType = "VXLANCrossSubnet"
	EncapsulationNone             EncapsulationType = "None"
	EncapsulationDefault          EncapsulationType = EncapsulationIPIP
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

// NATOutgoingType describe the type of outgoing NAT to use.
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
	// CIDR contains the address range for the IP Pool in classless inter-domain routing format.
	CIDR string `json:"cidr"`

	// Encapsulation specifies the encapsulation type that will be used with
	// the IP Pool.
	// Default: IPIP
	// +optional
	// +kubebuilder:validation:Enum=IPIPCrossSubnet,IPIP,VXLAN,VXLANCrossSubnet,None
	Encapsulation EncapsulationType `json:"encapsulation,omitempty"`

	// NATOutgoing specifies if NAT will be enabled or disabled for outgoing traffic.
	// Default: Enabled
	// +optional
	// +kubebuilder:validation:Enum=Enabled,Disabled
	NATOutgoing NATOutgoingType `json:"natOutgoing,omitempty"`

	// NodeSelector specifies the node selector that will be set for the IP Pool.
	// Default: 'all()'
	// +optional
	NodeSelector string `json:"nodeSelector,omitempty"`

	// BlockSize specifies the CIDR prefex length to use when allocating per-node IP blocks from
	// the main IP pool CIDR.
	// Default: 26 (IPv4), 122 (IPv6)
	// +optional
	BlockSize *int32 `json:"blockSize,omitempty"`
}

// InstallationStatus defines the observed state of the Calico or Calico Enterprise installation.
// +k8s:openapi-gen=true
type InstallationStatus struct {
	// Variant is the most recently observed installed variant - one of Calico or TigeraSecureEnterprise
	// +kubebuilder:validation:Enum=Calico,TigeraSecureEnterprise
	Variant ProductVariant `json:"variant,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +genclient
// +genclient:nonNamespaced

// Installation configures an installation of Calico or Calico Enterprise. At most one instance
// of this resource is supported. It must be named "default". The Installation API installs core networking
// and network policy components, and provides general install-time configuration.
// +k8s:openapi-gen=true
// +kubebuilder:subresource:status
type Installation struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the desired state for the Calico or Calico Enterprise installation.
	Spec InstallationSpec `json:"spec,omitempty"`

	// Most recently observed state for the Calico or Calico Enterprise installation.
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
