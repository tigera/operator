// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.

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
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// InstallationSpec defines configuration for a Calico or Calico Enterprise installation.
// +k8s:openapi-gen=true
type InstallationSpec struct {
	// Variant is the product to install - one of Calico or TigeraSecureEnterprise
	// Default: Calico
	// +optional
	// +kubebuilder:validation:Enum=Calico;TigeraSecureEnterprise
	Variant ProductVariant `json:"variant,omitempty"`

	// Registry is the default Docker registry used for component Docker images. If specified,
	// all images will be pulled from this registry. If not specified then the default registries
	// will be used.
	//
	// Image format:
	//    `<registry>/<imagePath>/<imageName>:<image-tag>`
	//
	// This option allows configuring the `<registry>` portion of the above format.
	// +optional
	Registry string `json:"registry,omitempty"`

	// ImagePath allows for the path part of an image to be specified. If specified
	// then the specified value will be used as the image path for each image. If not specified
	// or empty, the default for each image will be used.
	//
	// Image format:
	//    `<registry>/<imagePath>/<imageName>:<image-tag>`
	//
	// This option allows configuring the `<imagePath>` portion of the above format.
	// +optional
	ImagePath string `json:"imagePath,omitempty"`

	// ImagePullSecrets is an array of references to container registry pull secrets to use. These are
	// applied to all images to be pulled.
	// +optional
	ImagePullSecrets []v1.LocalObjectReference `json:"imagePullSecrets,omitempty"`

	// KubernetesProvider specifies a particular provider of the Kubernetes platform and enables provider-specific configuration.
	// If the specified value is empty, the Operator will attempt to automatically determine the current provider.
	// If the specified value is not empty, the Operator will still attempt auto-detection, but
	// will additionally compare the auto-detected value to the specified value to confirm they match.
	// +optional
	// +kubebuilder:validation:Enum="";EKS;GKE;AKS;OpenShift;DockerEnterprise;
	KubernetesProvider Provider `json:"kubernetesProvider,omitempty"`

	// CNI specifies the CNI that will be used by this installation.
	// +optional
	CNI *CNISpec `json:"cni,omitempty"`

	// CalicoNetwork specifies networking configuration options for Calico.
	// +optional
	CalicoNetwork *CalicoNetworkSpec `json:"calicoNetwork,omitempty"`

	// ControlPlaneNodeSelector is used to select control plane nodes on which to run specific Calico
	// components. This currently only applies to kube-controllers and the apiserver.
	// +optional
	ControlPlaneNodeSelector map[string]string `json:"controlPlaneNodeSelector,omitempty"`

	// NodeMetricsPort specifies which port calico/node serves prometheus metrics on. By default, metrics are not enabled.
	// If specified, this overrides any FelixConfiguration resources which may exist. If omitted, then
	// prometheus metrics may still be configured through FelixConfiguration.
	// +optional
	NodeMetricsPort *int32 `json:"nodeMetricsPort,omitempty"`

	// FlexVolumePath optionally specifies a custom path for FlexVolume. If not specified, FlexVolume will be
	// enabled by default. If set to 'None', FlexVolume will be disabled. The default is based on the
	// kubernetesProvider.
	// +optional
	FlexVolumePath string `json:"flexVolumePath,omitempty"`

	// NodeUpdateStrategy can be used to customize the desired update strategy, such as the MaxUnavailable
	// field.
	// +optional
	NodeUpdateStrategy appsv1.DaemonSetUpdateStrategy `json:"nodeUpdateStrategy,omitempty"`

	// ComponentResources can be used to customize the resource requirements for each component.
	// +optional
	ComponentResources []*ComponentResource `json:"componentResources,omitempty"`
}

// ComponentName CRD enum
type ComponentName string

const (
	ComponentNameNode            ComponentName = "Node"
	ComponentNameTypha           ComponentName = "Typha"
	ComponentNameKubeControllers ComponentName = "KubeControllers"
)

// The ComponentResource struct associates a ResourceRequirements with a component by name
// +k8s:openapi-gen=true
type ComponentResource struct {
	// ComponentName is an enum which identifies the component
	// +kubebuilder:validation:Enum=Node;Typha;KubeControllers
	ComponentName ComponentName `json:"componentName"`
	// ResourceRequirements allows customization of limits and requests for compute resources such as cpu and memory.
	ResourceRequirements *v1.ResourceRequirements `json:"resourceRequirements"`
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

// ContainerIPForwardingType specifies whether the CNI config for container ip forwarding is enabled.
type ContainerIPForwardingType string

const (
	ContainerIPForwardingEnabled  ContainerIPForwardingType = "Enabled"
	ContainerIPForwardingDisabled ContainerIPForwardingType = "Disabled"
)

// HostPortsType specifies if the HostPorts plugin enabled status.
type HostPortsType string

const (
	HostPortsEnabled  HostPortsType = "Enabled"
	HostPortsDisabled HostPortsType = "Disabled"
)

var HostPortsTypes []HostPortsType = []HostPortsType{
	HostPortsEnabled,
	HostPortsDisabled,
}
var HostPortsTypesString []string = []string{
	HostPortsEnabled.String(),
	HostPortsDisabled.String(),
}

type MultiInterfaceMode string

func (m MultiInterfaceMode) Value() string {
	return strings.ToLower(string(m))
}

const (
	MultiInterfaceModeNone   MultiInterfaceMode = "None"
	MultiInterfaceModeMultus MultiInterfaceMode = "Multus"
)

func (nt HostPortsType) String() string {
	return string(nt)
}

type BGPOption string

const (
	BGPEnabled  BGPOption = "Enabled"
	BGPDisabled BGPOption = "Disabled"
)

// CalicoNetworkSpec specifies configuration options for Calico provided pod networking.
type CalicoNetworkSpec struct {
	// BGP configures whether or not to enable Calico's BGP capabilities.
	// +optional
	// +kubebuilder:validation:Enum=Enabled;Disabled
	BGP *BGPOption `json:"bgp,omitempty"`

	// IPPools contains a list of IP pools to create if none exist. At most one IP pool of each
	// address family may be specified. If omitted, a single pool will be configured if needed.
	// +optional
	IPPools []IPPool `json:"ipPools,omitempty"`

	// MTU specifies the maximum transmission unit to use on the pod network.
	// Default: 1410
	// +optional
	MTU *int32 `json:"mtu,omitempty"`

	// NodeAddressAutodetectionV4 specifies an approach to automatically detect node IPv4 addresses. If not specified,
	// will use default auto-detection settings to acquire an IPv4 address for each node.
	// +optional
	NodeAddressAutodetectionV4 *NodeAddressAutodetection `json:"nodeAddressAutodetectionV4,omitempty"`

	// NodeAddressAutodetectionV6 specifies an approach to automatically detect node IPv6 addresses. If not specified,
	// IPv6 addresses will not be auto-detected.
	// +optional
	NodeAddressAutodetectionV6 *NodeAddressAutodetection `json:"nodeAddressAutodetectionV6,omitempty"`

	// HostPorts configures whether or not Calico will support Kubernetes HostPorts. Valid only when using the Calico CNI plugin.
	// Default: Enabled
	// +optional
	// +kubebuilder:validation:Enum=Enabled;Disabled
	HostPorts *HostPortsType `json:"hostPorts,omitempty"`

	// MultiInterfaceMode configures what will configure multiple interface per pod. Only valid for Calico Enterprise installations
	// using the Calico CNI plugin.
	// Default: None
	// +optional
	// +kubebuilder:validation:Enum=None;Multus
	MultiInterfaceMode *MultiInterfaceMode `json:"multiInterfaceMode,omitempty"`

	// ContainerIPForwarding configures whether ip forwarding will be enabled for containers in the CNI configuration.
	// Default: Disabled
	// +optional
	// +kubebuilder:validation:Enum=Enabled;Disabled
	ContainerIPForwarding *ContainerIPForwardingType `json:"containerIPForwarding,omitempty"`
}

// NodeAddressAutodetection provides configuration options for auto-detecting node addresses. At most one option
// can be used. If no detection option is specified, then IP auto detection will be disabled for this address family and IPs
// must be specified directly on the Node resource.
type NodeAddressAutodetection struct {
	// FirstFound uses default interface matching parameters to select an interface, performing best-effort
	// filtering based on well-known interface names.
	// +optional
	FirstFound *bool `json:"firstFound,omitempty"`

	// Interface enables IP auto-detection based on interfaces that match the given regex.
	// +optional
	Interface string `json:"interface,omitempty"`

	// SkipInterface enables IP auto-detection based on interfaces that do not match
	// the given regex.
	// +optional
	SkipInterface string `json:"skipInterface,omitempty"`

	// CanReach enables IP auto-detection based on which source address on the node is used to reach the
	// specified IP or domain.
	// +optional
	CanReach string `json:"canReach,omitempty"`
}

// EncapsulationType is the type of encapsulation to use on an IP pool. Valid
// options are: IPIP, VXLAN, IPIPCrossSubnet, VXLANCrossSubnet, None.
type EncapsulationType string

func (et EncapsulationType) String() string {
	return string(et)
}

const (
	EncapsulationIPIPCrossSubnet  EncapsulationType = "IPIPCrossSubnet"
	EncapsulationIPIP             EncapsulationType = "IPIP"
	EncapsulationVXLAN            EncapsulationType = "VXLAN"
	EncapsulationVXLANCrossSubnet EncapsulationType = "VXLANCrossSubnet"
	EncapsulationNone             EncapsulationType = "None"
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

// NATOutgoingType describe the type of outgoing NAT to use.
type NATOutgoingType string

const (
	NATOutgoingEnabled  NATOutgoingType = "Enabled"
	NATOutgoingDisabled NATOutgoingType = "Disabled"
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
	// +kubebuilder:validation:Enum=IPIPCrossSubnet;IPIP;VXLAN;VXLANCrossSubnet;None
	Encapsulation EncapsulationType `json:"encapsulation,omitempty"`

	// NATOutgoing specifies if NAT will be enabled or disabled for outgoing traffic.
	// Default: Enabled
	// +optional
	// +kubebuilder:validation:Enum=Enabled;Disabled
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

// CNIPluginType describe the type of CNI plugin used.
type CNIPluginType string

const (
	PluginCalico    CNIPluginType = "Calico"
	PluginGKE       CNIPluginType = "GKE"
	PluginAmazonVPC CNIPluginType = "AmazonVPC"
	PluginAzureVNET CNIPluginType = "AzureVNET"
)

var CNIPluginTypes []CNIPluginType = []CNIPluginType{
	PluginCalico,
	PluginGKE,
	PluginAmazonVPC,
	PluginAzureVNET,
}
var CNIPluginTypesString []string = []string{
	PluginCalico.String(),
	PluginGKE.String(),
	PluginAmazonVPC.String(),
	PluginAzureVNET.String(),
}

func (cp CNIPluginType) String() string {
	return string(cp)
}

type IPAMPluginType string

const (
	IPAMPluginCalico    IPAMPluginType = "Calico"
	IPAMPluginHostLocal IPAMPluginType = "HostLocal"
	IPAMPluginAmazonVPC IPAMPluginType = "AmazonVPC"
	IPAMPluginAzureVNET IPAMPluginType = "AzureVNET"
)

var IPAMPluginTypes []IPAMPluginType = []IPAMPluginType{
	IPAMPluginCalico,
	IPAMPluginHostLocal,
	IPAMPluginAmazonVPC,
	IPAMPluginAzureVNET,
}

var IPAMPluginTypesString []string = []string{
	IPAMPluginCalico.String(),
	IPAMPluginHostLocal.String(),
	IPAMPluginAmazonVPC.String(),
	IPAMPluginAzureVNET.String(),
}

func (cp IPAMPluginType) String() string {
	return string(cp)
}

// IPAMSpec contains configuration for pod IP address management.
type IPAMSpec struct {
	// Specifies the IPAM plugin that will be used in the Calico or Calico Enterprise installation.
	// * For CNI Plugin Calico, this field defaults to Calico.
	// * For CNI Plugin GKE, this field defaults to HostLocal.
	// * For CNI Plugin AzureVNET, this field defaults to AzureVNET.
	// * For CNI Plugin AmazonVPC, this field defaults to AmazonVPC.
	//
	// The IPAM plugin is installed and configured only if the CNI plugin is set to Calico,
	// for all other values of the CNI plugin the plugin binaries and CNI config is a dependency
	// that is expected to be installed separately.
	//
	// Default: Calico
	// +kubebuilder:validation:Enum=Calico;HostLocal;AmazonVPC;AzureVNET
	Type IPAMPluginType `json:"type"`
}

// CNISpec contains configuration for the CNI plugin.
type CNISpec struct {
	// Specifies the CNI plugin that will be used in the Calico or Calico Enterprise installation.
	// * For KubernetesProvider GKE, this field defaults to GKE.
	// * For KubernetesProvider AKS, this field defaults to AzureVNET.
	// * For KubernetesProvider EKS, this field defaults to AmazonVPC.
	// * For all other KubernetesProviders this field defaults to Calico.
	//
	// For the value Calico, the CNI plugin binaries and CNI config will be installed as part of deployment,
	// for all other values the CNI plugin binaries and CNI config is a dependency that is expected
	// to be installed separately.
	//
	// Default: Calico
	// +kubebuilder:validation:Enum=Calico;GKE;AmazonVPC;AzureVNET
	Type CNIPluginType `json:"type"`

	// IPAM specifies the pod IP address management that will be used in the Calico or
	// Calico Enterprise installation.
	// +optional
	IPAM *IPAMSpec `json:"ipam"`
}

// InstallationStatus defines the observed state of the Calico or Calico Enterprise installation.
// +k8s:openapi-gen=true
type InstallationStatus struct {
	// Variant is the most recently observed installed variant - one of Calico or TigeraSecureEnterprise
	// +kubebuilder:validation:Enum=Calico;TigeraSecureEnterprise
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
// +kubebuilder:resource:scope=Cluster
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
