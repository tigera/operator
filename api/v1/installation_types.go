// Copyright (c) 2022 Tigera, Inc. All rights reserved.
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
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// InstallationSpec defines configuration for a Calico or Calico Enterprise installation.
type InstallationSpec struct {
	// Variant is the product to install - one of Calico or TigeraSecureEnterprise
	// Default: Calico
	// +optional
	// +kubebuilder:validation:Enum=Calico;TigeraSecureEnterprise
	Variant ProductVariant `json:"variant,omitempty"`

	// Registry is the default Docker registry used for component Docker images.
	// If specified then the given value must end with a slash character (`/`) and all images will be pulled from this registry.
	// If not specified then the default registries will be used. A special case value, UseDefault, is
	// supported to explicitly specify the default registries will be used.
	//
	// Image format:
	//    `<registry><imagePath>/<imagePrefix><imageName>:<image-tag>`
	//
	// This option allows configuring the `<registry>` portion of the above format.
	// +optional
	Registry string `json:"registry,omitempty"`

	// ImagePath allows for the path part of an image to be specified. If specified
	// then the specified value will be used as the image path for each image. If not specified
	// or empty, the default for each image will be used.
	// A special case value, UseDefault, is supported to explicitly specify the default
	// image path will be used for each image.
	//
	// Image format:
	//    `<registry><imagePath>/<imagePrefix><imageName>:<image-tag>`
	//
	// This option allows configuring the `<imagePath>` portion of the above format.
	// +optional
	ImagePath string `json:"imagePath,omitempty"`

	// ImagePrefix allows for the prefix part of an image to be specified. If specified
	// then the given value will be used as a prefix on each image. If not specified
	// or empty, no prefix will be used.
	// A special case value, UseDefault, is supported to explicitly specify the default
	// image prefix will be used for each image.
	//
	// Image format:
	//    `<registry><imagePath>/<imagePrefix><imageName>:<image-tag>`
	//
	// This option allows configuring the `<imagePrefix>` portion of the above format.
	// +optional
	ImagePrefix string `json:"imagePrefix,omitempty"`

	// ImagePullSecrets is an array of references to container registry pull secrets to use. These are
	// applied to all images to be pulled.
	// +optional
	ImagePullSecrets []v1.LocalObjectReference `json:"imagePullSecrets,omitempty"`

	// KubernetesProvider specifies a particular provider of the Kubernetes platform and enables provider-specific configuration.
	// If the specified value is empty, the Operator will attempt to automatically determine the current provider.
	// If the specified value is not empty, the Operator will still attempt auto-detection, but
	// will additionally compare the auto-detected value to the specified value to confirm they match.
	// +optional
	// +kubebuilder:validation:Enum="";EKS;GKE;AKS;OpenShift;DockerEnterprise;RKE2;
	KubernetesProvider Provider `json:"kubernetesProvider,omitempty"`

	// CNI specifies the CNI that will be used by this installation.
	// +optional
	CNI *CNISpec `json:"cni,omitempty"`

	// CalicoNetwork specifies networking configuration options for Calico.
	// +optional
	CalicoNetwork *CalicoNetworkSpec `json:"calicoNetwork,omitempty"`

	// TyphaAffinity allows configuration of node affinity characteristics for Typha pods.
	// +optional
	TyphaAffinity *TyphaAffinity `json:"typhaAffinity,omitempty"`

	// ControlPlaneNodeSelector is used to select control plane nodes on which to run Calico
	// components. This is globally applied to all resources created by the operator excluding daemonsets.
	// +optional
	ControlPlaneNodeSelector map[string]string `json:"controlPlaneNodeSelector,omitempty"`

	// ControlPlaneTolerations specify tolerations which are then globally applied to all resources
	// created by the operator.
	// +optional
	ControlPlaneTolerations []v1.Toleration `json:"controlPlaneTolerations,omitempty"`

	// ControlPlaneReplicas defines how many replicas of the control plane core components will be deployed.
	// This field applies to all control plane components that support High Availability. Defaults to 2.
	// +optional
	ControlPlaneReplicas *int32 `json:"controlPlaneReplicas,omitempty"`

	// NodeMetricsPort specifies which port calico/node serves prometheus metrics on. By default, metrics are not enabled.
	// If specified, this overrides any FelixConfiguration resources which may exist. If omitted, then
	// prometheus metrics may still be configured through FelixConfiguration.
	// +optional
	NodeMetricsPort *int32 `json:"nodeMetricsPort,omitempty"`

	// TyphaMetricsPort specifies which port calico/typha serves prometheus metrics on. By default, metrics are not enabled.
	// +optional
	TyphaMetricsPort *int32 `json:"typhaMetricsPort,omitempty"`

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
	// Node, Typha, and KubeControllers are supported for installations.
	// +optional
	ComponentResources []ComponentResource `json:"componentResources,omitempty"`

	// CertificateManagement configures pods to submit a CertificateSigningRequest to the certificates.k8s.io/v1beta1 API in order
	// to obtain TLS certificates. This feature requires that you bring your own CSR signing and approval process, otherwise
	// pods will be stuck during initialization.
	// +optional
	CertificateManagement *CertificateManagement `json:"certificateManagement,omitempty"`

	// NonPrivileged configures Calico to be run in non-privileged containers as non-root users where possible.
	// +optional
	NonPrivileged *NonPrivilegedType `json:"nonPrivileged,omitempty"`
}

// TyphaAffinity allows configuration of node affinity characteristics for Typha pods.
type TyphaAffinity struct {
	// NodeAffinity describes node affinity scheduling rules for typha.
	// +optional
	NodeAffinity *NodeAffinity `json:"nodeAffinity,omitempty"`
}

// NodeAffinity is similar to *v1.NodeAffinity, but allows us to limit available schedulers.
type NodeAffinity struct {
	// The scheduler will prefer to schedule pods to nodes that satisfy
	// the affinity expressions specified by this field, but it may choose
	// a node that violates one or more of the expressions.
	// +optional
	PreferredDuringSchedulingIgnoredDuringExecution []v1.PreferredSchedulingTerm `json:"preferredDuringSchedulingIgnoredDuringExecution,omitempty"`

	// WARNING: Please note that if the affinity requirements specified by this field are not met at
	// scheduling time, the pod will NOT be scheduled onto the node.
	// There is no fallback to another affinity rules with this setting.
	// This may cause networking disruption or even catastrophic failure!
	// PreferredDuringSchedulingIgnoredDuringExecution should be used for affinity
	// unless there is a specific well understood reason to use RequiredDuringSchedulingIgnoredDuringExecution and
	// you can guarantee that the RequiredDuringSchedulingIgnoredDuringExecution will always have sufficient nodes to satisfy the requirement.
	// NOTE: RequiredDuringSchedulingIgnoredDuringExecution is set by default for AKS nodes,
	// to avoid scheduling Typhas on virtual-nodes.
	// If the affinity requirements specified by this field cease to be met
	// at some point during pod execution (e.g. due to an update), the system
	// may or may not try to eventually evict the pod from its node.
	// +optional
	RequiredDuringSchedulingIgnoredDuringExecution *v1.NodeSelector `json:"requiredDuringSchedulingIgnoredDuringExecution,omitempty"`
}

// ComponentName represents a single component.
//
// One of: Node, Typha, KubeControllers
type ComponentName string

const (
	ComponentNameNode            ComponentName = "Node"
	ComponentNameTypha           ComponentName = "Typha"
	ComponentNameKubeControllers ComponentName = "KubeControllers"
)

// The ComponentResource struct associates a ResourceRequirements with a component by name
type ComponentResource struct {
	// ComponentName is an enum which identifies the component
	// +kubebuilder:validation:Enum=Node;Typha;KubeControllers
	ComponentName ComponentName `json:"componentName"`
	// ResourceRequirements allows customization of limits and requests for compute resources such as cpu and memory.
	ResourceRequirements *v1.ResourceRequirements `json:"resourceRequirements"`
}

// Provider represents a particular provider or flavor of Kubernetes. Valid options
// are: EKS, GKE, AKS, RKE2, OpenShift, DockerEnterprise.
type Provider string

var (
	ProviderNone      Provider = ""
	ProviderEKS       Provider = "EKS"
	ProviderGKE       Provider = "GKE"
	ProviderAKS       Provider = "AKS"
	ProviderRKE2      Provider = "RKE2"
	ProviderOpenShift Provider = "OpenShift"
	ProviderDockerEE  Provider = "DockerEnterprise"
)

// ProductVariant represents the variant of the product.
//
// One of: Calico, TigeraSecureEnterprise
type ProductVariant string

var (
	Calico                 ProductVariant = "Calico"
	TigeraSecureEnterprise ProductVariant = "TigeraSecureEnterprise"
)

// NonPrivilegedType specifies whether Calico runs as permissioned or not
//
// One of: Enabled, Disabled
type NonPrivilegedType string

const (
	NonPrivilegedEnabled  NonPrivilegedType = "Enabled"
	NonPrivilegedDisabled NonPrivilegedType = "Disabled"
)

// ContainerIPForwardingType specifies whether the CNI config for container ip forwarding is enabled.
type ContainerIPForwardingType string

const (
	ContainerIPForwardingEnabled  ContainerIPForwardingType = "Enabled"
	ContainerIPForwardingDisabled ContainerIPForwardingType = "Disabled"
)

// HostPortsType specifies host port support.
//
// One of: Enabled, Disabled
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

// MultiInterfaceMode describes the method of providing multiple pod interfaces.
//
// One of: None, Multus
type MultiInterfaceMode string

func (m MultiInterfaceMode) Value() string {
	return strings.ToLower(string(m))
}

const (
	MultiInterfaceModeNone   MultiInterfaceMode = "None"
	MultiInterfaceModeMultus MultiInterfaceMode = "Multus"
)

func HostPortsTypePtr(h HostPortsType) *HostPortsType {
	return &h
}

func (nt HostPortsType) String() string {
	return string(nt)
}

// BGPOption describes the mode of BGP to use.
//
// One of: Enabled, Disabled
type BGPOption string

func BGPOptionPtr(b BGPOption) *BGPOption {
	return &b
}

const (
	BGPEnabled  BGPOption = "Enabled"
	BGPDisabled BGPOption = "Disabled"
)

// LinuxDataplaneOption controls which dataplane is to be used on Linux nodes.
//
// One of: Iptables, BPF
type LinuxDataplaneOption string

const (
	LinuxDataplaneIptables LinuxDataplaneOption = "Iptables"
	LinuxDataplaneBPF      LinuxDataplaneOption = "BPF"
	LinuxDataplaneVPP      LinuxDataplaneOption = "VPP"
)

// CalicoNetworkSpec specifies configuration options for Calico provided pod networking.
type CalicoNetworkSpec struct {
	// LinuxDataplane is used to select the dataplane used for Linux nodes. In particular, it
	// causes the operator to add required mounts and environment variables for the particular dataplane.
	// If not specified, iptables mode is used.
	// Default: Iptables
	// +optional
	// +kubebuilder:validation:Enum=Iptables;BPF;VPP
	LinuxDataplane *LinuxDataplaneOption `json:"linuxDataplane,omitempty"`

	// BGP configures whether or not to enable Calico's BGP capabilities.
	// +optional
	// +kubebuilder:validation:Enum=Enabled;Disabled
	BGP *BGPOption `json:"bgp,omitempty"`

	// IPPools contains a list of IP pools to create if none exist. At most one IP pool of each
	// address family may be specified. If omitted, a single pool will be configured if needed.
	// +optional
	IPPools []IPPool `json:"ipPools,omitempty"`

	// MTU specifies the maximum transmission unit to use on the pod network.
	// If not specified, Calico will perform MTU auto-detection based on the cluster network.
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

	// Kubernetes configures Calico to detect node addresses based on the Kubernetes API.
	// +optional
	// +kubebuilder:validation:Enum=NodeInternalIP
	Kubernetes *KubernetesAutodetectionMethod `json:"kubernetes,omitempty"`

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

	// CIDRS enables IP auto-detection based on which addresses on the nodes are within
	// one of the provided CIDRs.
	CIDRS []string `json:"cidrs,omitempty"`
}

// KubernetesAutodetectionMethod is a method of detecting an IP address based on the Kubernetes API.
//
// One of: NodeInternalIP
type KubernetesAutodetectionMethod string

const (
	// NodeInternalIP detects a node IP using the first status.Addresses entry of the relevant IP family
	// with type NodeInternalIP on the Kubernetes nodes API.
	NodeInternalIP KubernetesAutodetectionMethod = "NodeInternalIP"
)

// EncapsulationType is the type of encapsulation to use on an IP pool.
//
// One of: IPIP, VXLAN, IPIPCrossSubnet, VXLANCrossSubnet, None
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
//
// One of: Enabled, Disabled
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

// CNIPluginType describes the type of CNI plugin used.
//
// One of: Calico, GKE, AmazonVPC, AzureVNET
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
	// * If aws-node daemonset exists in kube-system when the Installation resource is created, this field defaults to AmazonVPC.
	// * For all other cases this field defaults to Calico.
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
type InstallationStatus struct {
	// Variant is the most recently observed installed variant - one of Calico or TigeraSecureEnterprise
	// +kubebuilder:validation:Enum=Calico;TigeraSecureEnterprise
	Variant ProductVariant `json:"variant,omitempty"`

	// MTU is the most recently observed value for pod network MTU. This may be an explicitly
	// configured value, or based on Calico's native auto-detetion.
	MTU int32 `json:"mtu,omitempty"`

	// ImageSet is the name of the ImageSet being used, if there is an ImageSet
	// that is being used. If an ImageSet is not being used then this will not be set.
	// +optional
	ImageSet string `json:"imageSet,omitempty"`

	// Computed is the final installation including overlaid resources.
	// +optional
	Computed *InstallationSpec `json:"computed,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster

// Installation configures an installation of Calico or Calico Enterprise. At most one instance
// of this resource is supported. It must be named "default". The Installation API installs core networking
// and network policy components, and provides general install-time configuration.
type Installation struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the desired state for the Calico or Calico Enterprise installation.
	Spec InstallationSpec `json:"spec,omitempty"`
	// Most recently observed state for the Calico or Calico Enterprise installation.
	Status InstallationStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// InstallationList contains a list of Installation
type InstallationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Installation `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Installation{}, &InstallationList{})
}

// CertificateManagement configures pods to submit a CertificateSigningRequest to the certificates.k8s.io/v1beta1 API in order
// to obtain TLS certificates. This feature requires that you bring your own CSR signing and approval process, otherwise
// pods will be stuck during initialization.
type CertificateManagement struct {
	// Certificate of the authority that signs the CertificateSigningRequests in PEM format.
	CACert []byte `json:"caCert"`

	// When a CSR is issued to the certificates.k8s.io API, the signerName is added to the request in order to accommodate for clusters
	// with multiple signers.
	// Must be formatted as: `<my-domain>/<my-signername>`.
	SignerName string `json:"signerName"`

	// Specify the algorithm used by pods to generate a key pair that is associated with the X.509 certificate request.
	// Default: RSAWithSize2048
	// +kubebuilder:validation:Enum="";RSAWithSize2048;RSAWithSize4096;RSAWithSize8192;ECDSAWithCurve256;ECDSAWithCurve384;ECDSAWithCurve521;
	// +optional
	KeyAlgorithm string `json:"keyAlgorithm,omitempty"`

	// Specify the algorithm used for the signature of the X.509 certificate request.
	// Default: SHA256WithRSA
	// +kubebuilder:validation:Enum="";SHA256WithRSA;SHA384WithRSA;SHA512WithRSA;ECDSAWithSHA256;ECDSAWithSHA384;ECDSAWithSHA512;
	// +optional
	SignatureAlgorithm string `json:"signatureAlgorithm,omitempty"`
}
