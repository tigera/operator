package v1alpha1

import (
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.
// NOTE: After modifying this file, run `make gen-files` to regenerate code.

// KubeProxySpec defines the state of a kube-proxy installation.
// +k8s:openapi-gen=true
type KubeProxySpec struct {
	// Required specifies whether kube-Proxy needs to be installed or if it's already provided.
	// Default: false
	// +optional
	Required bool `json:"required,omitempty"`

	// APIServer is a mandatory string containing a server:port URL.
	// Default: ""
	// +optional
	APIServer string `json:"apiServer,omitempty"`

	// A custom kube-proxy image.
	// Default: "k8s.gcr.io/kube-proxy:v1.13.6"
	// +optional
	Image string `json:"image,omitempty"`
}

// CoreSpec defines the desired state of Core.
// +k8s:openapi-gen=true
type CoreSpec struct {
	// Version of the product to install.
	// Default: latest
	// +optional
	Version string `json:"version,omitempty"`

	// MinimumOperatorVersion is the minimum required version of Operator for the specified Version.
	// +optional
	MinimumOperatorVersion string `json:"minimumOperatorVersion,omitempty"`

	// Datastore is datastore configuration.
	// +optional
	Datastore DatastoreConfig `json:"datastore,omitempty"`

	// Variant is the product to install - one of Calico or TigeraSecureEnterprise
	// Default: Calico
	// +optional
	Variant ProductVariant `json:"variant,omitempty"`

	// Registry to use for container images.
	// Default: docker.io
	// +optional
	Registry string `json:"registry,omitempty"`

	// ImagePullSecretsRef is an array of references to registry pull secrets.
	// +optional
	ImagePullSecretsRef []v1.LocalObjectReference `json:"imagePullSecrets,omitempty"`

	// IPPools contains a list of IP pools to use for allocating pod IP addresses. For now,
	// a maximum of one IP pool is supported.
	// Default: 192.168.0.0/16.
	// +optional
	IPPools []IPPool `json:"ipPools,omitempty"`

	// CNINetDir configures the path on the host where CNI network configuration files will be installed.
	// Default: /etc/cni/net.d
	// +optional
	CNINetDir string `json:"cniNetDir,omitempty"`

	// CNIBinDir configures the path on the host where CNI binaries will be installed.
	// Default: /opt/cni/bin
	// +optional
	CNIBinDir string `json:"cniBinDir,omitempty"`

	// Components specifies the configuration of components.
	// +optional
	Components ComponentsSpec `json:"components,omitempty"`
}

// ComponentsSpec defines the desired state of components.
// +k8s:openapi-gen=true
type ComponentsSpec struct {
	// Node is optional configuration for the node component.
	// +optional
	Node NodeSpec `json:"node,omitempty"`

	// CNI is optional configuration for the CNI component.
	// +optional
	CNI CNISpec `json:"cni,omitempty"`

	// KubeControllers is optional configuration for the kube-controllers component.
	// +optional
	KubeControllers KubeControllersSpec `json:"kubeControllers,omitempty"`

	// KubeProxy is optional configuration for kube-proxy.
	// +optional
	KubeProxy KubeProxySpec `json:"kubeProxy,omitempty"`
}

// KubeControllersSpec defines optional configuration for the kube-controllers component.
// +k8s:openapi-gen=true
type KubeControllersSpec struct {
	// ImageOverride configures a different Docker image for the kube-controllers deployment.
	// E.g "acme/calico-kube-controllers".
	// +optional
	ImageOverride string `json:"imageOverride,omitempty"`

	// ExtraEnv adds extra environment variables to the kube-controllers container.
	// +optional
	ExtraEnv []v1.EnvVar `json:"extraEnv,omitempty"`

	// ExtraVolumes configures custom volumes to be used by the kube-controllers container.
	// +optional
	ExtraVolumes []v1.Volume `json:"extraVolumes,omitempty"`

	// ExtraVolumeMounts configures custom volume mounts to be used by the kube-controllers container.
	// +optional
	ExtraVolumeMounts []v1.VolumeMount `json:"extraVolumeMounts,omitempty"`

	// Tolerations configures custom tolerations on the kube-controllers deployment.
	// +optional
	Tolerations []v1.Toleration `json:"tolerations,omitempty"`

	// Resources configures custom resource requirements on the kube-controllers container.
	// +optional
	Resources v1.ResourceRequirements `json:"resources,omitempty"`
}

// NodeSpec defines optional configuration for the node component.
// +k8s:openapi-gen=true
type NodeSpec struct {
	// ImageOverride configures a different Docker image for the node daemonset. E.g "tigera/cnx-node".
	// +optional
	ImageOverride string `json:"imageOverride,omitempty"`

	// MaxUnavailable configures the maximum number of pods that can be unavailable during a rolling update of the
	// node daemonset.
	// Default: 1
	// +optional
	MaxUnavailable *intstr.IntOrString `json:"maxUnavailable,omitempty"`

	// ExtraEnv adds extra environment variables to the node container.
	// +optional
	ExtraEnv []v1.EnvVar `json:"extraEnv,omitempty"`

	// ExtraVolumes configures custom volumes to be used by the node daemonset.
	// +optional
	ExtraVolumes []v1.Volume `json:"extraVolumes,omitempty"`

	// ExtraVolumeMounts configures custom volume mounts to be used by the node container.
	// +optional
	ExtraVolumeMounts []v1.VolumeMount `json:"extraVolumeMounts,omitempty"`

	// Tolerations configures custom tolerations on the node daemonset.
	// +optional
	Tolerations []v1.Toleration `json:"tolerations,omitempty"`

	// Resources configures custom resource requirements on the node container.
	// +optional
	Resources v1.ResourceRequirements `json:"resources,omitempty"`
}

// CNISpec defines optional configuration for the CNI component.
// +k8s:openapi-gen=true
type CNISpec struct {
	// ImageOverride configures a different Docker image for the CNI image. E.g "acme/calico-cni".
	// +optional
	ImageOverride string `json:"imageOverride,omitempty"`

	// ExtraEnv adds extra environment variables to the CNI container.
	// +optional
	ExtraEnv []v1.EnvVar `json:"extraEnv,omitempty"`

	// ExtraVolumes configures custom volumes to be used by the CNI container.
	// +optional
	ExtraVolumes []v1.Volume `json:"extraVolumes,omitempty"`

	// ExtraVolumeMounts configures custom volume mounts to be used by the CNI container.
	// +optional
	ExtraVolumeMounts []v1.VolumeMount `json:"extraVolumeMounts,omitempty"`
}

// DatastoreConfig specifies the product's datastore configuration.
// +k8s:openapi-gen=true
type DatastoreConfig struct {
	// Type is the type of datastore to be used. Currently, only Kubernetes API datastore is supported.
	// Default: kubernetes
	// +optional
	Type DatastoreType `json:"type,omitempty"`
}

// DatastoreType is a valid datastore type.
type DatastoreType string

var (
	Kubernetes DatastoreType = "kubernetes"
)

type ProductVariant string

var (
	Calico                 ProductVariant = "Calico"
	TigeraSecureEnterprise ProductVariant = "TigeraSecureEnterprise"
)

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
