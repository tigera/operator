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
	"k8s.io/apimachinery/pkg/util/intstr"
)

// NOTE: json tags are required. Any new fields you add must have json tags for the fields to be serialized.
// NOTE: After modifying this file, run `make gen-files` to regenerate code.

// KubeProxySpec defines the state of a kube-proxy installation.
// +k8s:openapi-gen=true
type KubeProxySpec struct {
	// Required specifies whether kube-proxy needs to be installed or if it's already provided.
	// Default: false
	// +optional
	Required bool `json:"required,omitempty"`

	// APIServer is a mandatory string containing a server:port URL.
	// Default: ""
	// +optional
	APIServer string `json:"apiServer,omitempty"`

	// Image is a custom kube-proxy image. The value must be a full qualified image name.
	// Default: "k8s.gcr.io/kube-proxy:v1.13.6"
	// +optional
	Image string `json:"image,omitempty"`
}

// InstallationSpec defines the desired state of Installation.
// +k8s:openapi-gen=true
type InstallationSpec struct {
	// Version of the product to install. This is the default image tag used for component Docker images.
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

	// Registry is the default Docker registry used for component Docker images.
	// Default: docker.io/
	// +optional
	Registry string `json:"registry,omitempty"`

	// ImagePullSecrets is an array of references to Docker registry pull secrets.
	// +optional
	ImagePullSecrets []v1.LocalObjectReference `json:"imagePullSecrets,omitempty"`

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

	// APIServer is optional configuration for the API server component.
	// +optional
	APIServer APIServerSpec `json:"apiServer,omitempty"`

	// Compliance is option configuration for the Compliance component.
	// +optional
	Compliance ComplianceSpec `json:"compliance,omitempty"`

	// IntrusionDetection is optional configuration for the Intrusion Detection feature in Tigera Secure.
	// +optional
	IntrusionDetection IntrusionDetectionSpec `json:"intrusionDetection,omitempty"`

	// Console is optional configuration for the Tigera Secure management console.
	// +optional
	Console ConsoleSpec `json:"console,omitempty"`
}

// IntrusionDetectionSpec defines optional configuration for the Intrusion Detection component.
// +k8s:openapi-gen=true
type IntrusionDetectionSpec struct {
	// Controller is optional configuration for the Intrusion Detection controller.
	// +optional
	Controller IntrusionDetectionControllerSpec `json:"controller,omitempty"`

	// Installer is optional configuration for the Intrusion Detection elasticsearch job installer.
	// +optional
	Installer IntrusionDetectionInstallerSpec `json:"installer,omitempty"`
}

// IntrusionDetectionControllerSpec defines optional configuration for the Intrusion Detection controller.
// +k8s:openapi-gen=true
type IntrusionDetectionControllerSpec struct {
	// Image configures a different Docker image for this component. The value must be a full qualified image name.
	// +optional
	Image string `json:"image,omitempty"`
}

// IntrusionDetectionInstallerSpec defines optional configuration for the Intrusion Detection job installer.
// +k8s:openapi-gen=true
type IntrusionDetectionInstallerSpec struct {
	// Image configures a different Docker image for this component. The value must be a full qualified image name.
	// +optional
	Image string `json:"image,omitempty"`
}

// KubeControllersSpec defines optional configuration for the kube-controllers component.
// +k8s:openapi-gen=true
type KubeControllersSpec struct {
	// Image configures a different Docker image for the kube-controllers deployment.
	// The value must be a full qualified image name.
	// E.g "gcr.io/acme/calico-kube-controllers:beta".
	// +optional
	Image string `json:"image,omitempty"`

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

// APIServerSpec defines optional configuration for the API server component.
// Valid only for the variant 'TigeraSecureEnterprise'.
// +k8s:openapi-gen=true
type APIServerSpec struct {
	// Image configures a different Docker image for the API server. The value must be a full qualified image name.
	// E.g "gcr.io/acme/calico-api-server:beta".
	// +optional
	Image string `json:"image,omitempty"`

	// ExtraEnv adds extra environment variables to the API server.
	// +optional
	ExtraEnv []v1.EnvVar `json:"extraEnv,omitempty"`

	// ExtraVolumes configures custom volumes to be used by the API server.
	// +optional
	ExtraVolumes []v1.Volume `json:"extraVolumes,omitempty"`

	// ExtraVolumeMounts configures custom volume mounts to be used by the API server.
	// +optional
	ExtraVolumeMounts []v1.VolumeMount `json:"extraVolumeMounts,omitempty"`

	// Tolerations configures custom tolerations on the API server deployment.
	// +optional
	Tolerations []v1.Toleration `json:"tolerations,omitempty"`

	// Resources configures custom resource requirements on the API server container.
	// +optional
	Resources v1.ResourceRequirements `json:"resources,omitempty"`
}

// ConsoleManagerSpec defines optional configuration for the Tigera Secure management console manager.
// +k8s:openapi-gen=true
type ConsoleManagerSpec struct {
	// Image configures a different Docker image for this component. The value must be a full qualified image name.
	// +optional
	Image string `json:"image,omitempty"`
}

// ConsoleProxySpec defines optional configuration for the Tigera Secure management console proxy.
// +k8s:openapi-gen=true
type ConsoleProxySpec struct {
	// Image configures a different Docker image for this component. The value must be a full qualified image name.
	// +optional
	Image string `json:"image,omitempty"`
}

// ConsoleEsProxySpec defines optional configuration for the Tigera Secure management console ES proxy.
// +k8s:openapi-gen=true
type ConsoleEsProxySpec struct {
	// Image configures a different Docker image for this component. The value must be a full qualified image name.
	// +optional
	Image string `json:"image,omitempty"`
}

// ConsoleSpec defines optional configuration for the Tigera Secure management console.
// Valid only for the variant 'TigeraSecureEnterprise'.
// +k8s:openapi-gen=true
type ConsoleSpec struct {
	// Manager is optional configuration for the Tigera Secure management console manager.
	// +optional
	Manager ConsoleManagerSpec `json:"manager,omitempty"`

	// Proxy is optional configuration for the Tigera Secure management console proxy.
	// +optional
	Proxy ConsoleProxySpec `json:"proxy,omitempty"`

	// EsProxy is optional configuration for the Tigera Secure management console ES proxy.
	// +optional
	EsProxy ConsoleEsProxySpec `json:"esProxy,omitempty"`

	// Auth is optional authentication configuration for the Tigera Secure management console.
	// +optional
	Auth Auth `json:"auth,omitempty"`
}

// Auth defines authentication configuration.
// +k8s:openapi-gen=true
type Auth struct {
	// Type configures the type of authentication used by the manager.
	// Default: "Basic"
	// +optional
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

// NodeSpec defines optional configuration for the node component.
// +k8s:openapi-gen=true
type NodeSpec struct {
	// Image configures a different Docker image for the node daemonset. The value must be a full qualified image name
	// E.g "gcr.io/tigera/cnx-node:beta".
	// +optional
	Image string `json:"image,omitempty"`

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
	// Image configures a different Docker image for the CNI image. The value must be a full qualified image name.
	// E.g "gcr.io/acme/calico-cni:beta".
	// +optional
	Image string `json:"image,omitempty"`

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

// ComplianceControllerSpec defines optional configuration for the Compliance Controller component.
// +k8s:openapi-gen=true
type ComplianceControllerSpec struct {
	// Image configures a different Docker imagee for this component. The value must be a full qualified image name.
	// +optional
	Image string `json:"image,omitempty"`
}

// ComplianceReporterSpec defines optional configuration for the Compliance Reporter component.
// +k8s:openapi-gen=true
type ComplianceReporterSpec struct {
	// Image configures a different Docker imagee for this component. The value must be a full qualified image name.
	// +optional
	Image string `json:"image,omitempty"`
}

// ComplianceServerSpec defines optional configuration for the Compliance Server component.
// +k8s:openapi-gen=true
type ComplianceServerSpec struct {
	// Image configures a different Docker imagee for this component. The value must be a full qualified image name.
	// +optional
	Image string `json:"image,omitempty"`
}

// ComplianceSnapshotterSpec defines optional configuration for the Compliance Snapshotter component.
// +k8s:openapi-gen=true
type ComplianceSnapshotterSpec struct {
	// Image configures a different Docker imagee for this component. The value must be a full qualified image name.
	// +optional
	Image string `json:"image,omitempty"`
}

// ComplianceBenchmarkerSpec defines optional configuration for the Compliance Benchmarker component.
// +k8s:openapi-gen=true
type ComplianceBenchmarkerSpec struct {
	// Image configures a different Docker imagee for this component. The value must be a full qualified image name.
	// +optional
	Image string `json:"image,omitempty"`
}

// ComplianceSpec defines optional configuration for the Compliance component.
// +k8s:openapi-gen=true
type ComplianceSpec struct {
	// Controller is an optional configuration for the Compliance Controller component.
	// +optional
	Controller ComplianceControllerSpec `json:"controller,omitempty"`

	// Reporter is an optional configuration for the Compliance Reporter component.
	// +optional
	Reporter ComplianceReporterSpec `json:"reporter,omitempty"`

	// Server is an optional configuration for the Compliance Server component.
	// +optional
	Server ComplianceServerSpec `json:"server,omitempty"`

	// Snapshotter is an optional configuration for the Compliance Snapshotter component.
	// +optional
	Snapshotter ComplianceSnapshotterSpec `json:"snapshotter,omitempty"`

	// Benchmarker is an optional configuration for the Compliance Benchmarker component.
	// +optional
	Benchmarker ComplianceBenchmarkerSpec `json:"benchmarker,omitempty"`
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

// InstallationStatus defines the observed state of Installation
// +k8s:openapi-gen=true
type InstallationStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book.kubebuilder.io/beyond_basics/generating_crd.html
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
