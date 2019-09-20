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

	// KubernetesProvider specifies which platform this cluster is running on. Operator will
	// do it's best to autodetect and set this. But can be overridden here.
	KubernetesProvider Provider `json:"kubernetesProvider,omitempty"`
}

type Provider string

var (
	ProviderNone      Provider = ""
	ProviderEKS       Provider = "EKS"
	ProviderOpenShift Provider = "OpenShift"
	ProviderDockerEE  Provider = "DockerEnterprise"
)

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
}

// KubeControllersSpec defines optional configuration for the kube-controllers component.
// +k8s:openapi-gen=true
type KubeControllersSpec struct {
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
