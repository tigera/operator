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
	v1 "k8s.io/api/core/v1"
)

// CalicoNodeContainer is a calico-node DaemonSet container.
type CalicoNodeContainer struct {
	// Name is an enum which identifies the calico-node DaemonSet container by name.
	// +kubebuilder:validation:Enum=calico-node
	Name string `json:"name"`
	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	Resources *v1.ResourceRequirements `json:"resources"`
}

// CalicoNodeInitContainer is a calico-node DaemonSet init container.
type CalicoNodeInitContainer struct {
	// Name is an enum which identifies the calico-node DaemonSet init container by name.
	// +kubebuilder:validation:Enum=install-cni;hostpath-init;flexvol-driver;mount-bpffs;node-certs-key-cert-provisioner;calico-node-prometheus-server-tls-key-cert-provisioner
	Name string `json:"name"`
	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	Resources *v1.ResourceRequirements `json:"resources"`
}

// CalicoNodeDaemonSetPodSpec is the calico-node DaemonSet's PodSpec.
type CalicoNodeDaemonSetPodSpec struct {
	// InitContainers is a list of calico-node init containers.
	// +optional
	InitContainers []CalicoNodeInitContainer `json:"initContainers,omitempty"`
	// Containers is a list of calico-node containers.
	// +optional
	Containers []CalicoNodeContainer `json:"containers,omitempty"`
	// Affinity is a group of affinity scheduling rules for the calico-node pods.
	// +optional
	Affinity *v1.Affinity `json:"affinity,omitempty"`
	// NodeSelector is the calico-node pod's scheduling constraints.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Tolerations is the calico-node pod's tolerations.
	// +optional
	Tolerations []v1.Toleration `json:"tolerations,omitempty"`
}

// CalicoNodeDaemonSetPodTemplateSpec is the calico-node DaemonSet's PodTemplateSpec
type CalicoNodeDaemonSetPodTemplateSpec struct {
	// Metadata is a subset of a Kubernetes object's metadata that is added to
	// the pod's metadata.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`
	// Spec is the calico-node DaemonSet's PodSpec.
	// +optional
	Spec *CalicoNodeDaemonSetPodSpec `json:"spec,omitempty"`
}

// CalicoNodeDaemonSet is the configuration for the calico-node DaemonSet.
type CalicoNodeDaemonSet struct {
	// Metadata is a subset of a Kubernetes object's metadata that is added to the DaemonSet.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`
	// Spec is the specification of the calico-node DaemonSet.
	// +optional
	Spec *CalicoNodeDaemonSetSpec `json:"spec,omitempty"`
}

// CalicoNodeDaemonSetSpec defines configuration for the calico-node DaemonSet.
type CalicoNodeDaemonSetSpec struct {
	// MinReadySeconds is the minimum number of seconds for which a newly created DaemonSet pod should
	// be ready without any of its container crashing, for it to be considered
	// available. Defaults to 0 (pod will be considered available as soon as it
	// is ready).
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=2147483647
	MinReadySeconds *int32 `json:"minReadySeconds,omitempty"`
	// Template describes the calico-node DaemonSet pod that will be created.
	// +optional
	Template *CalicoNodeDaemonSetPodTemplateSpec `json:"template,omitempty"`
}
