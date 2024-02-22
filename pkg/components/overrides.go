// Copyright (c) 2022-2024 Tigera, Inc. All rights reserved.

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

package components

import (
	opv1 "github.com/tigera/operator/api/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

// ReplicatedPodResourceOverrides represents a type that contains the data needed to override a component DaemonSet or Deployment resource.
type ReplicatedPodResourceOverrides interface {
	// GetMetadata returns metadata used to override the DaemonSet/Deployment's metadata.
	GetMetadata() *opv1.Metadata

	// GetMinReadySeconds returns the value used to override a DaemonSet/Deployment's minReadySeconds.
	GetMinReadySeconds() *int32

	// GetPodTemplateMetadata returns metadata used to override a DaemonSet/Deployment pod template's metadata.
	GetPodTemplateMetadata() *opv1.Metadata

	// GetInitContainers returns the containers used to override a DaemonSet/Deployment's init containers.
	// Only containers with fields specified (other than its name) should be returned.
	GetInitContainers() []corev1.Container

	// GetContainers returns the containers used to override a DaemonSet/Deployment's containers.
	// Only containers with fields specified (other than its name) should be returned.
	GetContainers() []corev1.Container

	// GetAffinity returns the value used to override a DaemonSet/Deployment's affinity.
	GetAffinity() *corev1.Affinity

	// GetNodeSelector returns the value used to override a DaemonSet/Deployment's nodeSelector.
	GetNodeSelector() map[string]string

	// GetTopologySpreadConstraints returns topology spread constraints to use.
	GetTopologySpreadConstraints() []corev1.TopologySpreadConstraint

	// GetTolerations returns the value used to override a DaemonSet/Deployment's tolerations.
	GetTolerations() []corev1.Toleration

	GetTerminationGracePeriodSeconds() *int64

	GetDeploymentStrategy() *appsv1.DeploymentStrategy

	// GetPriorityClassName() returns the value used to override a DaemonSet/Deployment's priorityClassName.
	GetPriorityClassName() string
}
