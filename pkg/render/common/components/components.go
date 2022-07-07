// Copyright (c) 2022 Tigera, Inc. All rights reserved.

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
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

// ApplyDaemonSetOverrides applies the overrides to the given DaemonSet.
// Note: overrides must not be nil pointer.
func ApplyDaemonSetOverrides(ds *appsv1.DaemonSet, overrides components.DaemonSetOverride) *appsv1.DaemonSet {
	// Catch if caller passes in an explicit nil.
	if overrides == nil {
		return ds
	}

	var metadata *operatorv1.Metadata
	var minReadySeconds *int32
	var podTemplateMetadata *operatorv1.Metadata

	var affinity *corev1.Affinity
	var tolerations []corev1.Toleration
	var nodeSelector map[string]string
	var initContainers []operatorv1.Container
	var containers []operatorv1.Container

	metadata = overrides.GetMetadata()
	podTemplateMetadata = overrides.GetPodTemplateMetadata()
	minReadySeconds = overrides.GetMinReadySeconds()
	affinity = overrides.GetAffinity()
	tolerations = overrides.GetTolerations()
	nodeSelector = overrides.GetNodeSelector()

	initContainers = overrides.GetInitContainers()
	containers = overrides.GetContainers()

	if metadata != nil {
		if len(metadata.Labels) > 0 {
			if ds.Labels == nil {
				ds.SetLabels(make(map[string]string))
			}
			common.MergeMaps(metadata.Labels, ds.Labels)
		}
		if len(metadata.Annotations) > 0 {
			if ds.GetAnnotations() == nil {
				ds.SetAnnotations(make(map[string]string))
			}
			common.MergeMaps(metadata.Annotations, ds.GetAnnotations())
		}
	}

	if minReadySeconds != nil {
		ds.Spec.MinReadySeconds = *minReadySeconds
	}

	if podTemplateMetadata != nil {
		if len(podTemplateMetadata.Labels) > 0 {
			if ds.Spec.Template.GetLabels() == nil {
				ds.Spec.Template.SetLabels(make(map[string]string))
			}
			common.MergeMaps(podTemplateMetadata.Labels, ds.Spec.Template.GetLabels())
		}
		if len(podTemplateMetadata.Annotations) > 0 {
			if ds.Spec.Template.GetAnnotations() == nil {
				ds.Spec.Template.SetAnnotations(make(map[string]string))
			}
			common.MergeMaps(podTemplateMetadata.Annotations, ds.Spec.Template.GetAnnotations())
		}
	}

	// Merge all other fields in the overrides spec if they exist.
	if initContainers != nil {
		mergeContainers(ds.Spec.Template.Spec.InitContainers, initContainers)
	}
	if containers != nil {
		mergeContainers(ds.Spec.Template.Spec.Containers, containers)
	}
	if affinity != nil {
		ds.Spec.Template.Spec.Affinity = affinity
	}
	if nodeSelector != nil {
		ds.Spec.Template.Spec.NodeSelector = nodeSelector
	}
	if tolerations != nil {
		ds.Spec.Template.Spec.Tolerations = tolerations
	}

	return ds
}

// mergeContainers copies the ResourceRequirements from the provided containers
// to the current corev1.Containers.
func mergeContainers(current []corev1.Container, provided []operatorv1.Container) {
	providedMap := make(map[string]operatorv1.Container)
	for _, c := range provided {
		providedMap[c.Name] = c
	}

	for i, c := range current {
		if override, ok := providedMap[c.Name]; ok {
			current[i].Resources = *override.Resources
		}
	}
}
