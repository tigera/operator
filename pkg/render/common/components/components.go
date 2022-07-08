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
	"fmt"

	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var log = logf.Log.WithName("components")

// ApplyDaemonSetOverrides applies the overrides to the given DaemonSet.
// Note: overrides must not be nil pointer.
func ApplyDaemonSetOverrides(ds *appsv1.DaemonSet, overrides components.DaemonSetOverrides) *appsv1.DaemonSet {
	// Catch if caller passes in an explicit nil.
	if overrides == nil {
		return ds
	}

	metadata := overrides.GetMetadata()
	podTemplateMetadata := overrides.GetPodTemplateMetadata()
	minReadySeconds := overrides.GetMinReadySeconds()
	affinity := overrides.GetAffinity()
	tolerations := overrides.GetTolerations()
	nodeSelector := overrides.GetNodeSelector()

	initContainers := overrides.GetInitContainers()
	containers := overrides.GetContainers()

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
func mergeContainers(current []corev1.Container, provided []corev1.Container) {
	providedMap := make(map[string]corev1.Container)
	for _, c := range provided {
		providedMap[c.Name] = c
	}

	for i, c := range current {
		if override, ok := providedMap[c.Name]; ok {
			current[i].Resources = override.Resources
		} else {
			log.V(1).Info(fmt.Sprintf("WARNING: the container %q was provided for an override and passed CRD validation but the container does not currently exist", c.Name))
		}
	}
}
