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
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

type container struct {
	Name      string                       `json:"name"`
	Resources *corev1.ResourceRequirements `json:"resources"`
}

// ApplyDaemonSetOverrides applies the overrides to the given DaemonSet.
func ApplyDaemonSetOverrides(ds *appsv1.DaemonSet, overrides interface{}) *appsv1.DaemonSet {
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
	var initContainers []container
	var containers []container

	switch obj := overrides.(type) {
	case *operatorv1.CalicoNodeDaemonSet:
		// If overrides was a pointer to nil, then just return the original ds.
		if obj == nil {
			return ds
		}

		metadata = obj.Metadata

		// Skip the rest of the case if no spec.
		if obj.Spec == nil {
			break
		}

		minReadySeconds = obj.Spec.MinReadySeconds

		// Skip the rest of the case if no pod template spec.
		if obj.Spec.Template == nil {
			break
		}

		podTemplateMetadata = obj.Spec.Template.Metadata

		if obj.Spec.Template.Spec != nil {
			affinity = obj.Spec.Template.Spec.Affinity
			tolerations = obj.Spec.Template.Spec.Tolerations
			nodeSelector = obj.Spec.Template.Spec.NodeSelector

			if len(obj.Spec.Template.Spec.InitContainers) > 0 {
				for _, v := range obj.Spec.Template.Spec.InitContainers {
					c := container{Name: v.Name, Resources: v.Resources}
					initContainers = append(initContainers, c)
				}
			}
			if len(obj.Spec.Template.Spec.Containers) > 0 {
				for _, v := range obj.Spec.Template.Spec.Containers {
					c := container{Name: v.Name, Resources: v.Resources}
					containers = append(containers, c)
				}
			}
		}
	}

	if metadata != nil {
		if len(metadata.Labels) > 0 {
			if ds.Labels == nil {
				ds.SetLabels(make(map[string]string))
			}
			mergeMaps(ds.Labels, metadata.Labels)
		}
		if len(metadata.Annotations) > 0 {
			if ds.GetAnnotations() == nil {
				ds.SetAnnotations(make(map[string]string))
			}
			mergeMaps(ds.GetAnnotations(), metadata.Annotations)
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
			mergeMaps(ds.Spec.Template.GetLabels(), podTemplateMetadata.Labels)
		}
		if len(podTemplateMetadata.Annotations) > 0 {
			if ds.Spec.Template.GetAnnotations() == nil {
				ds.Spec.Template.SetAnnotations(make(map[string]string))
			}
			mergeMaps(ds.Spec.Template.GetAnnotations(), podTemplateMetadata.Annotations)
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

// mergeMaps adds all key/value pairs from the provided map to the current map
// if those keys do not already exist in the current map.
func mergeMaps(current map[string]string, provided map[string]string) {
	for k, v := range provided {
		// Only copy this key/value pair from the provided map if it does
		// not already exist.
		if _, ok := current[k]; !ok {
			current[k] = v
		}
	}
}

// mergeContainers copies the ResourceRequirements from the provided containers
// to the current corev1.Containers.
func mergeContainers(current []corev1.Container, provided []container) {
	for _, pc := range provided {
		// Skip if no resources defined.
		if pc.Resources == nil {
			continue
		}

		var index int
		var found bool
		for i, cc := range current {
			if cc.Name == pc.Name {
				index = i
				found = true
				break
			}
		}
		if found {
			current[index].Resources = *pc.Resources
		}
	}
}
