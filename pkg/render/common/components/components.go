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

// replicatedPodResource contains the overridable data for a Deployment or DaemonSet.
type replicatedPodResource struct {
	labels             map[string]string
	annotations        map[string]string
	minReadySeconds    *int32
	podTemplateSpec    *corev1.PodTemplateSpec
	deploymentStrategy *appsv1.DeploymentStrategy // Deployments only
}

// applyReplicatedPodResourceOverrides takes the given replicated pod resource data and applies the overrides.
func applyReplicatedPodResourceOverrides(r *replicatedPodResource, overrides components.ReplicatedPodResourceOverrides) *replicatedPodResource {
	if metadata := overrides.GetMetadata(); metadata != nil {
		if len(metadata.Labels) > 0 {
			r.labels = common.MapExistsOrInitialize(r.labels)
			common.MergeMaps(metadata.Labels, r.labels)
		}
		if len(metadata.Annotations) > 0 {
			r.annotations = common.MapExistsOrInitialize(r.annotations)
			common.MergeMaps(metadata.Annotations, r.annotations)
		}
	}
	if minReadySeconds := overrides.GetMinReadySeconds(); minReadySeconds != nil {
		r.minReadySeconds = minReadySeconds
	}
	if podTemplateMetadata := overrides.GetPodTemplateMetadata(); podTemplateMetadata != nil {
		if len(podTemplateMetadata.Labels) > 0 {
			r.podTemplateSpec.Labels = common.MapExistsOrInitialize(r.podTemplateSpec.Labels)
			common.MergeMaps(podTemplateMetadata.Labels, r.podTemplateSpec.Labels)
		}
		if len(podTemplateMetadata.Annotations) > 0 {
			r.podTemplateSpec.Annotations = common.MapExistsOrInitialize(r.podTemplateSpec.Annotations)
			common.MergeMaps(podTemplateMetadata.Annotations, r.podTemplateSpec.Annotations)
		}
	}
	if tgp := overrides.GetTerminationGracePeriodSeconds(); tgp != nil {
		r.podTemplateSpec.Spec.TerminationGracePeriodSeconds = tgp
	}
	if ds := overrides.GetDeploymentStrategy(); ds != nil {
		r.deploymentStrategy = ds
	}
	if initContainers := overrides.GetInitContainers(); initContainers != nil {
		mergeContainers(r.podTemplateSpec.Spec.InitContainers, initContainers)
	}
	if containers := overrides.GetContainers(); containers != nil {
		mergeContainers(r.podTemplateSpec.Spec.Containers, containers)
	}
	if affinity := overrides.GetAffinity(); affinity != nil {
		r.podTemplateSpec.Spec.Affinity = affinity
	}
	if nodeSelector := overrides.GetNodeSelector(); nodeSelector != nil {
		r.podTemplateSpec.Spec.NodeSelector = common.MapExistsOrInitialize(r.podTemplateSpec.Spec.NodeSelector)
		common.MergeMaps(nodeSelector, r.podTemplateSpec.Spec.NodeSelector)
	}
	if tolerations := overrides.GetTolerations(); tolerations != nil {
		r.podTemplateSpec.Spec.Tolerations = tolerations
	}

	return r
}

// ApplyDaemonSetOverrides applies the overrides to the given DaemonSet.
// Note: overrides must not be nil pointer.
func ApplyDaemonSetOverrides(ds *appsv1.DaemonSet, overrides components.ReplicatedPodResourceOverrides) {
	// Catch if caller passes in an explicit nil.
	if overrides == nil {
		return
	}

	// Pull out the data we'll override from the DaemonSet.
	r := &replicatedPodResource{
		labels:          ds.Labels,
		annotations:     ds.Annotations,
		minReadySeconds: &ds.Spec.MinReadySeconds,
		podTemplateSpec: &ds.Spec.Template,
	}
	// Apply the overrides.
	applyReplicatedPodResourceOverrides(r, overrides)

	// Set the possibly new fields back onto the DaemonSet.
	ds.Labels = r.labels
	ds.Annotations = r.annotations
	ds.Spec.MinReadySeconds = *r.minReadySeconds
	ds.Spec.Template = *r.podTemplateSpec
}

// ApplyDeploymentOverrides applies the overrides to the given Deployment.
// Note: overrides must not be nil pointer.
func ApplyDeploymentOverrides(d *appsv1.Deployment, overrides components.ReplicatedPodResourceOverrides) {
	// Catch if caller passes in an explicit nil.
	if overrides == nil {
		return
	}

	// Pull out the data we'll override from the DaemonSet.
	r := &replicatedPodResource{
		labels:             d.Labels,
		annotations:        d.Annotations,
		minReadySeconds:    &d.Spec.MinReadySeconds,
		podTemplateSpec:    &d.Spec.Template,
		deploymentStrategy: &d.Spec.Strategy,
	}
	// Apply the overrides.
	applyReplicatedPodResourceOverrides(r, overrides)

	// Set the possibly new fields back onto the DaemonSet.
	d.Labels = r.labels
	d.Annotations = r.annotations
	d.Spec.MinReadySeconds = *r.minReadySeconds
	d.Spec.Template = *r.podTemplateSpec
	d.Spec.Strategy = *r.deploymentStrategy
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
