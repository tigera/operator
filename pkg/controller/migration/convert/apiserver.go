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

package convert

import (
	"fmt"
	"reflect"

	"github.com/tigera/operator/pkg/controller/migration/convert/helpers"

	operatorv1 "github.com/tigera/operator/api/v1"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

// handleAPIServer
func handleAPIServer(d *appsv1.Deployment, apiServer *operatorv1.APIServer) error {
	// handle labels
	if err := handleAPIServerLabels(d, apiServer); err != nil {
		return err
	}

	// handle annotations
	if err := handleAPIServerAnnotations(d, apiServer); err != nil {
		return err
	}

	// handle apiserver container resources
	for _, container := range d.Spec.Template.Spec.Containers {
		if len(container.Resources.Limits) > 0 || len(container.Resources.Requests) > 0 {
			if err := migrateAPIServerContainerResources(apiServer, &container); err != nil {
				return err
			}
		}
	}

	// handle apiserver init container resources
	for _, initContainer := range d.Spec.Template.Spec.InitContainers {
		if len(initContainer.Resources.Limits) > 0 || len(initContainer.Resources.Requests) > 0 {
			if err := migrateAPIServerInitContainerResources(apiServer, &initContainer); err != nil {
				return err
			}
		}
	}

	// handle minReadySeconds
	if err := migrateAPIServerMinReadySeconds(d, apiServer); err != nil {
		return err
	}

	// handle tolerations
	if err := migrateAPIServerTolerations(d, apiServer); err != nil {
		return err
	}

	// handle nodeSelector and affinity
	if err := migrateAPIServerNodeSelectors(d, apiServer); err != nil {
		return err
	}

	return nil
}

func handleAPIServerAnnotations(d *appsv1.Deployment, apiServer *operatorv1.APIServer) error {
	// Handle calico-apiserver annotations.
	annots := removeKubernetesAnnotations(d.Annotations, map[string]string{}, toBeIgnoredAnnotationKeyRegExps)
	if len(annots) == 0 {
		if hasAnnotations(apiServer.Spec.APIServerDeployment) {
			return ErrAnnotationsOnlyOnInstall(ComponentAPIServer)
		}
	} else {
		helpers.EnsureAPIServerAnnotationsNotNil(apiServer)
		if err := mergeAnnotations(ComponentAPIServer, apiServer.Spec.APIServerDeployment.Metadata.Annotations, annots); err != nil {
			return err
		}
	}

	// Handle calico-apiserver pod template spec annotations.
	annots = removeKubernetesAnnotations(d.Spec.Template.Annotations, map[string]string{}, toBeIgnoredAnnotationKeyRegExps)
	if len(annots) == 0 {
		if hasPodTemplateAnnotations(apiServer.Spec.APIServerDeployment) {
			return ErrAnnotationsOnlyOnInstall(ComponentAPIServer + " podTemplateSpec")
		}
	} else {
		helpers.EnsureAPIServerPodTemplateAnnotationsNotNil(apiServer)
		if err := mergeAnnotations(ComponentAPIServer+" podTemplateSpec", apiServer.Spec.APIServerDeployment.Spec.Template.Metadata.Annotations, annots); err != nil {
			return err
		}
	}
	return nil
}

func handleAPIServerLabels(d *appsv1.Deployment, apiServer *operatorv1.APIServer) error {
	// Handle calico-apiserver labels
	labels := removeStandardOperatorLabels(d.Labels)
	if len(labels) == 0 {
		if hasLabels(apiServer.Spec.APIServerDeployment) {
			return ErrLabelsOnlyOnInstall(ComponentAPIServer)
		}
	} else {
		helpers.EnsureAPIServerLabelsNotNil(apiServer)
		if err := mergeLabels(ComponentAPIServer, apiServer.Spec.APIServerDeployment.Metadata.Labels, labels); err != nil {
			return err
		}
	}

	// Handle calico-apiserver pod template spec annotations.
	labels = removeStandardOperatorLabels(d.Spec.Template.Labels)
	if len(labels) == 0 {
		if hasPodTemplateLabels(apiServer.Spec.APIServerDeployment) {
			return ErrLabelsOnlyOnInstall(ComponentAPIServer + " podTemplateSpec")
		}
	} else {
		helpers.EnsureAPIServerPodTemplateLabelsNotNil(apiServer)
		if err := mergeLabels(ComponentAPIServer, apiServer.Spec.APIServerDeployment.Spec.Template.Metadata.Labels, labels); err != nil {
			return err
		}
	}

	return nil
}

func migrateAPIServerContainerResources(apiServer *operatorv1.APIServer, container *corev1.Container) error {
	var apiServerResources corev1.ResourceRequirements
	var found bool

	if apiServer.Spec.APIServerDeployment != nil {
		cs := apiServer.Spec.APIServerDeployment.GetContainers()
		for _, c := range cs {
			if c.Name == container.Name {
				apiServerResources = c.Resources
				found = true
			}
		}
	}

	// If resources already exist for the API server container, verify that they equal the container's existing resources.
	if found {
		if !reflect.DeepEqual(apiServerResources, container.Resources) {
			return ErrIncompatibleCluster{
				err:       fmt.Sprintf("Resources for the component container %q did not match between APIServer and migration source", container.Name),
				component: ComponentAPIServer,
				fix:       "remove the component's container resources from your APIServer resource, or remove them from the currently installed API server",
			}
		}
		return nil
	}

	// Create a container override using the resources and append it to the component resource override containers' field.
	// Note: calico-windows-upgrade is not available in a manifest install so is not handled here.
	newContainer := operatorv1.APIServerDeploymentContainer{Name: container.Name, Resources: &container.Resources}
	helpers.EnsureAPIServerContainersNotNil(apiServer)
	apiServer.Spec.APIServerDeployment.Spec.Template.Spec.Containers = append(apiServer.Spec.APIServerDeployment.Spec.Template.Spec.Containers, newContainer)

	return nil
}

func migrateAPIServerInitContainerResources(apiServer *operatorv1.APIServer, container *corev1.Container) error {
	var apiServerResources corev1.ResourceRequirements
	var found bool

	if apiServer.Spec.APIServerDeployment != nil {
		cs := apiServer.Spec.APIServerDeployment.GetInitContainers()
		for _, c := range cs {
			if c.Name == container.Name {
				apiServerResources = c.Resources
				found = true
			}
		}
	}

	// If resources already exist for the API server init container, verify that they equal the container's existing resources.
	if found {
		if !reflect.DeepEqual(apiServerResources, container.Resources) {
			return ErrIncompatibleCluster{
				err:       fmt.Sprintf("Resources for the component init container %q did not match between APIServer and migration source", container.Name),
				component: ComponentAPIServer,
				fix:       "remove the component's init container resources from your APIServer resource, or remove them from the currently installed API server",
			}
		}
		return nil
	}

	// Create a container override using the resources and append it to the component resource override containers' field.
	// Note: calico-windows-upgrade is not available in a manifest install so is not handled here.
	newContainer := operatorv1.APIServerDeploymentInitContainer{Name: container.Name, Resources: &container.Resources}
	helpers.EnsureAPIServerInitContainersNotNil(apiServer)
	apiServer.Spec.APIServerDeployment.Spec.Template.Spec.InitContainers = append(apiServer.Spec.APIServerDeployment.Spec.Template.Spec.InitContainers, newContainer)

	return nil
}

func migrateAPIServerMinReadySeconds(d *appsv1.Deployment, apiServer *operatorv1.APIServer) error {
	minReadySeconds := getMinReadySeconds(apiServer.Spec.APIServerDeployment)
	if d.Spec.MinReadySeconds > 0 {
		if minReadySeconds == nil {
			// minReadySeconds set on the component but not the resource so migrate it over.
			helpers.EnsureAPIServerSpecNotNil(apiServer)
			apiServer.Spec.APIServerDeployment.Spec.MinReadySeconds = &d.Spec.MinReadySeconds
		} else {
			if *minReadySeconds != d.Spec.MinReadySeconds {
				return ErrIncompatibleMinReadySeconds(ComponentAPIServer)
			}
		}
	} else {
		// minReadySeconds is not set on the component, check if it's set on the resource.
		if minReadySeconds != nil {
			return ErrIncompatibleMinReadySeconds(ComponentAPIServer)
		}
	}

	return nil
}

func migrateAPIServerTolerations(d *appsv1.Deployment, apiServer *operatorv1.APIServer) error {
	var apiServerTolerations []corev1.Toleration
	if apiServer.Spec.APIServerDeployment != nil {
		apiServerTolerations = apiServer.Spec.APIServerDeployment.GetTolerations()
	}
	componentTolerations := d.Spec.Template.Spec.Tolerations

	// The API server container has different tolerations depending on whether it's hostNetworked or not.
	defaultAPIServerTolerations := []corev1.Toleration{rmeta.TolerateMaster}
	if d.Spec.Template.Spec.HostNetwork {
		defaultAPIServerTolerations = rmeta.TolerateAll
	}

	migratedTolerations, err := determineMigratedTolerations(ComponentAPIServer, apiServerTolerations, componentTolerations, defaultAPIServerTolerations)
	if err != nil {
		return err
	}

	// If the resulting tolerations to migrate are nil and the APIServer tolerations were nil, do not update the APIServer.
	// In all other cases, we need to update the APIServer.
	if migratedTolerations != nil || apiServerTolerations != nil {
		helpers.EnsureAPIServerPodSpecNotNil(apiServer)
		apiServer.Spec.APIServerDeployment.Spec.Template.Spec.Tolerations = migratedTolerations
	}
	return nil
}

func migrateAPIServerNodeSelectors(d *appsv1.Deployment, apiServer *operatorv1.APIServer) error {
	if d.Spec.Template.Spec.Affinity != nil {
		if apiServer.Spec.APIServerDeployment == nil || apiServer.Spec.APIServerDeployment.GetAffinity() == nil {
			// Affinity set on the component but not the API server so migrate it over.
			helpers.EnsureAPIServerPodSpecNotNil(apiServer)
			apiServer.Spec.APIServerDeployment.Spec.Template.Spec.Affinity = d.Spec.Template.Spec.Affinity
		} else {
			// Affinity is set on the component and the resource, verify that they match.
			if !reflect.DeepEqual(d.Spec.Template.Spec.Affinity, apiServer.Spec.APIServerDeployment.Spec.Template.Spec.Affinity) {
				return ErrIncompatibleAffinity(ComponentAPIServer)
			}
		}
	} else {
		// Affinity is not set on the component, check if it's set on the resource.
		if apiServer.Spec.APIServerDeployment != nil && apiServer.Spec.APIServerDeployment.GetAffinity() != nil {
			return ErrIncompatibleAffinity(ComponentAPIServer)
		}
	}

	nodeSel := removeOSNodeSelectors(d.Spec.Template.Spec.NodeSelector)

	// Merge any remaining nodeSelectors into the resource.
	if len(nodeSel) == 0 {
		if hasNodeSelector(apiServer.Spec.APIServerDeployment) {
			return ErrNodeSelectorOnlyOnInstall(ComponentAPIServer)
		}
	} else {
		helpers.EnsureAPIServerNodeSelectorNotNil(apiServer)
		if err := mergeNodeSelector(ComponentAPIServer, apiServer.Spec.APIServerDeployment.Spec.Template.Spec.NodeSelector, nodeSel); err != nil {
			return err
		}
	}

	return nil
}
