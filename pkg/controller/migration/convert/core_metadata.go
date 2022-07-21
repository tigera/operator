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
	"reflect"
	"regexp"

	comp "github.com/tigera/operator/pkg/components"
	. "github.com/tigera/operator/pkg/controller/migration/convert/helpers"

	operatorv1 "github.com/tigera/operator/api/v1"
)

// removeKubernetesAnnotations returns the given annotations with common k8s-native annotations removed.
// this function also accepts a second argument of additional annotations to remove.
func removeKubernetesAnnotations(existing, ignoreWithValue map[string]string, toBeIgnoredAnnotationKeyRegExps []*regexp.Regexp) map[string]string {
	a := existing

	for key, val := range existing {
		if key == "deprecated.daemonset.template.generation" ||
			key == "deployment.kubernetes.io/revision" ||
			key == "scheduler.alpha.kubernetes.io/critical-pod" {
			delete(a, key)
			continue
		}

		if v, ok := ignoreWithValue[key]; ok && v == val {
			delete(a, key)
			continue
		}

		for _, annotationKeyRegexp := range toBeIgnoredAnnotationKeyRegExps {
			if annotationKeyRegexp.MatchString(key) {
				delete(a, key)
				break
			}
		}
	}

	return a
}

// mergeAnnotations merges the annotations on the component with those on the installation.
func mergeAnnotations(componentName string, installAnnots, compAnnots map[string]string) error {
	// Verify that any annotations on the installation exist on the component.
	for k, v := range installAnnots {
		if x, ok := compAnnots[k]; !ok || x != v {
			return ErrIncompatibleAnnotation(k, componentName)
		}
	}
	// Copy annotations from the component to the install.
	for k, v := range compAnnots {
		// If a key already exists in the component's annotations in the install but values differ, return an error.
		if x, ok := installAnnots[k]; ok && x != v {
			return ErrIncompatibleAnnotation(k, componentName)
		}
		installAnnots[k] = v
	}

	return nil
}

func hasAnnotations(override comp.ReplicatedPodResourceOverrides) bool {
	if reflect.ValueOf(override).IsNil() {
		return false
	}
	if md := override.GetMetadata(); md != nil {
		return len(md.Annotations) > 0
	}
	return false
}

func hasPodTemplateAnnotations(override comp.ReplicatedPodResourceOverrides) bool {
	if reflect.ValueOf(override).IsNil() {
		return false
	}
	if md := override.GetPodTemplateMetadata(); md != nil {
		return len(md.Annotations) > 0
	}
	return false
}

// handleAnnotations is a migration handler that ensures the components' annotations are migrated to the install.
func handleAnnotations(c *components, install *operatorv1.Installation) error {
	// Handle calico-node annotations.
	annots := removeKubernetesAnnotations(c.node.Annotations, map[string]string{}, toBeIgnoredAnnotationKeyRegExps)
	if len(annots) == 0 && hasAnnotations(install.Spec.CalicoNodeDaemonSet) {
		return ErrAnnotationsOnlyOnInstall(ComponentCalicoNode)
	} else {
		EnsureCalicoNodeAnnotationsNotNil(install)
		if err := mergeAnnotations(ComponentCalicoNode, install.Spec.CalicoNodeDaemonSet.Metadata.Annotations, annots); err != nil {
			return err
		}
	}

	// Handle calico-node pod template spec annotations.
	annots = removeKubernetesAnnotations(c.node.Spec.Template.Annotations, map[string]string{}, toBeIgnoredAnnotationKeyRegExps)
	if len(annots) == 0 && hasPodTemplateAnnotations(install.Spec.CalicoNodeDaemonSet) {
		return ErrAnnotationsOnlyOnInstall(ComponentCalicoNode + " podTemplateSpec")
	} else {
		EnsureCalicoNodePodTemplateAnnotationsNotNil(install)
		if err := mergeAnnotations(ComponentCalicoNode+" podTemplateSpec", install.Spec.CalicoNodeDaemonSet.Spec.Template.Metadata.Annotations, annots); err != nil {
			return err
		}
	}

	// Handle calico-kube-controllers annotations.
	if c.kubeControllers == nil {
		if hasAnnotations(install.Spec.CalicoKubeControllersDeployment) {
			return ErrAnnotationsOnlyOnInstall(ComponentKubeControllers)
		}
		if hasPodTemplateAnnotations(install.Spec.CalicoKubeControllersDeployment) {
			return ErrAnnotationsOnlyOnInstall(ComponentKubeControllers + " podTemplateSpec")
		}
	} else {
		// Handle annotations
		annots = removeKubernetesAnnotations(c.kubeControllers.Annotations, map[string]string{}, toBeIgnoredAnnotationKeyRegExps)
		if len(annots) == 0 && hasAnnotations(install.Spec.CalicoKubeControllersDeployment) {
			return ErrAnnotationsOnlyOnInstall(ComponentKubeControllers)
		} else {
			EnsureKubeControllersAnnotationsNotNil(install)
			if err := mergeAnnotations(ComponentKubeControllers, install.Spec.CalicoKubeControllersDeployment.Metadata.Annotations, annots); err != nil {
				return err
			}
		}

		// Handle the pod template spec annotations
		annots = removeKubernetesAnnotations(c.kubeControllers.Spec.Template.Annotations, map[string]string{}, toBeIgnoredAnnotationKeyRegExps)
		if len(annots) == 0 && hasPodTemplateAnnotations(install.Spec.CalicoKubeControllersDeployment) {
			return ErrAnnotationsOnlyOnInstall(ComponentKubeControllers + " podTemplateSpec")
		} else {
			EnsureKubeControllersPodTemplateAnnotationsNotNil(install)
			if err := mergeAnnotations(ComponentKubeControllers, install.Spec.CalicoKubeControllersDeployment.Spec.Template.Metadata.Annotations, annots); err != nil {
				return err
			}
		}
	}

	// Handle typha annotations.
	if c.typha == nil {
		if hasAnnotations(install.Spec.TyphaDeployment) {
			return ErrAnnotationsOnlyOnInstall(ComponentTypha)
		}
		if hasPodTemplateAnnotations(install.Spec.TyphaDeployment) {
			return ErrAnnotationsOnlyOnInstall(ComponentTypha + " podTemplateSpec")
		}
	} else {
		// Handle annotations
		annots = removeKubernetesAnnotations(c.typha.Annotations, map[string]string{}, toBeIgnoredAnnotationKeyRegExps)
		if len(annots) == 0 && hasAnnotations(install.Spec.TyphaDeployment) {
			return ErrAnnotationsOnlyOnInstall(ComponentTypha)
		} else {
			EnsureTyphaAnnotationsNotNil(install)
			if err := mergeAnnotations(ComponentTypha, install.Spec.TyphaDeployment.Metadata.Annotations, annots); err != nil {
				return err
			}
		}
		// Handle the pod template spec annotations
		annots = removeKubernetesAnnotations(c.typha.Spec.Template.Annotations, map[string]string{}, toBeIgnoredAnnotationKeyRegExps)
		if len(annots) == 0 && hasPodTemplateAnnotations(install.Spec.TyphaDeployment) {
			return ErrAnnotationsOnlyOnInstall(ComponentTypha + " podTemplateSpec")
		} else {
			EnsureTyphaPodTemplateAnnotationsNotNil(install)
			if err := mergeAnnotations(ComponentTypha, install.Spec.TyphaDeployment.Spec.Template.Metadata.Annotations, annots); err != nil {
				return err
			}
		}
	}

	return nil
}

// removeStandardOperatorLabels returns the given labels with standard labels added by the operator removed.
func removeStandardOperatorLabels(existing map[string]string) map[string]string {
	for key, _ := range existing {
		// "app.kubernetes.io/name" is only set by the operator on deployments but we should not see it on daemonsets.
		if key == "k8s-app" || key == "app.kubernetes.io/name" {
			delete(existing, key)
			continue
		}
	}

	return existing
}

// mergeLabels merges the labels on the component with those on the installation.
func mergeLabels(componentName string, installLabels, compLabels map[string]string) error {
	// Verify that any annotations on the installation exist on the component.
	for k, v := range installLabels {
		if x, ok := compLabels[k]; !ok || x != v {
			return ErrIncompatibleLabel(k, componentName)
		}
	}
	// Copy annotations from the component to the install.
	for k, v := range compLabels {
		// If a key already exists in the component's annotations in the install but values differ, return an error.
		if x, ok := installLabels[k]; ok && x != v {
			return ErrIncompatibleLabel(k, componentName)
		}
		installLabels[k] = v
	}

	return nil
}

func hasLabels(override comp.ReplicatedPodResourceOverrides) bool {
	if reflect.ValueOf(override).IsNil() {
		return false
	}
	if md := override.GetMetadata(); md != nil {
		return len(md.Labels) > 0
	}
	return false
}

func hasPodTemplateLabels(override comp.ReplicatedPodResourceOverrides) bool {
	if reflect.ValueOf(override).IsNil() {
		return false
	}
	if md := override.GetPodTemplateMetadata(); md != nil {
		return len(md.Labels) > 0
	}
	return false
}

// handleLabels is a migration handler that ensures the components' labels are migrated to the install.
func handleLabels(c *components, install *operatorv1.Installation) error {
	// Handle calico-node labels
	labels := removeStandardOperatorLabels(c.node.Labels)
	if len(labels) == 0 && hasLabels(install.Spec.CalicoNodeDaemonSet) {
		return ErrLabelsOnlyOnInstall(ComponentCalicoNode)
	} else {
		EnsureCalicoNodeLabelsNotNil(install)
		if err := mergeLabels(ComponentCalicoNode, install.Spec.CalicoNodeDaemonSet.Metadata.Labels, labels); err != nil {
			return err
		}
	}

	// Handle calico-node pod template spec annotations.
	labels = removeStandardOperatorLabels(c.node.Spec.Template.Labels)
	if len(labels) == 0 && hasPodTemplateLabels(install.Spec.CalicoNodeDaemonSet) {
		return ErrLabelsOnlyOnInstall(ComponentCalicoNode + " podTemplateSpec")
	} else {
		EnsureCalicoNodePodTemplateLabelsNotNil(install)
		if err := mergeLabels(ComponentCalicoNode, install.Spec.CalicoNodeDaemonSet.Spec.Template.Metadata.Labels, labels); err != nil {
			return err
		}
	}

	if c.kubeControllers == nil {
		if hasAnnotations(install.Spec.CalicoKubeControllersDeployment) {
			return ErrAnnotationsOnlyOnInstall(ComponentKubeControllers)
		}
		if hasPodTemplateAnnotations(install.Spec.CalicoKubeControllersDeployment) {
			return ErrAnnotationsOnlyOnInstall(ComponentKubeControllers + " podTemplateSpec")
		}
	} else {
		// Handle labels
		labels = removeStandardOperatorLabels(c.kubeControllers.Labels)
		if len(labels) == 0 && hasLabels(install.Spec.CalicoKubeControllersDeployment) {
			return ErrLabelsOnlyOnInstall(ComponentKubeControllers)
		} else {
			EnsureKubeControllersLabelsNotNil(install)
			if err := mergeLabels(ComponentKubeControllers, install.Spec.CalicoKubeControllersDeployment.Metadata.Labels, labels); err != nil {
				return err
			}
		}
		// Handle the pod template spec labels
		labels = removeStandardOperatorLabels(c.kubeControllers.Spec.Template.Labels)
		if len(labels) == 0 && hasPodTemplateLabels(install.Spec.CalicoKubeControllersDeployment) {
			return ErrLabelsOnlyOnInstall(ComponentKubeControllers + " podTemplateSpec")
		} else {
			EnsureKubeControllersPodTemplateLabelsNotNil(install)
			if err := mergeLabels(ComponentKubeControllers, install.Spec.CalicoKubeControllersDeployment.Spec.Template.Metadata.Labels, labels); err != nil {
				return err
			}
		}
	}

	if c.typha == nil {
		if hasLabels(install.Spec.TyphaDeployment) {
			return ErrLabelsOnlyOnInstall(ComponentTypha)
		}
		if hasPodTemplateLabels(install.Spec.TyphaDeployment) {
			return ErrLabelsOnlyOnInstall(ComponentTypha + " podTemplateSpec")
		}
	} else {
		// Handle labels
		labels = removeStandardOperatorLabels(c.typha.Labels)
		if len(labels) == 0 && hasLabels(install.Spec.TyphaDeployment) {
			return ErrLabelsOnlyOnInstall(ComponentTypha)
		} else {
			EnsureTyphaLabelsNotNil(install)
			if err := mergeLabels(ComponentTypha, install.Spec.TyphaDeployment.Metadata.Labels, labels); err != nil {
				return err
			}
		}
		// Handle the pod template spec labels
		labels = removeStandardOperatorLabels(c.typha.Spec.Template.Labels)
		if len(labels) == 0 && hasPodTemplateLabels(install.Spec.TyphaDeployment) {
			return ErrLabelsOnlyOnInstall(ComponentTypha + " podTemplateSpec")
		} else {
			EnsureTyphaPodTemplateLabelsNotNil(install)
			if err := mergeLabels(ComponentTypha, install.Spec.TyphaDeployment.Spec.Template.Metadata.Labels, labels); err != nil {
				return err
			}
		}
	}

	return nil
}
