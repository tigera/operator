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
	"regexp"

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

// handleAnnotations is a migration handler that ensures the components' annotations are migrated to the install.
func handleAnnotations(c *components, install *operatorv1.Installation) error {
	// Remove the expected k8s annotations and copy the remaining annotations to the override field.
	annots := removeKubernetesAnnotations(c.node.Annotations, map[string]string{}, toBeIgnoredAnnotationKeyRegExps)

	if len(annots) == 0 {
		// Check if the component has no annotations but the install does.
		if install.Spec.CalicoNodeDaemonSet != nil {
			md := install.Spec.CalicoNodeDaemonSet.GetMetadata()
			if md != nil && len(md.Annotations) > 0 {
				return ErrAnnotationsOnlyOnInstall(ComponentCalicoNode)
			}
		}
	} else {
		ensureEmptyCalicoNodeDaemonSetMetadata(install)
		if install.Spec.CalicoNodeDaemonSet.Metadata.Annotations == nil {
			install.Spec.CalicoNodeDaemonSet.Metadata.Annotations = make(map[string]string)
		}
		// Verify that any annotations on the install exist on the component.
		for k, v := range install.Spec.CalicoNodeDaemonSet.Metadata.Annotations {
			if x, ok := annots[k]; !ok || x != v {
				return ErrIncompatibleAnnotation(k, ComponentCalicoNode)
			}
		}

		for k, v := range annots {
			// If a key already exists in the component's annotations in the install but values differ, return an error.
			if x, ok := install.Spec.CalicoNodeDaemonSet.Metadata.Annotations[k]; ok && x != v {
				return ErrIncompatibleAnnotation(k, ComponentCalicoNode)
			}
			install.Spec.CalicoNodeDaemonSet.Metadata.Annotations[k] = v
		}
	}
	// Handle the pod template spec annotations
	// Note that we don't handle "cluster-autoscaler.kubernetes.io/daemonset-pod" as that is set by some orchestrators.
	annots = removeKubernetesAnnotations(c.node.Spec.Template.Annotations, map[string]string{}, toBeIgnoredAnnotationKeyRegExps)

	if len(annots) == 0 {
		// Check if the component has no annotations but the install does.
		if install.Spec.CalicoNodeDaemonSet != nil &&
			install.Spec.CalicoNodeDaemonSet.Spec != nil &&
			install.Spec.CalicoNodeDaemonSet.Spec.Template != nil &&
			install.Spec.CalicoNodeDaemonSet.Spec.Template.Metadata != nil {
			if len(install.Spec.CalicoNodeDaemonSet.Spec.Template.Metadata.Annotations) > 0 {
				return ErrAnnotationsOnlyOnInstall(ComponentCalicoNode)
			}
		}
	} else {
		ensureEmptyCalicoNodeDaemonSetPodTemplateMetadata(install)
		if install.Spec.CalicoNodeDaemonSet.Spec.Template.Metadata.Annotations == nil {
			install.Spec.CalicoNodeDaemonSet.Spec.Template.Metadata.Annotations = make(map[string]string)
		}

		// Verify that any annotations on the install exist on the component.
		for k, v := range install.Spec.CalicoNodeDaemonSet.Spec.Template.Metadata.Annotations {
			if x, ok := annots[k]; !ok || x != v {
				return ErrIncompatibleAnnotation(k, ComponentCalicoNode+" podTemplateSpec")
			}
		}
		for k, v := range annots {
			// If a key already exists in the component's annotations in the install but values differ, return an error.
			if x, ok := install.Spec.CalicoNodeDaemonSet.Spec.Template.Metadata.Annotations[k]; ok && x != v {
				return ErrIncompatibleAnnotation(k, ComponentCalicoNode+" podTemplateSpec")
			}
			install.Spec.CalicoNodeDaemonSet.Spec.Template.Metadata.Annotations[k] = v
		}
	}

	// Check if the component has no annotations but the install does.
	checkKubeControllersAnnotsInstallOnly := func() error {
		if install.Spec.CalicoKubeControllersDeployment != nil {
			md := install.Spec.CalicoKubeControllersDeployment.GetMetadata()
			if md != nil && len(md.Annotations) > 0 {
				return ErrAnnotationsOnlyOnInstall(ComponentKubeControllers)
			}
		}
		return nil
	}
	checkKubeControllersPodTemplateAnnotsInstallOnly := func() error {
		if install.Spec.CalicoKubeControllersDeployment != nil &&
			install.Spec.CalicoKubeControllersDeployment.Spec != nil &&
			install.Spec.CalicoKubeControllersDeployment.Spec.Template != nil &&
			install.Spec.CalicoKubeControllersDeployment.Spec.Template.Metadata != nil {
			if len(install.Spec.CalicoKubeControllersDeployment.Spec.Template.Metadata.Annotations) > 0 {
				return ErrAnnotationsOnlyOnInstall(ComponentKubeControllers)
			}
		}
		return nil
	}

	if c.kubeControllers == nil {
		if err := checkKubeControllersAnnotsInstallOnly(); err != nil {
			return err
		}
		if err := checkKubeControllersPodTemplateAnnotsInstallOnly(); err != nil {
			return err
		}
	} else {
		annots = removeKubernetesAnnotations(c.kubeControllers.Annotations, map[string]string{}, toBeIgnoredAnnotationKeyRegExps)
		if len(annots) == 0 {
			if err := checkKubeControllersAnnotsInstallOnly(); err != nil {
				return err
			}
		} else {
			ensureEmptyCalicoKubeControllersDeploymentMetadata(install)
			if install.Spec.CalicoKubeControllersDeployment.Metadata.Annotations == nil {
				install.Spec.CalicoKubeControllersDeployment.Metadata.Annotations = make(map[string]string)
			}

			// Verify that any annotations on the install exist on the component.
			for k, v := range install.Spec.CalicoKubeControllersDeployment.Metadata.Annotations {
				if x, ok := annots[k]; !ok || x != v {
					return ErrIncompatibleAnnotation(k, ComponentKubeControllers)
				}
			}
			for k, v := range annots {
				// If a key already exists in the component's annotations in the install, then return an error.
				if x, ok := install.Spec.CalicoKubeControllersDeployment.Metadata.Annotations[k]; ok && x != v {
					return ErrIncompatibleAnnotation(k, ComponentKubeControllers)
				}
				install.Spec.CalicoKubeControllersDeployment.Metadata.Annotations[k] = v
			}
		}
		// Handle the pod template spec annotations
		// Note that we don't handle "cluster-autoscaler.kubernetes.io/daemonset-pod" as that is set by some orchestrators.
		annots = removeKubernetesAnnotations(c.kubeControllers.Spec.Template.Annotations, map[string]string{}, toBeIgnoredAnnotationKeyRegExps)
		if len(annots) == 0 {
			if err := checkKubeControllersPodTemplateAnnotsInstallOnly(); err != nil {
				return err
			}
		} else {
			ensureEmptyCalicoKubeControllersDeploymentPodTemplateMetadata(install)
			if install.Spec.CalicoKubeControllersDeployment.Spec.Template.Metadata.Annotations == nil {
				install.Spec.CalicoKubeControllersDeployment.Spec.Template.Metadata.Annotations = make(map[string]string)
			}
			// Verify that any annotations on the install exist on the component.
			for k, v := range install.Spec.CalicoKubeControllersDeployment.Spec.Template.Metadata.Annotations {
				if x, ok := annots[k]; !ok || x != v {
					return ErrIncompatibleAnnotation(k, ComponentKubeControllers+" podTemplateSpec")
				}
			}
			for k, v := range annots {
				// If a key already exists in the component's annotations in the install, then return an error.
				if x, ok := install.Spec.CalicoKubeControllersDeployment.Spec.Template.Metadata.Annotations[k]; ok && x != v {
					return ErrIncompatibleAnnotation(k, ComponentKubeControllers+" podTemplateSpec")
				}
				install.Spec.CalicoKubeControllersDeployment.Spec.Template.Metadata.Annotations[k] = v
			}
		}
	}

	checkTyphaAnnotsInstallOnly := func() error {
		if install.Spec.TyphaDeployment != nil {
			md := install.Spec.TyphaDeployment.GetMetadata()
			if md != nil && len(md.Annotations) > 0 {
				return ErrAnnotationsOnlyOnInstall(ComponentTypha)
			}
		}
		return nil
	}
	checkTyphaPodTemplateAnnotsInstallOnly := func() error {
		if install.Spec.TyphaDeployment != nil &&
			install.Spec.TyphaDeployment.Spec != nil &&
			install.Spec.TyphaDeployment.Spec.Template != nil &&
			install.Spec.TyphaDeployment.Spec.Template.Metadata != nil {
			if len(install.Spec.TyphaDeployment.Spec.Template.Metadata.Annotations) > 0 {
				return ErrAnnotationsOnlyOnInstall(ComponentTypha)
			}
		}
		return nil
	}
	if c.typha == nil {
		if err := checkTyphaAnnotsInstallOnly(); err != nil {
			return err
		}
		if err := checkTyphaPodTemplateAnnotsInstallOnly(); err != nil {
			return err
		}
	} else {
		annots = removeKubernetesAnnotations(c.typha.Annotations, map[string]string{}, toBeIgnoredAnnotationKeyRegExps)
		if len(annots) == 0 {
			if err := checkTyphaAnnotsInstallOnly(); err != nil {
				return err
			}
		} else {
			ensureEmptyTyphaDeploymentMetadata(install)
			if install.Spec.TyphaDeployment.Metadata.Annotations == nil {
				install.Spec.TyphaDeployment.Metadata.Annotations = make(map[string]string)
			}

			// Verify that any annotations on the install exist on the component.
			for k, v := range install.Spec.TyphaDeployment.Metadata.Annotations {
				if x, ok := annots[k]; !ok || x != v {
					return ErrIncompatibleAnnotation(k, ComponentTypha)
				}
			}
			for k, v := range annots {
				// If a key already exists in the component's annotations in the install, then return an error.
				if x, ok := install.Spec.TyphaDeployment.Metadata.Annotations[k]; ok && x != v {
					return ErrIncompatibleAnnotation(k, ComponentTypha)
				}
				install.Spec.TyphaDeployment.Metadata.Annotations[k] = v
			}
		}
		// Handle the pod template spec annotations
		annots = removeKubernetesAnnotations(c.typha.Spec.Template.Annotations, map[string]string{}, toBeIgnoredAnnotationKeyRegExps)
		if len(annots) == 0 {
			if err := checkTyphaPodTemplateAnnotsInstallOnly(); err != nil {
				return err
			}
		} else {
			ensureEmptyTyphaDeploymentPodTemplateMetadata(install)
			if install.Spec.TyphaDeployment.Spec.Template.Metadata.Annotations == nil {
				install.Spec.TyphaDeployment.Spec.Template.Metadata.Annotations = make(map[string]string)
			}
			// Verify that any annotations on the install exist on the component.
			for k, v := range install.Spec.TyphaDeployment.Spec.Template.Metadata.Annotations {
				if x, ok := annots[k]; !ok || x != v {
					return ErrIncompatibleAnnotation(k, ComponentTypha+" podTemplateSpec")
				}
			}
			for k, v := range annots {
				// If a key already exists in the component's annotations in the install, then return an error.
				if x, ok := install.Spec.TyphaDeployment.Spec.Template.Metadata.Annotations[k]; ok && x != v {
					return ErrIncompatibleAnnotation(k, ComponentTypha+" podTemplateSpec")
				}
				install.Spec.TyphaDeployment.Spec.Template.Metadata.Annotations[k] = v
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

// handleLabels is a migration handler that ensures the components' labels are migrated to the install.
func handleLabels(c *components, install *operatorv1.Installation) error {
	// Remove the standard labels set by the operator
	labels := removeStandardOperatorLabels(c.node.Labels)

	if len(labels) == 0 {
		// Check if the component has no labels but the install does.
		if install.Spec.CalicoNodeDaemonSet != nil {
			md := install.Spec.CalicoNodeDaemonSet.GetMetadata()
			if md != nil && len(md.Labels) > 0 {
				return ErrLabelsOnlyOnInstall(ComponentCalicoNode)
			}
		}
	} else {
		ensureEmptyCalicoNodeDaemonSetMetadata(install)
		if install.Spec.CalicoNodeDaemonSet.Metadata.Labels == nil {
			install.Spec.CalicoNodeDaemonSet.Metadata.Labels = make(map[string]string)
		}
		// Verify that any labels on the install exist on the component.
		for k, v := range install.Spec.CalicoNodeDaemonSet.Metadata.Labels {
			if x, ok := labels[k]; !ok || x != v {
				return ErrIncompatibleLabel(k, ComponentCalicoNode)
			}
		}

		for k, v := range labels {
			// If a key already exists in the component's labels in the install but values differ, return an error.
			if x, ok := install.Spec.CalicoNodeDaemonSet.Metadata.Labels[k]; ok && x != v {
				return ErrIncompatibleLabel(k, ComponentCalicoNode)
			}
			install.Spec.CalicoNodeDaemonSet.Metadata.Labels[k] = v
		}
	}

	// Remove the standard labels set by the operator
	labels = removeStandardOperatorLabels(c.node.Spec.Template.Labels)

	if len(labels) == 0 {
		// Check if the component has no annotations but the install does.
		if install.Spec.CalicoNodeDaemonSet != nil &&
			install.Spec.CalicoNodeDaemonSet.Spec != nil &&
			install.Spec.CalicoNodeDaemonSet.Spec.Template != nil &&
			install.Spec.CalicoNodeDaemonSet.Spec.Template.Metadata != nil {
			if len(install.Spec.CalicoNodeDaemonSet.Spec.Template.Metadata.Labels) > 0 {
				return ErrLabelsOnlyOnInstall(ComponentCalicoNode)
			}
		}
	} else {
		ensureEmptyCalicoNodeDaemonSetPodTemplateMetadata(install)
		if install.Spec.CalicoNodeDaemonSet.Spec.Template.Metadata.Labels == nil {
			install.Spec.CalicoNodeDaemonSet.Spec.Template.Metadata.Labels = make(map[string]string)
		}

		// Verify that any labels on the install exist on the component.
		for k, v := range install.Spec.CalicoNodeDaemonSet.Spec.Template.Metadata.Labels {
			if x, ok := labels[k]; !ok || x != v {
				return ErrIncompatibleLabel(k, ComponentCalicoNode+" podTemplateSpec")
			}
		}
		for k, v := range labels {
			// If a key already exists in the component's labels in the install but values differ, return an error.
			if x, ok := install.Spec.CalicoNodeDaemonSet.Spec.Template.Metadata.Labels[k]; ok && x != v {
				return ErrIncompatibleLabel(k, ComponentCalicoNode+" podTemplateSpec")
			}
			install.Spec.CalicoNodeDaemonSet.Spec.Template.Metadata.Labels[k] = v
		}
	}

	// Check if the component has no labels but the install does.
	checkKubeControllersLabelsInstallOnly := func() error {
		if install.Spec.CalicoKubeControllersDeployment != nil {
			md := install.Spec.CalicoKubeControllersDeployment.GetMetadata()
			if md != nil && len(md.Labels) > 0 {
				return ErrLabelsOnlyOnInstall(ComponentKubeControllers)
			}
		}
		return nil
	}
	checkKubeControllersPodTemplateLabelsInstallOnly := func() error {
		if install.Spec.CalicoKubeControllersDeployment != nil &&
			install.Spec.CalicoKubeControllersDeployment.Spec != nil &&
			install.Spec.CalicoKubeControllersDeployment.Spec.Template != nil &&
			install.Spec.CalicoKubeControllersDeployment.Spec.Template.Metadata != nil {
			if len(install.Spec.CalicoKubeControllersDeployment.Spec.Template.Metadata.Labels) > 0 {
				return ErrLabelsOnlyOnInstall(ComponentKubeControllers)
			}
		}
		return nil
	}

	if c.kubeControllers == nil {
		if err := checkKubeControllersLabelsInstallOnly(); err != nil {
			return err
		}
		if err := checkKubeControllersPodTemplateLabelsInstallOnly(); err != nil {
			return err
		}
	} else {
		// Remove the standard labels set by the operator
		labels = removeStandardOperatorLabels(c.kubeControllers.Labels)
		if len(labels) == 0 {
			if err := checkKubeControllersLabelsInstallOnly(); err != nil {
				return err
			}
		} else {
			ensureEmptyCalicoKubeControllersDeploymentMetadata(install)
			if install.Spec.CalicoKubeControllersDeployment.Metadata.Labels == nil {
				install.Spec.CalicoKubeControllersDeployment.Metadata.Labels = make(map[string]string)
			}

			// Verify that any labels on the install exist on the component.
			for k, v := range install.Spec.CalicoKubeControllersDeployment.Metadata.Labels {
				if x, ok := labels[k]; !ok || x != v {
					return ErrIncompatibleLabel(k, ComponentKubeControllers)
				}
			}
			for k, v := range labels {
				// If a key already exists in the component's labels in the install, then return an error.
				if x, ok := install.Spec.CalicoKubeControllersDeployment.Metadata.Labels[k]; ok && x != v {
					return ErrIncompatibleLabel(k, ComponentKubeControllers)
				}
				install.Spec.CalicoKubeControllersDeployment.Metadata.Labels[k] = v
			}
		}
		// Handle the pod template spec annotations
		// Remove the standard labels set by the operator
		labels = removeStandardOperatorLabels(c.kubeControllers.Spec.Template.Labels)
		if len(labels) == 0 {
			if err := checkKubeControllersPodTemplateLabelsInstallOnly(); err != nil {
				return err
			}
		} else {
			ensureEmptyCalicoKubeControllersDeploymentPodTemplateMetadata(install)
			if install.Spec.CalicoKubeControllersDeployment.Spec.Template.Metadata.Labels == nil {
				install.Spec.CalicoKubeControllersDeployment.Spec.Template.Metadata.Labels = make(map[string]string)
			}
			// Verify that any labels on the install exist on the component.
			for k, v := range install.Spec.CalicoKubeControllersDeployment.Spec.Template.Metadata.Labels {
				if x, ok := labels[k]; !ok || x != v {
					return ErrIncompatibleLabel(k, ComponentKubeControllers+" podTemplateSpec")
				}
			}
			for k, v := range labels {
				// If a key already exists in the component's labels in the install, then return an error.
				if x, ok := install.Spec.CalicoKubeControllersDeployment.Spec.Template.Metadata.Labels[k]; ok && x != v {
					return ErrIncompatibleLabel(k, ComponentKubeControllers+" podTemplateSpec")
				}
				install.Spec.CalicoKubeControllersDeployment.Spec.Template.Metadata.Labels[k] = v
			}
		}
	}

	checkTyphaLabelsInstallOnly := func() error {
		if install.Spec.TyphaDeployment != nil {
			md := install.Spec.TyphaDeployment.GetMetadata()
			if md != nil && len(md.Labels) > 0 {
				return ErrLabelsOnlyOnInstall(ComponentTypha)
			}
		}
		return nil
	}
	checkTyphaPodTemplateLabelsInstallOnly := func() error {
		if install.Spec.TyphaDeployment != nil &&
			install.Spec.TyphaDeployment.Spec != nil &&
			install.Spec.TyphaDeployment.Spec.Template != nil &&
			install.Spec.TyphaDeployment.Spec.Template.Metadata != nil {
			if len(install.Spec.TyphaDeployment.Spec.Template.Metadata.Labels) > 0 {
				return ErrLabelsOnlyOnInstall(ComponentTypha)
			}
		}
		return nil
	}
	if c.typha == nil {
		if err := checkTyphaLabelsInstallOnly(); err != nil {
			return err
		}
		if err := checkTyphaPodTemplateLabelsInstallOnly(); err != nil {
			return err
		}
	} else {
		// Remove the standard labels set by the operator
		labels = removeStandardOperatorLabels(c.typha.Labels)
		if len(labels) == 0 {
			if err := checkTyphaLabelsInstallOnly(); err != nil {
				return err
			}
		} else {
			ensureEmptyTyphaDeploymentMetadata(install)
			if install.Spec.TyphaDeployment.Metadata.Labels == nil {
				install.Spec.TyphaDeployment.Metadata.Labels = make(map[string]string)
			}

			// Verify that any labels on the install exist on the component.
			for k, v := range install.Spec.TyphaDeployment.Metadata.Labels {
				if x, ok := labels[k]; !ok || x != v {
					return ErrIncompatibleLabel(k, ComponentTypha)
				}
			}
			for k, v := range labels {
				// If a key already exists in the component's labels in the install, then return an error.
				if x, ok := install.Spec.TyphaDeployment.Metadata.Labels[k]; ok && x != v {
					return ErrIncompatibleLabel(k, ComponentTypha)
				}
				install.Spec.TyphaDeployment.Metadata.Labels[k] = v
			}
		}
		// Handle the pod template spec annotations
		// Remove the standard labels set by the operator
		labels = removeStandardOperatorLabels(c.typha.Spec.Template.Labels)
		if len(labels) == 0 {
			if err := checkTyphaPodTemplateLabelsInstallOnly(); err != nil {
				return err
			}
		} else {
			ensureEmptyTyphaDeploymentPodTemplateMetadata(install)
			if install.Spec.TyphaDeployment.Spec.Template.Metadata.Labels == nil {
				install.Spec.TyphaDeployment.Spec.Template.Metadata.Labels = make(map[string]string)
			}
			// Verify that any labels on the install exist on the component.
			for k, v := range install.Spec.TyphaDeployment.Spec.Template.Metadata.Labels {
				if x, ok := labels[k]; !ok || x != v {
					return ErrIncompatibleLabel(k, ComponentTypha+" podTemplateSpec")
				}
			}
			for k, v := range labels {
				// If a key already exists in the component's labels in the install, then return an error.
				if x, ok := install.Spec.TyphaDeployment.Spec.Template.Metadata.Labels[k]; ok && x != v {
					return ErrIncompatibleLabel(k, ComponentTypha+" podTemplateSpec")
				}
				install.Spec.TyphaDeployment.Spec.Template.Metadata.Labels[k] = v
			}
		}
	}

	return nil
}
