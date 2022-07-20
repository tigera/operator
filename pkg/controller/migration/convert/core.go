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
	"regexp"
	"strconv"
	"strings"

	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/kubecontrollers"

	operatorv1 "github.com/tigera/operator/api/v1"
	corev1 "k8s.io/api/core/v1"
)

var toBeIgnoredAnnotationKeyRegExps []*regexp.Regexp

func init() {
	log.Info("Compiling regular expressions for annotation keys to be ignored...")
	toBeIgnoredAnnotationKeyRegExps = make([]*regexp.Regexp, 0)
	for _, annotationKey := range []string{"^kubectl\\.kubernetes\\.io"} {
		annotationKeyRegexp, err := regexp.Compile(annotationKey)
		if err != nil {
			log.Error(fmt.Errorf("%s is not a valid regular expression", annotationKey), "Error when removing expected annotations")
			continue
		}
		toBeIgnoredAnnotationKeyRegExps = append(toBeIgnoredAnnotationKeyRegExps, annotationKeyRegexp)
	}
}

func handleCore(c *components, install *operatorv1.Installation) error {
	dsType, err := c.node.getEnv(ctx, c.client, "calico-node", "DATASTORE_TYPE")
	if err != nil {
		return err
	}
	if dsType != nil && *dsType != "kubernetes" {
		return ErrIncompatibleCluster{
			err:       "only DATASTORE_TYPE=kubernetes is supported",
			component: ComponentCalicoNode,
		}
	}

	// Convert any deprecated ComponentResources to the new component override fields.
	convertComponentResources(install)

	// node container resources
	for _, container := range c.node.Spec.Template.Spec.Containers {
		if len(container.Resources.Limits) > 0 || len(container.Resources.Requests) > 0 {
			if err = addContainerResources(install, "calico-node", container.Name, &container.Resources); err != nil {
				return err
			}
		}
	}

	// node init container resources
	for _, initContainer := range c.node.Spec.Template.Spec.InitContainers {
		if len(initContainer.Resources.Limits) > 0 || len(initContainer.Resources.Requests) > 0 {
			if err = addInitContainerResources(install, "calico-node", initContainer.Name, &initContainer.Resources); err != nil {
				return err
			}
		}
	}

	// kube-controllers container resources
	if c.kubeControllers != nil {
		for _, container := range c.kubeControllers.Spec.Template.Spec.Containers {
			if len(container.Resources.Limits) > 0 || len(container.Resources.Requests) > 0 {
				if err = addContainerResources(install, "calico-kube-controllers", container.Name, &container.Resources); err != nil {
					return err
				}
			}
		}
	}
	// Note: kube-controllers doesn't have init containers.

	// typha container resources. typha is optional so check for nil first
	if c.typha != nil {
		for _, container := range c.typha.Spec.Template.Spec.Containers {
			if len(container.Resources.Limits) > 0 || len(container.Resources.Requests) > 0 {
				if err = addContainerResources(install, "calico-typha", container.Name, &container.Resources); err != nil {
					return err
				}
			}
		}
		for _, initContainer := range c.typha.Spec.Template.Spec.InitContainers {
			if len(initContainer.Resources.Limits) > 0 || len(initContainer.Resources.Requests) > 0 {
				if err = addInitContainerResources(install, "calico-typha", initContainer.Name, &initContainer.Resources); err != nil {
					return err
				}
			}
		}
	}

	if c.kubeControllers != nil {
		if err := assertEnv(ctx, c.client, c.kubeControllers.Spec.Template.Spec, ComponentKubeControllers, containerKubeControllers, "ENABLED_CONTROLLERS", "node"); err != nil {
			return err
		}

		if err := assertEnv(ctx, c.client, c.kubeControllers.Spec.Template.Spec, ComponentKubeControllers, containerKubeControllers, "AUTO_HOST_ENDPOINTS", "disabled"); err != nil {
			return err
		}
	}

	// node update-strategy
	install.Spec.NodeUpdateStrategy = c.node.Spec.UpdateStrategy

	// alp
	vol := getVolume(c.node.Spec.Template.Spec, "flexvol-driver-host")
	if vol != nil {
		// prefer user-defined flexvolpath over detected value
		if install.Spec.FlexVolumePath == "" {
			if vol.HostPath == nil {
				return ErrIncompatibleCluster{
					err:       "volume 'flexvol-driver-host' must be a HostPath",
					component: ComponentCalicoNode,
					fix:       "remove the 'flexvol-driver-host' volume or convert it to type hostPath",
				}
			}
			if fv := getContainer(c.node.Spec.Template.Spec, "flexvol-driver"); fv == nil {
				return ErrIncompatibleCluster{
					err:       "detected 'flexvol-driver-host' volume but no 'flexvol-driver' init container",
					component: ComponentCalicoNode,
					fix:       "remove the 'flexvol-driver-host' volume or restore the 'flexvol-driver' init container",
				}
			}
			install.Spec.FlexVolumePath = vol.HostPath.Path
		}
	} else {
		// verify that no flexvol container is set
		if fv := getContainer(c.node.Spec.Template.Spec, "flexvol-driver"); fv != nil {
			return ErrIncompatibleCluster{
				err:       "detected 'flexvol-driver' init container but no 'flexvol-driver-host' volume",
				component: ComponentCalicoNode,
				fix:       "restore the 'flexvol-driver-host' volume or remove the 'flexvol-driver' init container",
			}
		}
		install.Spec.FlexVolumePath = "None"
	}

	// Volumes for lib-modules, xtables-lock, var-run-calico, var-lib-calico, or policysync have been changed
	if err := checkNodeHostPathVolume(c.node.Spec.Template.Spec, "lib-modules", "/lib/modules"); err != nil {
		return err
	}
	if err := checkNodeHostPathVolume(c.node.Spec.Template.Spec, "var-run-calico", "/var/run/calico"); err != nil {
		return err
	}
	if err := checkNodeHostPathVolume(c.node.Spec.Template.Spec, "var-lib-calico", "/var/lib/calico"); err != nil {
		return err
	}
	if err := checkNodeHostPathVolume(c.node.Spec.Template.Spec, "xtables-lock", "/run/xtables.lock"); err != nil {
		return err
	}
	if c.cni.CalicoConfig != nil {
		if err := checkNodeHostPathVolume(c.node.Spec.Template.Spec, "cni-bin-dir", "/opt/cni/bin"); err != nil {
			return err
		}
		if err := checkNodeHostPathVolume(c.node.Spec.Template.Spec, "cni-net-dir", "/etc/cni/net.d"); err != nil {
			return err
		}
	}

	// check that nodename is a ref
	e, err := c.node.getEnvVar("calico-node", "NODENAME")
	if err != nil {
		return err
	}
	if e != nil && (e.ValueFrom == nil || e.ValueFrom.FieldRef == nil || e.ValueFrom.FieldRef.FieldPath != "spec.nodeName") {
		return ErrIncompatibleCluster{
			err:       "NODENAME on 'calico-node' container must be unset or be a FieldRef to 'spec.nodeName'",
			component: ComponentCalicoNode,
			fix:       "remove the NODENAME env var or convert it to a fieldRef with value 'spec.nodeName'",
		}
	}

	if cni := getContainer(c.node.Spec.Template.Spec, "install-cni"); cni != nil {
		e, err = c.node.getEnvVar("install-cni", "KUBERNETES_NODE_NAME")
		if err != nil {
			return err
		}
		if e != nil && (e.ValueFrom == nil || e.ValueFrom.FieldRef == nil || e.ValueFrom.FieldRef.FieldPath != "spec.nodeName") {
			return ErrIncompatibleCluster{
				err:       "KUBERNETES_NODE_NAME on 'install-cni' container must be unset or be a FieldRef to 'spec.nodeName'",
				component: ComponentCalicoNode,
				fix:       "remove the KUBERNETES_NODE_NAME env var or convert it to a fieldRef with value 'spec.nodeName'",
			}
		}

		if err := c.node.assertEnv(ctx, c.client, containerInstallCNI, "CNI_CONF_NAME", "10-calico.conflist"); err != nil {
			return err
		}
	}

	c.node.ignoreEnv("calico-node", "WAIT_FOR_DATASTORE")
	c.node.ignoreEnv("calico-node", "CLUSTER_TYPE")
	c.node.ignoreEnv("calico-node", "CALICO_DISABLE_FILE_LOGGING")
	c.node.ignoreEnv("calico-node", "CALICO_IPV4POOL_IPIP")
	c.node.ignoreEnv("calico-node", "CALICO_IPV4POOL_VXLAN")
	c.node.ignoreEnv("calico-node", "CALICO_IPV6POOL_CIDR")
	c.node.ignoreEnv("calico-node", "CALICO_IPV6POOL_VXLAN")
	c.node.ignoreEnv("calico-node", "FELIX_LOGSEVERITYSCREEN")
	c.node.ignoreEnv("calico-node", "FELIX_HEALTHENABLED")
	c.node.ignoreEnv("calico-node", "FELIX_USAGEREPORTINGENABLED")
	c.node.ignoreEnv("calico-node", "FELIX_TYPHAK8SSERVICENAME")
	c.node.ignoreEnv("calico-node", "FELIX_LOGSEVERITYSYS")
	c.node.ignoreEnv("upgrade-ipam", "KUBERNETES_NODE_NAME")
	c.node.ignoreEnv("upgrade-ipam", "CALICO_NETWORKING_BACKEND")
	c.node.ignoreEnv("install-cni", "SLEEP")

	return nil
}

// checkNodeHostPathVolume returns an error if a hostpath with the passed in name and path does not exist in a given podspec.
func checkNodeHostPathVolume(spec corev1.PodSpec, name, path string) error {
	v := getVolume(spec, name)
	if v == nil || v.HostPath == nil || v.HostPath.Path != path {
		return ErrIncompatibleCluster{
			err:       fmt.Sprintf("missing expected volume '%s' with hostPath '%s'", name, path),
			component: ComponentCalicoNode,
			fix:       fmt.Sprintf("add the expected volume to %s", ComponentCalicoNode),
		}
	}
	return nil
}

// getContainerResourceOverride gets the container resources override from the Installation for the given component's container.
// Note: calico-windows-upgrade is not available in a manifest install so is not handled here.
func getContainerResourceOverride(install *operatorv1.Installation, componentName, containerName string) (*corev1.ResourceRequirements, bool) {
	switch componentName {
	case "calico-node":
		// Check if the component overrides is set for this component and find the container override if it exists.
		if install.Spec.CalicoNodeDaemonSet != nil {
			cs := install.Spec.CalicoNodeDaemonSet.GetContainers()
			for _, c := range cs {
				if c.Name == containerName {
					return &c.Resources, true
				}
			}
		}
	case "calico-typha":
		if install.Spec.TyphaDeployment != nil {
			cs := install.Spec.TyphaDeployment.GetContainers()
			for _, c := range cs {
				if c.Name == containerName {
					return &c.Resources, true
				}
			}
		}
	case "calico-kube-controllers":
		if install.Spec.CalicoKubeControllersDeployment != nil {
			cs := install.Spec.CalicoKubeControllersDeployment.GetContainers()
			for _, c := range cs {
				if c.Name == containerName {
					return &c.Resources, true
				}
			}
		}
	}

	return nil, false
}

// getInitContainerResourceOverride gets the init container resources override from the Installation for the given component's init container.
// Note: calico-kube-controllers does not have init containers so is not handled here.
// Note: calico-windows-upgrade is not available in a manifest install so is not handled here.
func getInitContainerResourceOverride(install *operatorv1.Installation, componentName, initContainerName string) (*corev1.ResourceRequirements, bool) {
	switch componentName {
	case "calico-node":
		// Check if the component overrides is set for this component and find the init container override if it exists.
		if install.Spec.CalicoNodeDaemonSet != nil {
			cs := install.Spec.CalicoNodeDaemonSet.GetInitContainers()
			for _, c := range cs {
				if c.Name == initContainerName {
					return &c.Resources, true
				}
			}
		}

	case "calico-typha":
		if install.Spec.TyphaDeployment != nil {
			cs := install.Spec.TyphaDeployment.GetInitContainers()
			for _, c := range cs {
				if c.Name == initContainerName {
					return &c.Resources, true
				}
			}
		}
	}

	return nil, false
}

// convertComponentResources takes an installation and converts any deprecated ComponentResources in it to the new
// component resource override fields. The ComponentResources field will be nil after the conversion.
func convertComponentResources(install *operatorv1.Installation) {
	// For each ComponentResource we find, create a component resource override container for it if it doesn't already exist
	// After processing all ComponentResources, we can remove them.
	for _, compRes := range install.Spec.ComponentResources {
		switch compRes.ComponentName {
		case operatorv1.ComponentNameNode:
			// Ensure the override field is non nil
			ensureEmptyCalicoNodeDaemonSetContainers(install)

			// If the container already exists, do nothing since this container override takes precedence.
			var found bool
			for _, c := range install.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.Containers {
				if c.Name == render.CalicoNodeObjectName {
					found = true
				}
			}

			// If the container is not already specified, create the override container entry for it.
			if !found {
				container := operatorv1.CalicoNodeDaemonSetContainer{
					Name:      render.CalicoNodeObjectName,
					Resources: compRes.ResourceRequirements,
				}
				install.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.Containers = append(install.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.Containers, container)
			}
		case operatorv1.ComponentNameTypha:
			// Ensure the override field is non nil
			ensureEmptyTyphaDeploymentContainers(install)

			// If the container already exists, do nothing since this container override takes precedence.
			var found bool
			for _, c := range install.Spec.TyphaDeployment.Spec.Template.Spec.Containers {
				if c.Name == render.TyphaContainerName {
					found = true
				}
			}

			// If the container is not already specified, create the override container entry for it.
			if !found {
				container := operatorv1.TyphaDeploymentContainer{
					Name:      render.TyphaContainerName,
					Resources: compRes.ResourceRequirements,
				}
				install.Spec.TyphaDeployment.Spec.Template.Spec.Containers = append(install.Spec.TyphaDeployment.Spec.Template.Spec.Containers, container)
			}
		case operatorv1.ComponentNameKubeControllers:
			// Ensure the override field is non nil
			ensureEmptyCalicoKubeControllersDeploymentContainers(install)

			// If the container already exists, do nothing since this container override takes precedence.
			var found bool
			for _, c := range install.Spec.CalicoKubeControllersDeployment.Spec.Template.Spec.Containers {
				if c.Name == kubecontrollers.KubeController {
					found = true
				}
			}

			// If the container is not already specified, create the override container entry for it.
			if !found {
				container := operatorv1.CalicoKubeControllersDeploymentContainer{
					Name:      kubecontrollers.KubeController,
					Resources: compRes.ResourceRequirements,
				}
				install.Spec.CalicoKubeControllersDeployment.Spec.Template.Spec.Containers = append(install.Spec.CalicoKubeControllersDeployment.Spec.Template.Spec.Containers, container)
			}
		}
	}

	// Lastly, clear out the ComponentResources slice.
	install.Spec.ComponentResources = nil
}

// addContainerResources adds the resources for the specified component container if none was previously set. If the Installation
// already had a resource for the component container then they are compared and if they are different then an error is returned.
// If the component container resource is added to the Installation or the existing one matches then nil is returned.
func addContainerResources(install *operatorv1.Installation, componentName, containerName string, resources *corev1.ResourceRequirements) error {
	// If resources already exist for this component container, verify that they equal the container's existing resources.
	if existingResources, found := getContainerResourceOverride(install, componentName, containerName); found {
		if !reflect.DeepEqual(existingResources, resources) {
			return ErrIncompatibleCluster{
				err:       fmt.Sprintf("Resources for the component container %q did not match between Installation and migration source", containerName),
				component: componentName,
				fix:       "remove the component's container resources from your Installation resource, or remove them from the currently installed component",
			}
		}
		return nil
	}

	// Create a container override using the resources and append it to the component resource override containers' field.
	// Note: calico-windows-upgrade is not available in a manifest install so is not handled here.
	switch componentName {
	case render.CalicoNodeObjectName:
		container := operatorv1.CalicoNodeDaemonSetContainer{Name: containerName, Resources: resources}
		ensureEmptyCalicoNodeDaemonSetContainers(install)
		install.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.Containers = append(install.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.Containers, container)
	case kubecontrollers.KubeController:
		container := operatorv1.CalicoKubeControllersDeploymentContainer{Name: containerName, Resources: resources}
		ensureEmptyCalicoKubeControllersDeploymentContainers(install)
		install.Spec.CalicoKubeControllersDeployment.Spec.Template.Spec.Containers = append(install.Spec.CalicoKubeControllersDeployment.Spec.Template.Spec.Containers, container)
	case render.TyphaContainerName:
		container := operatorv1.TyphaDeploymentContainer{Name: containerName, Resources: resources}
		ensureEmptyTyphaDeploymentContainers(install)
		install.Spec.TyphaDeployment.Spec.Template.Spec.Containers = append(install.Spec.TyphaDeployment.Spec.Template.Spec.Containers, container)
	}

	return nil
}

// addInitContainerResources adds the resources for the specified component init container if none was previously set. If the Installation
// already had a resource for the component init container then they are compared and if they are different then an error is returned.
// If the component init container resource is added to the Installation or the existing one matches then nil is returned.
func addInitContainerResources(install *operatorv1.Installation, componentName, initContainerName string, resources *corev1.ResourceRequirements) error {
	// If resources already exist for this component init container, verify that they equal the container's existing resources.
	if existingResources, found := getInitContainerResourceOverride(install, componentName, initContainerName); found {
		if !reflect.DeepEqual(existingResources, resources) {
			return ErrIncompatibleCluster{
				err:       fmt.Sprintf("Resources for the component init container %q did not match between Installation and migration source", initContainerName),
				component: componentName,
				fix:       "remove the component's init container resources from your Installation resource, or remove them from the currently installed component",
			}
		}
		return nil
	}

	// Create an init container override using the resources and append it to the component resource override init containers' field.
	// Note: calico-kube-controllers does not have init containers, and calico-windows-upgrade is not available in manifest installs.
	switch componentName {
	case render.CalicoNodeObjectName:
		container := operatorv1.CalicoNodeDaemonSetInitContainer{Name: initContainerName, Resources: resources}
		ensureEmptyCalicoNodeDaemonSetInitContainers(install)
		install.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.InitContainers = append(install.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.InitContainers, container)
	case render.TyphaContainerName:
		container := operatorv1.TyphaDeploymentInitContainer{Name: initContainerName, Resources: resources}
		ensureEmptyTyphaDeploymentInitContainers(install)
		install.Spec.TyphaDeployment.Spec.Template.Spec.InitContainers = append(install.Spec.TyphaDeployment.Spec.Template.Spec.InitContainers, container)
	}

	return nil
}

// handleNodeSelectors is a migration handler which ensures that nodeSelectors are set as expected.
// In general, setting custom nodeSelectors and nodeAffinity for components is not supported.
// The exception to this is the calico-node nodeSelector, which is migrated into the
// ControlPlaneNodeSelector field.
func handleNodeSelectors(c *components, install *operatorv1.Installation) error {
	// check calico-node nodeSelectors
	if c.node.Spec.Template.Spec.Affinity != nil {
		if !(install.Spec.KubernetesProvider == operatorv1.ProviderAKS && reflect.DeepEqual(c.node.Spec.Template.Spec.Affinity, &corev1.Affinity{
			NodeAffinity: &corev1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
					NodeSelectorTerms: []corev1.NodeSelectorTerm{{
						MatchExpressions: []corev1.NodeSelectorRequirement{{
							Key:      "type",
							Operator: corev1.NodeSelectorOpNotIn,
							Values:   []string{"virtual-kubelet"},
						}},
					}},
				},
			},
		})) && !(install.Spec.KubernetesProvider == operatorv1.ProviderEKS && reflect.DeepEqual(c.node.Spec.Template.Spec.Affinity, &corev1.Affinity{
			NodeAffinity: &corev1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
					NodeSelectorTerms: []corev1.NodeSelectorTerm{{
						MatchExpressions: []corev1.NodeSelectorRequirement{{
							Key:      "eks.amazonaws.com/compute-type",
							Operator: corev1.NodeSelectorOpNotIn,
							Values:   []string{"fargate"},
						}},
					}},
				},
			},
		})) {
			return ErrIncompatibleCluster{
				err:       "node affinity not supported for calico-node daemonset",
				component: ComponentCalicoNode,
				fix:       "remove the affinity",
			}
		}
	}
	nodeSel := removeOSNodeSelectors(c.node.Spec.Template.Spec.NodeSelector)
	delete(nodeSel, "projectcalico.org/operator-node-migration")
	if len(nodeSel) > 0 {
		// raise error unless the only nodeSelector is the  calico-node migration nodeSelector
		return ErrIncompatibleCluster{
			err:       fmt.Sprintf("unsupported nodeSelector for calico-node daemonset: %v", nodeSel),
			component: ComponentCalicoNode,
			fix:       "remove the nodeSelector",
		}

	}

	// check typha nodeSelectors
	if c.typha != nil {
		// we can migrate typha affinities provided they are a NodeAffinity for Preferred.
		if aff := c.typha.Spec.Template.Spec.Affinity; aff != nil {
			if aff.PodAffinity != nil || aff.PodAntiAffinity != nil {
				return ErrIncompatibleCluster{
					err:       "pod affinity and antiAffinity not supported for typha deployment",
					component: ComponentTypha,
					fix:       "remove the affinity",
				}
			}
			if aff.NodeAffinity != nil {
				if aff.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution != nil {
					return ErrIncompatibleCluster{
						err:       "nodeAffinity 'RequiredDuringSchedulingIgnoredDuringExecution' not supported on Typha.",
						component: ComponentTypha,
						fix:       "remove the affinity",
					}
				}
				install.Spec.TyphaAffinity = &operatorv1.TyphaAffinity{
					NodeAffinity: &operatorv1.NodeAffinity{
						PreferredDuringSchedulingIgnoredDuringExecution: aff.NodeAffinity.PreferredDuringSchedulingIgnoredDuringExecution,
					},
				}
			}
		}
		if nodeSel := removeOSNodeSelectors(c.typha.Spec.Template.Spec.NodeSelector); len(nodeSel) != 0 {
			return ErrIncompatibleCluster{
				err:       fmt.Sprintf("invalid nodeSelector for typha deployment: %v", nodeSel),
				component: ComponentTypha,
				fix:       "remove the nodeSelector",
			}
		}
	}

	// check kube-controllers nodeSelectors
	if c.kubeControllers != nil {
		if c.kubeControllers.Spec.Template.Spec.Affinity != nil {
			return ErrIncompatibleCluster{
				err:       "node affinity not supported for kube-controller deployment",
				component: ComponentKubeControllers,
				fix:       "remove the affinity",
			}
		}

		// kube-controllers nodeSelector is unique in that we do have an API for setting it's nodeSelectors.
		// operator rendering code will automatically set the kubernetes.io/os=linux selector, so we just
		// want to set the field to any other nodeSelectors set on it.
		if sels := removeOSNodeSelectors(c.kubeControllers.Spec.Template.Spec.NodeSelector); len(sels) != 0 {
			install.Spec.ControlPlaneNodeSelector = sels
		}
	}

	return nil
}

// removeOSNodeSelectors returns the given nodeSelectors with [beta.]kubernetes.io/os=linux nodeSelectors removed.
func removeOSNodeSelectors(existing map[string]string) map[string]string {
	var nodeSel = map[string]string{}
	for key, val := range existing {
		if (key == "kubernetes.io/os" || key == "beta.kubernetes.io/os") && val == "linux" {
			continue
		}
		nodeSel[key] = val
	}

	return nodeSel
}

// handleFelixNodeMetrics is a migration handler which detects custom prometheus settings for felix and
// caries those options forward via the NodeMetricsPort field.
func handleFelixNodeMetrics(c *components, install *operatorv1.Installation) error {
	metricsEnabled, err := c.node.getEnv(ctx, c.client, containerCalicoNode, "FELIX_PROMETHEUSMETRICSENABLED")
	if err != nil {
		return err
	}
	if metricsEnabled != nil && strings.ToLower(*metricsEnabled) == "true" {
		var _9091 int32 = 9091
		install.Spec.NodeMetricsPort = &_9091
		port, err := c.node.getEnv(ctx, c.client, containerCalicoNode, "FELIX_PROMETHEUSMETRICSPORT")
		if err != nil {
			return err
		}
		if port != nil {
			p, err := strconv.ParseInt(*port, 10, 32)
			if err != nil || p <= 0 || p > 65535 {
				return ErrIncompatibleCluster{
					err:       fmt.Sprintf("invalid port defined in FELIX_PROMETHEUSMETRICSPORT=%s", *port),
					component: ComponentCalicoNode,
					fix:       "adjust it to be within the range of 1-65535 or remove the env var",
				}
			}
			i := int32(p)
			install.Spec.NodeMetricsPort = &i
		}
	} else {
		// Ignore the metrics port if metrics is disabled.
		c.node.ignoreEnv(containerCalicoNode, "FELIX_PROMETHEUSMETRICSPORT")
	}

	return nil
}
