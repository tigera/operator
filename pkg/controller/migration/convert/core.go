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

	comp "github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/migration/convert/helpers"

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
			helpers.EnsureCalicoNodeContainersNotNil(install)

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
			helpers.EnsureTyphaContainersNotNil(install)

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
			helpers.EnsureKubeControllersContainersNotNil(install)

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
		helpers.EnsureCalicoNodeContainersNotNil(install)
		install.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.Containers = append(install.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.Containers, container)
	case kubecontrollers.KubeController:
		container := operatorv1.CalicoKubeControllersDeploymentContainer{Name: containerName, Resources: resources}
		helpers.EnsureKubeControllersContainersNotNil(install)
		install.Spec.CalicoKubeControllersDeployment.Spec.Template.Spec.Containers = append(install.Spec.CalicoKubeControllersDeployment.Spec.Template.Spec.Containers, container)
	case render.TyphaContainerName:
		container := operatorv1.TyphaDeploymentContainer{Name: containerName, Resources: resources}
		helpers.EnsureTyphaContainersNotNil(install)
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
		helpers.EnsureCalicoNodeInitContainersNotNil(install)
		install.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.InitContainers = append(install.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.InitContainers, container)
	case render.TyphaContainerName:
		container := operatorv1.TyphaDeploymentInitContainer{Name: initContainerName, Resources: resources}
		helpers.EnsureTyphaInitContainersNotNil(install)
		install.Spec.TyphaDeployment.Spec.Template.Spec.InitContainers = append(install.Spec.TyphaDeployment.Spec.Template.Spec.InitContainers, container)
	}

	return nil
}

func hasNodeSelector(override comp.ReplicatedPodResourceOverrides) bool {
	if reflect.ValueOf(override).IsNil() {
		return false
	}
	return len(override.GetNodeSelector()) > 0
}

func mergeComponentMapWithInstallation(componentName string, install, comp map[string]string, errFunc func(key string) error) error {
	// Verify that any items on the installation exist on the component.
	for k, v := range install {
		if x, ok := comp[k]; !ok || x != v {
			return errFunc(k)
		}
	}
	// Copy items from the component to the install.
	for k, v := range comp {
		// If a key already exists in the install but values differ, return an error.
		if x, ok := install[k]; ok && x != v {
			return errFunc(k)
		}
		install[k] = v
	}

	return nil
}

// mergeNodeSelector merges the nodeSelector on the component with that on the installation.
func mergeNodeSelector(componentName string, installNodeSelector, compNodeSelector map[string]string) error {
	return mergeComponentMapWithInstallation(componentName, installNodeSelector, compNodeSelector, func(key string) error {
		return ErrIncompatibleNodeSelector(key, componentName)
	})
}

func getTyphaAffinity(install *operatorv1.Installation) *corev1.Affinity {
	// TyphaDeployment affinity takes precedence.
	if install.Spec.TyphaDeployment != nil && install.Spec.TyphaDeployment.GetAffinity() != nil {
		return install.Spec.TyphaDeployment.GetAffinity()
	}

	// If TyphaAffinity is defined, convert it to a v1.Affinity and return it
	if install.Spec.TyphaAffinity != nil && install.Spec.TyphaAffinity.NodeAffinity != nil {
		return &corev1.Affinity{
			NodeAffinity: &corev1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution:  install.Spec.TyphaAffinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution,
				PreferredDuringSchedulingIgnoredDuringExecution: install.Spec.TyphaAffinity.NodeAffinity.PreferredDuringSchedulingIgnoredDuringExecution,
			},
		}
	}
	return nil
}

// handleNodeSelectors is a migration handler which ensures that nodeSelectors and affinities are set as expected.
func handleNodeSelectors(c *components, install *operatorv1.Installation) error {
	// Handle calico-node.
	if c.node.Spec.Template.Spec.Affinity != nil {
		if install.Spec.CalicoNodeDaemonSet == nil || install.Spec.CalicoNodeDaemonSet.GetAffinity() == nil {
			// Affinity set on the component but not the installation so migrate it over.
			helpers.EnsureCalicoNodePodSpecNotNil(install)
			install.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.Affinity = c.node.Spec.Template.Spec.Affinity
		} else {
			// Affinity is set on the component and the installation, verify that they match.
			if !reflect.DeepEqual(c.node.Spec.Template.Spec.Affinity, install.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.Affinity) {
				return ErrIncompatibleAffinity(ComponentCalicoNode)
			}
		}
	} else {
		// Affinity is not set on the component, check if it's set on the installation.
		if install.Spec.CalicoNodeDaemonSet != nil && install.Spec.CalicoNodeDaemonSet.GetAffinity() != nil {
			return ErrIncompatibleAffinity(ComponentCalicoNode)
		}
	}

	nodeSel := removeOSNodeSelectors(c.node.Spec.Template.Spec.NodeSelector)
	delete(nodeSel, "projectcalico.org/operator-node-migration")

	// Merge any remaining nodeSelectors into the installation.
	if len(nodeSel) == 0 {
		if hasNodeSelector(install.Spec.CalicoNodeDaemonSet) {
			return ErrNodeSelectorOnlyOnInstall(ComponentCalicoNode)
		}
	} else {
		helpers.EnsureCalicoNodeNodeSelectorNotNil(install)
		if err := mergeNodeSelector(ComponentCalicoNode, install.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.NodeSelector, nodeSel); err != nil {
			return err
		}
	}

	// Handle typha.
	// We treat typha differently from the node and kube-controllers since there are two fields to determine typha affinity.
	if c.typha != nil {
		installAffinity := getTyphaAffinity(install)
		if c.typha.Spec.Template.Spec.Affinity != nil {
			if installAffinity != nil {
				// Affinity is set on the component and the installation, verify that they match.
				if !reflect.DeepEqual(c.typha.Spec.Template.Spec.Affinity, installAffinity) {
					return ErrIncompatibleAffinity(ComponentTypha)
				}
			}
			// Ensure that the affinity on the installation uses the new field and clears the deprecated TyphaAffinity.
			helpers.EnsureTyphaPodSpecNotNil(install)
			install.Spec.TyphaDeployment.Spec.Template.Spec.Affinity = c.typha.Spec.Template.Spec.Affinity
			install.Spec.TyphaAffinity = nil
		} else {
			// Affinity is not set on the component, check if it's set on the installation.
			if installAffinity != nil {
				return ErrIncompatibleAffinity(ComponentTypha)
			}
		}

		nodeSel := removeOSNodeSelectors(c.typha.Spec.Template.Spec.NodeSelector)

		// Merge any remaining nodeSelectors into the installation.
		if len(nodeSel) == 0 {
			if hasNodeSelector(install.Spec.TyphaDeployment) {
				return ErrNodeSelectorOnlyOnInstall(ComponentTypha)
			}
		} else {
			helpers.EnsureTyphaNodeSelectorNotNil(install)
			if err := mergeNodeSelector(ComponentTypha, install.Spec.TyphaDeployment.Spec.Template.Spec.NodeSelector, nodeSel); err != nil {
				return err
			}
		}
	}

	// Handle kube-controllers
	if c.kubeControllers != nil {
		// Handle affinity.
		if c.kubeControllers.Spec.Template.Spec.Affinity != nil {
			if install.Spec.CalicoKubeControllersDeployment == nil || install.Spec.CalicoKubeControllersDeployment.GetAffinity() == nil {
				// Affinity set on the component but not the installation so migrate it over.
				helpers.EnsureKubeControllersPodSpecNotNil(install)
				install.Spec.CalicoKubeControllersDeployment.Spec.Template.Spec.Affinity = c.node.Spec.Template.Spec.Affinity
			} else {
				// Affinity is set on the component and the installation, verify that they match.
				if !reflect.DeepEqual(c.kubeControllers.Spec.Template.Spec.Affinity, install.Spec.CalicoKubeControllersDeployment.Spec.Template.Spec.Affinity) {
					return ErrIncompatibleAffinity(ComponentKubeControllers)
				}
			}
		} else {
			// Affinity is not set on the component, check if it's set on the installation.
			if install.Spec.CalicoKubeControllersDeployment != nil && install.Spec.CalicoKubeControllersDeployment.GetAffinity() != nil {
				return ErrIncompatibleAffinity(ComponentKubeControllers)
			}
		}

		nodeSel := removeOSNodeSelectors(c.kubeControllers.Spec.Template.Spec.NodeSelector)

		// Merge any remaining nodeSelectors into the installation.
		if len(nodeSel) == 0 {
			if hasNodeSelector(install.Spec.CalicoKubeControllersDeployment) {
				return ErrNodeSelectorOnlyOnInstall(ComponentKubeControllers)
			}
		} else {
			helpers.EnsureKubeControllersNodeSelectorNotNil(install)
			if err := mergeNodeSelector(ComponentKubeControllers, install.Spec.CalicoKubeControllersDeployment.Spec.Template.Spec.NodeSelector, nodeSel); err != nil {
				return err
			}
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
