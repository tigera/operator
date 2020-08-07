package convert

import (
	"fmt"
	"strconv"
	"strings"

	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	corev1 "k8s.io/api/core/v1"
)

func handleCore(c *components, install *Installation) error {
	dsType, err := c.node.getEnv(ctx, c.client, "calico-node", "DATASTORE_TYPE")
	if err != nil {
		return err
	}
	if dsType != nil && *dsType != "kubernetes" {
		return ErrIncompatibleCluster{"only DATASTORE_TYPE=kubernetes is supported at this time"}
	}

	// node resource limits
	node := getContainer(c.node.Spec.Template.Spec, "calico-node")
	if len(node.Resources.Limits) > 0 || len(node.Resources.Requests) > 0 {
		install.Spec.ComponentResources = append(install.Spec.ComponentResources, &operatorv1.ComponentResource{
			ComponentName:        operatorv1.ComponentNameNode,
			ResourceRequirements: node.Resources.DeepCopy(),
		})
	}

	// kube-controllers
	if c.kubeControllers != nil {
		kubeControllers := getContainer(c.kubeControllers.Spec.Template.Spec, containerKubeControllers)
		if kubeControllers != nil && (len(kubeControllers.Resources.Limits) > 0 || len(kubeControllers.Resources.Requests) > 0) {
			install.Spec.ComponentResources = append(install.Spec.ComponentResources, &operatorv1.ComponentResource{
				ComponentName:        operatorv1.ComponentNameKubeControllers,
				ResourceRequirements: kubeControllers.Resources.DeepCopy(),
			})
		}
	}

	if c.typha != nil {
		// typha resource limits. typha is optional so check for nil first
		typha := getContainer(c.typha.Spec.Template.Spec, "calico-typha")
		if typha != nil && (len(typha.Resources.Limits) > 0 || len(typha.Resources.Requests) > 0) {
			install.Spec.ComponentResources = append(install.Spec.ComponentResources, &operatorv1.ComponentResource{
				ComponentName:        operatorv1.ComponentNameTypha,
				ResourceRequirements: typha.Resources.DeepCopy(),
			})
		}
	}

	if c.kubeControllers != nil {
		enabledControllers, err := getEnv(ctx, c.client, c.kubeControllers.Spec.Template.Spec, containerKubeControllers, "ENABLED_CONTROLLERS")
		if err != nil {
			return err
		}
		if enabledControllers != nil && *enabledControllers != "node" {
			return ErrIncompatibleCluster{"only ENABLED_CONTROLLERS=node supported"}
		}

		autoHeps, err := getEnv(ctx, c.client, c.kubeControllers.Spec.Template.Spec, containerKubeControllers, "AUTO_HOST_ENDPOINTS")
		if err != nil {
			return err
		}
		if autoHeps != nil && strings.ToLower(*autoHeps) != "disabled" {
			return ErrIncompatibleCluster{"only AUTO_HOST_ENDPOINTS=disabled supported"}
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
				return ErrIncompatibleCluster{"volume 'flexvol-driver-host' must be a HostPath"}
			}
			if fv := getContainer(c.node.Spec.Template.Spec, "flexvol-driver"); fv == nil {
				return ErrIncompatibleCluster{"detected 'flexvol-driver-host' volume but no 'flexvol-driver' init container"}
			}
			install.Spec.FlexVolumePath = vol.HostPath.Path
		}
	} else {
		// verify that no flexvol container is set
		if fv := getContainer(c.node.Spec.Template.Spec, "flexvol-driver"); fv != nil {
			return ErrIncompatibleCluster{"detected 'flexvol-driver' init container but no 'flexvol-driver-host' volume"}
		}
		install.Spec.FlexVolumePath = "None"
	}

	// Volumes for lib-modules, xtables-lock, var-run-calico, var-lib-calico, or policysync have been changed
	v := getVolume(c.node.Spec.Template.Spec, "lib-modules")
	if v == nil || v.HostPath == nil || v.HostPath.Path != "/lib/modules" {
		return ErrIncompatibleCluster{"expected calico-node to have volume 'lib-modules' with hostPath '/lib/modules'"}
	}
	v = getVolume(c.node.Spec.Template.Spec, "var-run-calico")
	if v == nil || v.HostPath == nil || v.HostPath.Path != "/var/run/calico" {
		return ErrIncompatibleCluster{"expected calico-node to have volume 'var-run-calico' with hostPath '/var/run/calico'"}
	}
	v = getVolume(c.node.Spec.Template.Spec, "var-lib-calico")
	if v == nil || v.HostPath == nil || v.HostPath.Path != "/var/lib/calico" {
		return ErrIncompatibleCluster{"expected calico-node to have volume 'var-lib-calico' with hostPath '/var/lib/calico'"}
	}
	v = getVolume(c.node.Spec.Template.Spec, "xtables-lock")
	if v == nil || v.HostPath == nil || v.HostPath.Path != "/run/xtables.lock" {
		return ErrIncompatibleCluster{"expected calico-node to have volume 'xtables-lock' with hostPath '/run/xtables.lock"}
	}
	if c.calicoCNIConfig != nil {
		v = getVolume(c.node.Spec.Template.Spec, "cni-bin-dir")
		if v == nil || v.HostPath == nil || v.HostPath.Path != "/opt/cni/bin" {
			return ErrIncompatibleCluster{"expected calico-node to have volume 'cni-bin-dir' with hostPath '/opt/cni/bin'"}
		}
		v = getVolume(c.node.Spec.Template.Spec, "cni-net-dir")
		if v == nil || v.HostPath == nil || v.HostPath.Path != "/etc/cni/net.d" {
			return ErrIncompatibleCluster{"expected calico-node to have volume 'cni-net-dir' with hostPath '/opt/cni/bin'"}
		}
	}

	// check node tolerations
	if err := checkTolerations(c.node.Spec.Template.Spec.Tolerations,
		corev1.Toleration{
			Key:      "CriticalAddonsOnly",
			Operator: corev1.TolerationOpExists,
		},
		corev1.Toleration{
			Effect:   corev1.TaintEffectNoSchedule,
			Operator: corev1.TolerationOpExists,
		},
		corev1.Toleration{
			Effect:   corev1.TaintEffectNoExecute,
			Operator: corev1.TolerationOpExists,
		}); err != nil {
		return ErrIncompatibleCluster{"calico-node has incompatible tolerations: " + err.Error()}
	}

	// check kube-controller tolerations
	if c.kubeControllers != nil {
		if err := checkTolerations(c.kubeControllers.Spec.Template.Spec.Tolerations,
			corev1.Toleration{
				Key:      "CriticalAddonsOnly",
				Operator: corev1.TolerationOpExists,
			},
			corev1.Toleration{
				Effect: corev1.TaintEffectNoSchedule,
				Key:    "node-role.kubernetes.io/master",
			}); err != nil {
			return ErrIncompatibleCluster{"kube-controllers has incompatible tolerations: " + err.Error()}
		}
	}

	// check typha tolerations
	if c.typha != nil {
		if err := checkTolerations(c.typha.Spec.Template.Spec.Tolerations, corev1.Toleration{
			Key:      "CriticalAddonsOnly",
			Operator: corev1.TolerationOpExists,
		}); err != nil {
			return ErrIncompatibleCluster{"typha has incompatible tolerations: " + err.Error()}
		}
	}

	// check that nodename is a ref
	e, err := c.node.getEnvVar("calico-node", "NODENAME")
	if err != nil {
		return err
	}
	if e != nil && (e.ValueFrom == nil || e.ValueFrom.FieldRef == nil || e.ValueFrom.FieldRef.FieldPath != "spec.nodeName") {
		return ErrIncompatibleCluster{"NODENAME on 'calico-node' container must be unset or be a FieldRef to 'spec.nodeName'"}
	}

	if cni := getContainer(c.node.Spec.Template.Spec, "install-cni"); cni != nil {
		e, err = c.node.getEnvVar("install-cni", "KUBERNETES_NODE_NAME")
		if err != nil {
			return err
		}
		if e != nil && (e.ValueFrom == nil || e.ValueFrom.FieldRef == nil || e.ValueFrom.FieldRef.FieldPath != "spec.nodeName") {
			return ErrIncompatibleCluster{"KUBERNETES_NODE_NAME on 'install-cni' container must be unset or be a FieldRef to 'spec.nodeName'"}
		}

		n, err := c.node.getEnv(ctx, c.client, containerInstallCNI, "CNI_CONF_NAME")
		if err != nil {
			return err
		}
		if n != nil && *n != "10-calico.conflist" {
			return ErrIncompatibleCluster{"CNI_CONF_NAME on 'install-cni' container must be '10-calico.conflist'"}
		}
	}

	// TODO: handle these vars appropriately
	c.node.ignoreEnv("calico-node", "WAIT_FOR_DATASTORE")
	c.node.ignoreEnv("calico-node", "CLUSTER_TYPE")
	c.node.ignoreEnv("calico-node", "CALICO_DISABLE_FILE_LOGGING")
	c.node.ignoreEnv("calico-node", "CALICO_IPV4POOL_IPIP")
	c.node.ignoreEnv("calico-node", "CALICO_IPV4POOL_VXLAN")
	c.node.ignoreEnv("calico-node", "FELIX_IPV6SUPPORT")
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

func handleAnnotations(c *components, _ *Installation) error {
	if a := removeExpectedAnnotations(c.node.Annotations, map[string]string{}); len(a) != 0 {
		return ErrIncompatibleCluster{fmt.Sprintf("calico-node daemonset has unexpected annotation: %v", a)}
	}
	if a := removeExpectedAnnotations(c.node.Spec.Template.Annotations, map[string]string{}); len(a) != 0 {
		return ErrIncompatibleCluster{fmt.Sprintf("calico-node podTemplateSpec has unexpected annotation: %v", a)}
	}

	if c.kubeControllers != nil {
		if a := removeExpectedAnnotations(c.kubeControllers.Annotations, map[string]string{}); len(a) != 0 {
			return ErrIncompatibleCluster{fmt.Sprintf("kube-controllers deployment has unexpected annotation: %v", a)}
		}
		if a := removeExpectedAnnotations(c.kubeControllers.Spec.Template.Annotations, map[string]string{}); len(a) != 0 {
			return ErrIncompatibleCluster{fmt.Sprintf("kube-controllers podTemplateSpec has unexpected annotation: %v", a)}
		}
	}

	if c.typha != nil {
		if a := removeExpectedAnnotations(c.typha.Annotations, map[string]string{}); len(a) != 0 {
			return ErrIncompatibleCluster{fmt.Sprintf("typha deployment has unexpected annotation: %v", a)}
		}
		if a := removeExpectedAnnotations(c.typha.Spec.Template.Annotations, map[string]string{
			"cluster-autoscaler.kubernetes.io/safe-to-evict": "true",
		}); len(a) != 0 {
			return ErrIncompatibleCluster{fmt.Sprintf("typha podTemplateSpec has unexpected annotation: %v", a)}
		}
	}
	return nil
}

// removeExpectedAnnotations returns the given annotations with common k8s-native annotations removed.
// this function also accepts a second argument of additional annotations to remove.
func removeExpectedAnnotations(existing, ignore map[string]string) map[string]string {
	a := existing
	for key, val := range existing {
		if key == "kubectl.kubernetes.io/last-applied-configuration" ||
			key == "deprecated.daemonset.template.generation" ||
			key == "deployment.kubernetes.io/revision" ||
			key == "scheduler.alpha.kubernetes.io/critical-pod" {
			delete(a, key)
			continue
		}

		if v, ok := ignore[key]; ok && v == val {
			delete(a, key)
		}
	}

	return a
}

func handleNodeSelectors(c *components, install *Installation) error {
	// check calico-node nodeSelectors
	if c.node.Spec.Template.Spec.Affinity != nil {
		return ErrIncompatibleCluster{"node affinity not supported for calico-node daemonset"}
	}
	if nodeSel := removeOSNodeSelectors(c.node.Spec.Template.Spec.NodeSelector); len(nodeSel) != 0 {
		return ErrIncompatibleCluster{fmt.Sprintf("unsupported nodeSelector for calico-node daemonset: %v", nodeSel)}
	}

	// check typha nodeSelectors
	if c.typha != nil {
		if c.typha.Spec.Template.Spec.Affinity != nil {
			return ErrIncompatibleCluster{"node affinity not supported for typha deployment"}
		}
		if nodeSel := removeOSNodeSelectors(c.typha.Spec.Template.Spec.NodeSelector); len(nodeSel) != 0 {
			return ErrIncompatibleCluster{fmt.Sprintf("invalid nodeSelector for typha deployment: %v", nodeSel)}
		}
	}

	// check kube-controllers nodeSelectors
	if c.kubeControllers != nil {
		if c.kubeControllers.Spec.Template.Spec.Affinity != nil {
			return ErrIncompatibleCluster{"node affinity not supported for kube-controller deployment"}
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

func handleFelixNodeMetrics(c *components, install *Installation) error {
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
				return ErrIncompatibleCluster{fmt.Sprintf(
					"invalid port defined in FELIX_PROMETHEUSMETRICSPORT(%s), it should be 1-65535 ", *port)}
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

func checkTolerations(existing []corev1.Toleration, expected ...corev1.Toleration) error {
	if len(existing) != len(expected) {
		return ErrIncompatibleCluster{fmt.Sprintf("missing expected tolerations. have: %+v. expecting: %+v", existing, expected)}
	}

	for _, t := range expected {
		var found bool
		for _, k := range existing {
			if k == t {
				found = true
				break
			}
		}
		if !found {
			return ErrIncompatibleCluster{fmt.Sprintf("missing expected toleration: %+v", t)}
		}
	}

	return nil
}
