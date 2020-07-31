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
		kubeControllers := getContainer(c.kubeControllers.Spec.Template.Spec, "calico-kube-controllers")
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

	// kube-controllers nodeSelector
	if c.kubeControllers != nil {
		install.Spec.ControlPlaneNodeSelector = c.kubeControllers.Spec.Template.Spec.NodeSelector
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
		return ErrIncompatibleCluster{"must mount /lib/modules from host"}
	}
	v = getVolume(c.node.Spec.Template.Spec, "var-run-calico")
	if v == nil || v.HostPath == nil || v.HostPath.Path != "/var/run/calico" {
		return ErrIncompatibleCluster{"must mount /var/run/calico from host"}
	}
	v = getVolume(c.node.Spec.Template.Spec, "var-lib-calico")
	if v == nil || v.HostPath == nil || v.HostPath.Path != "/var/lib/calico" {
		return ErrIncompatibleCluster{"must mount /var/lib/calico from host"}
	}
	v = getVolume(c.node.Spec.Template.Spec, "xtables-lock")
	if v == nil || v.HostPath == nil || v.HostPath.Path != "/run/xtables.lock" {
		return ErrIncompatibleCluster{"must mount /run/xtables.lock"}
	}
	if c.calicoCNIConfig != nil {
		v = getVolume(c.node.Spec.Template.Spec, "cni-bin-dir")
		if v == nil || v.HostPath == nil || v.HostPath.Path != "/opt/cni/bin" {
			return ErrIncompatibleCluster{"must mount /opt/cni/bin"}
		}
		v = getVolume(c.node.Spec.Template.Spec, "cni-net-dir")
		if v == nil || v.HostPath == nil || v.HostPath.Path != "/etc/cni/net.d" {
			return ErrIncompatibleCluster{"must mount /opt/cni/bin"}
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
		return fmt.Errorf("calico-node has incompatible tolerations: %v", err)
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
			return fmt.Errorf("kube-controllers has incompatible tolerations: %v", err)
		}
	}

	// check typha tolerations
	if c.typha != nil {
		if err := checkTolerations(c.typha.Spec.Template.Spec.Tolerations, corev1.Toleration{
			Key:      "CriticalAddonsOnly",
			Operator: corev1.TolerationOpExists,
		}); err != nil {
			return fmt.Errorf("typha has incompatible tolerations: %v", err)
		}
	}

	if err = handleFelixNodeMetrics(c, install); err != nil {
		return err
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
	}

	// TODO: handle these vars appropriately
	c.node.ignoreEnv("calico-node", "WAIT_FOR_DATASTORE")
	c.node.ignoreEnv("calico-node", "CLUSTER_TYPE")
	c.node.ignoreEnv("calico-node", "CALICO_DISABLE_FILE_LOGGING")
	c.node.ignoreEnv("calico-node", "CALICO_IPV4POOL_IPIP")
	c.node.ignoreEnv("calico-node", "CALICO_IPV4POOL_VXLAN")
	c.node.ignoreEnv("calico-node", "FELIX_IPINIPMTU")
	c.node.ignoreEnv("calico-node", "FELIX_VXLANMTU")
	c.node.ignoreEnv("calico-node", "FELIX_WIREGUARDMTU")
	c.node.ignoreEnv("calico-node", "FELIX_IPV6SUPPORT")
	c.node.ignoreEnv("calico-node", "FELIX_LOGSEVERITYSCREEN")
	c.node.ignoreEnv("calico-node", "FELIX_HEALTHENABLED")
	c.node.ignoreEnv("calico-node", "FELIX_USAGEREPORTINGENABLED")
	c.node.ignoreEnv("calico-node", "FELIX_TYPHAK8SSERVICENAME")
	c.node.ignoreEnv("calico-node", "FELIX_LOGSEVERITYSYS")
	c.node.ignoreEnv("upgrade-ipam", "KUBERNETES_NODE_NAME")
	c.node.ignoreEnv("upgrade-ipam", "CALICO_NETWORKING_BACKEND")
	c.node.ignoreEnv("install-cni", "CNI_CONF_NAME")
	c.node.ignoreEnv("install-cni", "SLEEP")

	return nil
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
		return fmt.Errorf("missing expected tolerations. have: %+v. expecting: %+v", existing, expected)
	}

OUTER:
	for _, t := range expected {
		for _, k := range existing {
			if k == t {
				continue OUTER
			}
		}
		return fmt.Errorf("missing expected toleration: %+v", t)
	}

	return nil
}
