package convert

import (
	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
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
	kubeControllers := getContainer(c.kubeControllers.Spec.Template.Spec, "calico-kube-controllers")
	if len(kubeControllers.Resources.Limits) > 0 || len(kubeControllers.Resources.Requests) > 0 {
		install.Spec.ComponentResources = append(install.Spec.ComponentResources, &operatorv1.ComponentResource{
			ComponentName:        operatorv1.ComponentNameKubeControllers,
			ResourceRequirements: kubeControllers.Resources.DeepCopy(),
		})
	}

	// typha resource limits. typha is optional so check for nil first
	typha := getContainer(c.typha.Spec.Template.Spec, "calico-typha")
	if typha != nil && (len(typha.Resources.Limits) > 0 || len(typha.Resources.Requests) > 0) {
		install.Spec.ComponentResources = append(install.Spec.ComponentResources, &operatorv1.ComponentResource{
			ComponentName:        operatorv1.ComponentNameTypha,
			ResourceRequirements: typha.Resources.DeepCopy(),
		})
	}

	// kube-controllers nodeSelector
	install.Spec.ControlPlaneNodeSelector = c.kubeControllers.Spec.Template.Spec.NodeSelector

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

	// TODO: handle these vars appropriately
	c.node.ignoreEnv("calico-node", "WAIT_FOR_DATASTORE")
	c.node.ignoreEnv("calico-node", "CLUSTER_TYPE")
	c.node.ignoreEnv("calico-node", "NODENAME")
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
	c.node.ignoreEnv("upgrade-ipam", "KUBERNETES_NODE_NAME")
	c.node.ignoreEnv("upgrade-ipam", "CALICO_NETWORKING_BACKEND")
	c.node.ignoreEnv("install-cni", "CNI_CONF_NAME")
	c.node.ignoreEnv("install-cni", "KUBERNETES_NODE_NAME")
	c.node.ignoreEnv("install-cni", "SLEEP")

	return nil
}
